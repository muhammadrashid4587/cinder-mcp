"""Bounded-batch keyspace scanning for cinder-mcp.

The scanner is backed by cinder's real SCAN command (cinder 0.26.0):
`SCAN cursor [MATCH pattern] [COUNT n]` returns `[cursor, keys]`,
and the walk repeats with the returned cursor until it comes back
"0". Callers iterate keys in bounded batches and never hold per-key
detail for the whole keyspace at once.

Two honest details. First, COUNT is a hint: cinder stops collecting
once it has at least COUNT matching keys, but only checks after
finishing a whole hash bucket, so one SCAN call can return a few
keys more than COUNT when several matches share a bucket. A page
from `scan_batch` therefore holds about `batch_size` keys, not
strictly at most; `iter_keys` re-batches the stream itself, so its
batches are exact. Second, real SCAN may return a key twice if the
hash table resizes mid-walk (a key added during the scan grows the
table). `iter_keys` dedupes against a seen set so the prompts built
on it still cover every key exactly once; the seen set holds one
string per key scanned, while the per-key TTL/type/size work stays
bounded per batch. `scan_batch` is the raw paged tool and does not
dedupe: it exposes real SCAN semantics, duplicates included, with
the same caveats real SCAN has.
"""

# Keys per batch when the caller does not say otherwise.
DEFAULT_SCAN_BATCH_SIZE = 100

# The largest batch a caller may ask for. A page is a tool result,
# so it stays small enough to read; ask for the next page instead
# of one giant one.
MAX_SCAN_BATCH_SIZE = 1000

# Cinder's cursor for a finished walk, and the cursor a walk starts
# from. The MCP tool surface uses "" for both ends: "" starts a
# walk, and a finished page returns "" as its cursor.
SCAN_DONE_CURSOR = "0"


def validate_batch_size(batch_size):
    """A batch size as an int in [1, MAX_SCAN_BATCH_SIZE], or
    ValueError. Bools are rejected — True is 1 to int() but is not
    a batch size anyone meant."""
    if isinstance(batch_size, bool) or not isinstance(batch_size, int):
        raise ValueError("batch_size must be an integer")
    if batch_size < 1 or batch_size > MAX_SCAN_BATCH_SIZE:
        raise ValueError(
            "batch_size must be between 1 and %d" % MAX_SCAN_BATCH_SIZE
        )
    return batch_size


def _scan_reply(client, cursor, pattern, count):
    """One SCAN call: `SCAN cursor MATCH pattern COUNT count`.
    Returns (next_cursor, keys) with the cursor as the decimal
    string cinder sent back. A malformed reply fails loudly
    instead of silently ending or looping the walk."""
    reply = client.command(
        "SCAN", cursor, "MATCH", pattern, "COUNT", str(count)
    )
    if not isinstance(reply, list) or len(reply) != 2:
        raise ValueError("SCAN returned an unexpected reply: %r" % (reply,))
    next_cursor, keys = reply
    if not isinstance(next_cursor, str) or not next_cursor.isdigit():
        raise ValueError(
            "SCAN returned an invalid cursor: %r" % (next_cursor,))
    if not isinstance(keys, list):
        raise ValueError("SCAN returned an unexpected key list: %r" % (keys,))
    return next_cursor, keys


def iter_keys(client, pattern="*", batch_size=DEFAULT_SCAN_BATCH_SIZE):
    """Yield the keys matching `pattern` in batches of at most
    `batch_size`. Each yielded batch is a plain list; the caller
    processes one batch, drops it, and asks for the next, so peak
    per-key detail is bounded by the batch size plus the seen set.
    The batches cover every matching key exactly once: a key SCAN
    returns twice (a table resize mid-walk) is yielded only the
    first time. The order is SCAN order — hash-bucket order, not
    sorted — and keys added or removed mid-walk follow the same
    caveats real SCAN has. An empty keyspace yields no batches."""
    batch_size = validate_batch_size(batch_size)
    seen = set()
    batch = []
    cursor = SCAN_DONE_CURSOR
    while True:
        cursor, keys = _scan_reply(client, cursor, pattern, batch_size)
        for key in keys:
            if key in seen:
                continue
            seen.add(key)
            batch.append(key)
            if len(batch) == batch_size:
                yield batch
                batch = []
        if cursor == SCAN_DONE_CURSOR:
            break
    if batch:
        yield batch


def scan_batch(client, pattern="*", cursor="", batch_size=DEFAULT_SCAN_BATCH_SIZE):
    """One page of the keyspace, SCAN-style: about `batch_size`
    keys from one real SCAN call, plus the cursor to resume from
    and whether the scan is done. Pass "" to start. The cursor is
    cinder's opaque decimal cursor — pass it back verbatim; do not
    read meaning into it. When done is true the cursor is "" and
    there is nothing left to fetch. A page can run a few keys over
    `batch_size`: COUNT is a hint to cinder, and a hash bucket
    holding several matches is returned whole. Keys added after
    the cursor are picked up on later pages; keys deleted or
    renamed between pages can shift the window, and a key can come
    back twice if the table resizes mid-walk — the same caveats
    real SCAN has. Returns {"keys": [...], "cursor": str,
    "done": bool, "batch_size": n}."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(cursor, str):
        raise ValueError("cursor must be a string")
    if cursor and not cursor.isdigit():
        raise ValueError("cursor must be a decimal SCAN cursor string")
    next_cursor, keys = _scan_reply(
        client, cursor or SCAN_DONE_CURSOR, pattern, batch_size
    )
    done = next_cursor == SCAN_DONE_CURSOR
    return {
        "keys": keys,
        "cursor": "" if done else next_cursor,
        "done": done,
        "batch_size": batch_size,
    }
