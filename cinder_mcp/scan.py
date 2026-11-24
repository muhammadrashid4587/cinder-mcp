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

Two more functions cover cinder's HSCAN the same way, one hash at a
time: `hscan_batch` returns one bounded page of a hash's fields
from one real HSCAN call, and `hscan_result` shapes a raw HSCAN
reply (a page fetched inside a MULTI/EXEC transaction) into the
same page shape. COUNT is exact for HSCAN — cinder stops the page
at exactly that many matching fields — so a page holds at most
`batch_size` fields, never more.

And two more cover cinder's ZSCAN (cinder 0.41.0) the same way,
one sorted set at a time: `zscan_batch` returns one bounded page
of a set's members from one real ZSCAN call, and `zscan_result`
shapes a raw ZSCAN reply into the same page shape. COUNT is exact
for ZSCAN too — cinder stops the page at exactly that many
matching members. Members come back in score order, lowest first.
The cursor is a rank into that order, so members added or deleted
between pages can shift the window: a member can be missed or
come back twice if the set changes mid-walk, the same caveats
real ZSCAN has.

And two more cover cinder's SSCAN (cinder 0.40.0) the same way,
one set at a time: `sscan_batch` returns one bounded page of a
set's members from one real SSCAN call, and `sscan_result` shapes
a raw SSCAN reply into the same page shape. COUNT is exact for
SSCAN too — cinder stops the page at exactly that many matching
members. Members come back in the set's storage order, which is
insertion order. The cursor is an index into that order, so
members added or deleted between pages can shift the window, the
same caveats real SSCAN has.
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


def _hscan_reply(client, key, cursor, pattern, count):
    """One HSCAN call: `HSCAN key cursor MATCH pattern COUNT count`.
    Returns (next_cursor, fields) with the cursor as the decimal
    string cinder sent back and fields as a field->value dict. A
    malformed reply fails loudly instead of silently ending or
    looping the walk."""
    reply = client.command(
        "HSCAN", key, cursor, "MATCH", pattern, "COUNT", str(count)
    )
    if not isinstance(reply, list) or len(reply) != 2:
        raise ValueError("HSCAN returned an unexpected reply: %r" % (reply,))
    next_cursor, flat = reply
    if not isinstance(next_cursor, str) or not next_cursor.isdigit():
        raise ValueError(
            "HSCAN returned an invalid cursor: %r" % (next_cursor,))
    if not isinstance(flat, list) or len(flat) % 2 != 0:
        raise ValueError(
            "HSCAN returned an unexpected field list: %r" % (flat,))
    return next_cursor, {
        flat[i]: flat[i + 1] for i in range(0, len(flat), 2)
    }


def hscan_result(reply, batch_size):
    """Shape one HSCAN reply [cursor, [field, value, ...]] into
    {"fields": {...}, "cursor": str, "done": bool, "batch_size": n}.
    A missing key replies as ["0", []], which becomes done with no
    fields. The cursor is cinder's opaque decimal cursor — pass it
    back verbatim; when done is true the cursor is ""."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(reply, list) or len(reply) != 2:
        raise ValueError("HSCAN returned an unexpected reply: %r" % (reply,))
    next_cursor, flat = reply
    if not isinstance(next_cursor, str) or not next_cursor.isdigit():
        raise ValueError(
            "HSCAN returned an invalid cursor: %r" % (next_cursor,))
    if not isinstance(flat, list) or len(flat) % 2 != 0:
        raise ValueError(
            "HSCAN returned an unexpected field list: %r" % (flat,))
    done = next_cursor == SCAN_DONE_CURSOR
    return {
        "fields": {
            flat[i]: flat[i + 1] for i in range(0, len(flat), 2)
        },
        "cursor": "" if done else next_cursor,
        "done": done,
        "batch_size": batch_size,
    }


def hscan_batch(client, key, pattern="*", cursor="",
                batch_size=DEFAULT_SCAN_BATCH_SIZE):
    """One page of a hash, HSCAN-style: at most `batch_size` fields
    from one real HSCAN call, plus the cursor to resume from and
    whether the scan is done. Pass "" to start. The cursor is
    cinder's opaque decimal cursor — pass it back verbatim; do not
    read meaning into it. When done is true the cursor is "" and
    there is nothing left to fetch. Unlike SCAN, COUNT is exact
    here: cinder stops the page at exactly `batch_size` matching
    fields. `pattern` matches field names only, with the same glob
    (* and ?). A missing key is done at once, with no fields. Fields
    come back in hash order, not sorted; fields added or deleted
    between pages can shift the window, the same caveats real
    HSCAN has. Returns {"fields": {...}, "cursor": str,
    "done": bool, "batch_size": n}."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(cursor, str):
        raise ValueError("cursor must be a string")
    if cursor and not cursor.isdigit():
        raise ValueError("cursor must be a decimal HSCAN cursor string")
    next_cursor, fields = _hscan_reply(
        client, key, cursor or SCAN_DONE_CURSOR, pattern, batch_size
    )
    done = next_cursor == SCAN_DONE_CURSOR
    return {
        "fields": fields,
        "cursor": "" if done else next_cursor,
        "done": done,
        "batch_size": batch_size,
    }


def zscan_result(reply, batch_size, withscores=False):
    """Shape one ZSCAN reply [cursor, [member, ...]] into
    {"members": [...], "cursor": str, "done": bool, "batch_size": n}.
    With withscores the reply is [cursor, [member, score, ...]] and
    the members become {"member": ..., "score": ...} objects, the
    scores parsed as numbers. A missing key replies as ["0", []],
    which becomes done with no members. The cursor is cinder's
    opaque decimal cursor — pass it back verbatim; when done is
    true the cursor is ""."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(withscores, bool):
        raise ValueError("withscores must be true or false")
    if not isinstance(reply, list) or len(reply) != 2:
        raise ValueError("ZSCAN returned an unexpected reply: %r" % (reply,))
    next_cursor, flat = reply
    if not isinstance(next_cursor, str) or not next_cursor.isdigit():
        raise ValueError(
            "ZSCAN returned an invalid cursor: %r" % (next_cursor,))
    if not isinstance(flat, list):
        raise ValueError(
            "ZSCAN returned an unexpected member list: %r" % (flat,))
    if withscores:
        if len(flat) % 2 != 0:
            raise ValueError(
                "ZSCAN returned an unexpected member list: %r" % (flat,))
        members = [
            {"member": flat[i], "score": float(flat[i + 1])}
            for i in range(0, len(flat), 2)
        ]
    else:
        members = list(flat)
    done = next_cursor == SCAN_DONE_CURSOR
    return {
        "members": members,
        "cursor": "" if done else next_cursor,
        "done": done,
        "batch_size": batch_size,
    }


def zscan_batch(client, key, pattern="*", cursor="",
                batch_size=DEFAULT_SCAN_BATCH_SIZE, withscores=False):
    """One page of a sorted set, ZSCAN-style: at most `batch_size`
    members from one real ZSCAN call, plus the cursor to resume
    from and whether the scan is done. Pass "" to start. The cursor
    is cinder's opaque decimal cursor — pass it back verbatim; do
    not read meaning into it. When done is true the cursor is ""
    and there is nothing left to fetch. COUNT is exact here: cinder
    stops the page at exactly `batch_size` matching members.
    `pattern` matches member names only, with the same glob
    (* and ?). With withscores=true the members come back as
    {"member": ..., "score": ...} objects instead of plain names.
    A missing key is done at once, with no members. Members come
    back in score order, lowest first, not sorted by name; members
    added or deleted between pages can shift the window, the same
    caveats real ZSCAN has. Returns {"members": [...], "cursor":
    str, "done": bool, "batch_size": n}."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(withscores, bool):
        raise ValueError("withscores must be true or false")
    if not isinstance(cursor, str):
        raise ValueError("cursor must be a string")
    if cursor and not cursor.isdigit():
        raise ValueError("cursor must be a decimal ZSCAN cursor string")
    cmd = ["ZSCAN", key, cursor or SCAN_DONE_CURSOR, "MATCH", pattern,
           "COUNT", str(batch_size)]
    if withscores:
        cmd.append("WITHSCORES")
    reply = client.command(*cmd)
    return zscan_result(reply, batch_size, withscores)


def sscan_result(reply, batch_size):
    """Shape one SSCAN reply [cursor, [member, ...]] into
    {"members": [...], "cursor": str, "done": bool, "batch_size": n}.
    A missing key replies as ["0", []], which becomes done with no
    members. The cursor is cinder's opaque decimal cursor — pass it
    back verbatim; when done is true the cursor is ""."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(reply, list) or len(reply) != 2:
        raise ValueError("SSCAN returned an unexpected reply: %r" % (reply,))
    next_cursor, members = reply
    if not isinstance(next_cursor, str) or not next_cursor.isdigit():
        raise ValueError(
            "SSCAN returned an invalid cursor: %r" % (next_cursor,))
    if not isinstance(members, list):
        raise ValueError(
            "SSCAN returned an unexpected member list: %r" % (members,))
    done = next_cursor == SCAN_DONE_CURSOR
    return {
        "members": list(members),
        "cursor": "" if done else next_cursor,
        "done": done,
        "batch_size": batch_size,
    }


def sscan_batch(client, key, pattern="*", cursor="",
                batch_size=DEFAULT_SCAN_BATCH_SIZE):
    """One page of a set, SSCAN-style: at most `batch_size`
    members from one real SSCAN call, plus the cursor to resume
    from and whether the scan is done. Pass "" to start. The cursor
    is cinder's opaque decimal cursor — pass it back verbatim; do
    not read meaning into it. When done is true the cursor is ""
    and there is nothing left to fetch. COUNT is exact here: cinder
    stops the page at exactly `batch_size` matching members.
    `pattern` matches member names only, with the same glob
    (* and ?). A missing key is done at once, with no members.
    Members come back in the set's storage order, which is
    insertion order; members added or deleted between pages can
    shift the window, the same caveats real SSCAN has. Returns
    {"members": [...], "cursor": str, "done": bool,
    "batch_size": n}."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(cursor, str):
        raise ValueError("cursor must be a string")
    if cursor and not cursor.isdigit():
        raise ValueError("cursor must be a decimal SSCAN cursor string")
    reply = client.command(
        "SSCAN", key, cursor or SCAN_DONE_CURSOR, "MATCH", pattern,
        "COUNT", str(batch_size)
    )
    return sscan_result(reply, batch_size)


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
