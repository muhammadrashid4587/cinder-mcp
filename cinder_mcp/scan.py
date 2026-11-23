"""Bounded-batch keyspace scanning for cinder-mcp.

Cinder has no SCAN command, so a full keyspace listing today is one
KEYS reply. This module is the seam where a cursor-based SCAN will
land when cinder grows one: callers iterate keys in bounded batches
and never hold per-key detail for the whole keyspace at once, so only
this module changes when the backend changes.

Honest limitation: until cinder has SCAN, `iter_keys` still runs one
KEYS call and slices its reply into batches. The win today is
downstream — the TTL probes, type probes, and prompt text built from
the scan are incremental and bounded by the batch size and the
caller's result caps, instead of materializing per-key detail for
every key. `scan_batch` is the same idea as a paged API: each page
re-runs KEYS and returns at most `batch_size` keys, so a client
walking a huge keyspace never holds more than one page at a time.
"""

import bisect

# Keys per batch when the caller does not say otherwise.
DEFAULT_SCAN_BATCH_SIZE = 100

# The largest batch a caller may ask for. A page is a tool result,
# so it stays small enough to read; ask for the next page instead
# of one giant one.
MAX_SCAN_BATCH_SIZE = 1000


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


def iter_keys(client, pattern="*", batch_size=DEFAULT_SCAN_BATCH_SIZE):
    """Yield the keys matching `pattern` in batches of at most
    `batch_size`. Each yielded batch is a plain list; the caller
    processes one batch, drops it, and asks for the next, so peak
    per-key memory is bounded by the batch size plus whatever the
    caller keeps. The batches cover every matching key exactly
    once, in KEYS order. When cinder gains SCAN this becomes a
    cursor loop with the same yield contract — callers do not
    change."""
    batch_size = validate_batch_size(batch_size)
    keys = client.command("KEYS", pattern) or []
    for start in range(0, len(keys), batch_size):
        yield keys[start:start + batch_size]


def scan_batch(client, pattern="*", cursor="", batch_size=DEFAULT_SCAN_BATCH_SIZE):
    """One page of the keyspace, SCAN-style: at most `batch_size`
    keys after `cursor` in sorted order, plus the cursor to resume
    from and whether the scan is done. Pass "" to start. The cursor
    is the last key of the page, so keys added after it are picked
    up on later pages; keys added before it are not revisited, and
    keys deleted or renamed between pages can shift the window —
    the same caveats real SCAN has. Returns {"keys": [...],
    "cursor": str, "done": bool, "batch_size": n}; when done is
    true the cursor is "" and there is nothing left to fetch."""
    batch_size = validate_batch_size(batch_size)
    if not isinstance(cursor, str):
        raise ValueError("cursor must be a string")
    keys = sorted(client.command("KEYS", pattern) or [])
    start = bisect.bisect_right(keys, cursor) if cursor else 0
    page = keys[start:start + batch_size]
    done = start + len(page) >= len(keys)
    return {
        "keys": page,
        "cursor": page[-1] if page and not done else "",
        "done": done,
        "batch_size": batch_size,
    }
