"""Prompt definitions for cinder-mcp.

Prompts are reusable starting points an MCP client can fetch: the
server fills them with live data from cinder and hands the client a
ready-to-send message. keyspace-summary samples cinder's INFO output
and lists the keys matching a pattern, then asks the model to check
what looks off: keys with no expiry, keys that should not be there,
and keys worth reading in full. key-deep-dive inspects one key in
detail — its type, TTL, size, a sample of its value, and the keys
related to it — and asks the model to judge whether that one key
looks healthy. ttl-audit scans the keyspace, groups every key by how
soon it expires, and asks the model to flag keys expiring soon and
keys with no expiry that the operator should act on. cleanup-plan
inspects the live keyspace — INFO, KEYS, and a per-key TTL, type,
and size sample — classifies every key as safe to delete, expiring
soon, risky to delete without confirmation, or keep, and asks the
model to turn that into a concrete cleanup plan with exact kv_del
calls. keyspace-health is the one-view health report: total keys,
type breakdown, keys without TTL, soonest-expiring keys, the
largest keys, and a short list of recommended actions. write-safety
audits a proposed write plan — a JSON list of kv_batch-shaped ops —
against the live keyspace before anything runs: it flags overwrites
of keys that never expire, overwrites of large keys, SETs, MSETs,
SETEXes and GETSETs that would destroy a list, set, or hash, GETDELs
that would delete a key that never expires, INCRs and DECRs that
would fail on a non-integer or a container, LSETs on a missing key
or with an index out of range, LSETs and LINSERTs on a container,
HINCRBYs that would fail
on a non-integer field or a container, HINCRBYFLOATs that would fail
on a non-float field or a container, HEXPIREs that would delete
fields at once or fail on a bad timeout, condition, or container,
and HPERSISTs that would strip a field's expiry, XADDs that would
fail on a container or trim entries off a stream, GEORADIUSes and
GEORADIUSBYMEMBERs that would store their hits at a destination —
a plain GEORADIUS is a read, and GEOSEARCH is a read too — and
GEOSEARCHSTOREs that would store their hits at a destination,
overwriting it whatever it held, clearing its TTL, or deleting it
on an empty result, and
EXPIREs with a bad timeout, then asks the model for a go/no-go
per risky op. SETNX never
writes to a key that already exists, so the audit reports it as a
safe no-op there and a new key with no expiry elsewhere. ttl-renewal plans
renewing the TTLs of keys that are expiring soon or have no expiry:
it reads live TTLs, flags keys that are already expired or missing,
and proposes one kv_expire renewal per key up to a safety cap,
without ever printing a value. key-migration plans moving keys
matching a pattern to a new prefix: it audits each key's type, size,
and TTL, checks whether the target name already exists and with
what type, and lays out the ordered copy steps — list keys move
atomically one element at a time with kv_lmove, other keys are read
and written under the target name, the TTL re-applied with
kv_expire, verified, then the source deleted with kv_del — without
ever printing a value. Cinder has no RENAME or COPY command, so a
migration of a non-list key is a read plus a write, not one atomic
move, and the prompt says so.
"""

import bisect
import json
import math
import time

from .resp import RespError
from .scan import DEFAULT_SCAN_BATCH_SIZE, iter_keys
from .tools import (MAX_GEOSEARCH_MEMBERS, MAX_XPENDING_ENTRIES,
                    _xack_args, _xadd_args, _xclaim_args,
                    _xgroup_create_args, _xgroup_setid_args,
                    _xreadgroup_args)

# Keys per batch when ttl-audit and cleanup-plan scan the keyspace.
# The prompts process one batch at a time and keep only bounded
# result lists, so a huge keyspace never becomes a huge prompt.
PROMPT_SCAN_BATCH_SIZE = DEFAULT_SCAN_BATCH_SIZE

# A string sample longer than this is truncated in the prompt text.
MAX_SAMPLE_CHARS = 200

# At most this many related keys are listed in the prompt text.
MAX_RELATED_KEYS = 20

# At most this many soonest-expiring keys are listed in the ttl-audit.
MAX_SOON_KEYS = 10

# At most this many no-expiry keys are listed in the ttl-audit.
MAX_NO_EXPIRY_KEYS = 20

# At most this many keys are listed per section in the cleanup-plan.
MAX_CLEANUP_KEYS = 20

# At most this many keys are listed per section in the
# keyspace-health report: no-expiry keys, soonest-expiring keys,
# largest string keys, largest container keys.
MAX_HEALTH_KEYS = 10

# At most this many ops in a write plan are audited; the rest are
# counted as not audited, so a huge plan never becomes a huge
# prompt. Ops are audited in plan order.
MAX_WRITE_SAFETY_OPS = 50

# Default target TTL for a ttl-renewal plan, in seconds (1 day):
# keys expiring sooner than this are proposed for renewal to it.
DEFAULT_RENEWAL_TARGET_TTL = 86400

# Default safety cap on how many keys a ttl-renewal plan covers:
# renewals plus first-expiry keys, combined.
DEFAULT_RENEWAL_MAX_KEYS = 20

# The largest max_keys a ttl-renewal plan accepts. The cap is a
# safety bound on a plan an operator runs by hand, so it stays
# small enough to read; narrow the pattern or pass an explicit
# keys list instead of raising it.
MAX_RENEWAL_MAX_KEYS = 100

# At most this many keys are listed in the ttl-renewal report's
# already-fine and missing-or-expired sections.
MAX_RENEWAL_LISTED = 10

# Default safety cap on how many ready keys a key-migration plan
# covers: the plan lists the ready keys, soonest in key order, and
# counts the rest as not covered, so the prompt text stays bounded
# however large the keyspace is.
DEFAULT_MIGRATION_MAX_KEYS = 20

# The largest max_keys a key-migration plan accepts. The cap is a
# safety bound on a plan an operator runs by hand, so it stays
# small enough to read; narrow the pattern instead of raising it.
MAX_MIGRATION_MAX_KEYS = 100

# At most this many keys are listed in the key-migration report's
# overwrite, conflict, self-mapping, and missing-or-expired
# sections. Those sections are warnings, not the plan itself, so
# they are bounded separately from the max_keys cap and the rest
# are counted.
MAX_MIGRATION_FLAGGED_LISTED = 10

# Ops a write plan may contain that actually write. Read ops in a
# plan are not audited: they change nothing, so there is nothing
# to flag about them. kv_keys_scan is a read too, but it is not a
# kv_batch op at all, so it lands in the unparseable list instead.
WRITE_SAFETY_WRITE_OPS = (
    "kv_set", "kv_del", "kv_incr", "kv_expire",
    "kv_mset", "kv_setnx", "kv_setex", "kv_getset", "kv_getdel",
    "kv_append", "kv_decr", "kv_decrby", "kv_getex", "kv_setrange",
    "kv_setbit", "kv_bitop", "kv_bitfield",
    "kv_hsetnx", "kv_hincrby", "kv_hincrbyfloat",
    "kv_hexpire", "kv_hpexpire", "kv_hexpireat", "kv_hpexpireat",
    "kv_hpersist",
    "kv_zpopmin", "kv_zpopmax",
    "kv_zremrangebyscore", "kv_zremrangebyrank", "kv_zremrangebylex",
    "kv_zunionstore", "kv_zinterstore", "kv_zdiffstore",
    "kv_pfadd", "kv_pfmerge",
    "kv_geoadd",
    "kv_georadius", "kv_georadiusbymember", "kv_geosearchstore",
    "kv_lset", "kv_linsert",
    "kv_lpushx", "kv_rpushx", "kv_ltrim", "kv_lmove",
    "kv_xadd", "kv_xreadgroup", "kv_xgroup_create", "kv_xack",
    "kv_xclaim", "kv_xgroup_setid",
)
WRITE_SAFETY_READ_OPS = ("kv_get", "kv_keys", "kv_dbsize", "kv_ttl",
                         "kv_exists",
                         "kv_strlen", "kv_getrange", "kv_getbit",
                         "kv_bitcount", "kv_hscan",
                         "kv_hkeys", "kv_hvals",
                         "kv_httl", "kv_hpttl",
                         "kv_zrandmember", "kv_zscan", "kv_zrangebylex",
                         "kv_zrevrange", "kv_zrevrangebyscore",
                         "kv_zlexcount", "kv_zmscore", "kv_zunion",
                         "kv_zinter", "kv_zdiff", "kv_pfcount",
                         "kv_geodist", "kv_geopos", "kv_geohash",
                         "kv_geosearch", "kv_georadius_ro",
                         "kv_georadiusbymember_ro",
                         "kv_lindex", "kv_sscan",
                         "kv_xrange", "kv_xrevrange", "kv_xlen", "kv_xread",
                         "kv_xpending")

# A largest-string recommendation only fires when the biggest string
# is at least this many bytes, and a largest-container one when the
# biggest container holds at least this many elements: below that,
# the largest key is unremarkable and not worth an action.
HEALTH_BIG_STRING_BYTES = 1024
HEALTH_BIG_CONTAINER_ELEMENTS = 100

# TTL bucket boundaries, in seconds: under 1 hour, under 1 day,
# under 1 week, over 1 week. Keys with TTL -1 have no expiry.
BUCKET_BOUNDS = (3600, 86400, 604800)

# Cleanup-plan classification thresholds, in seconds. A key expiring
# within the hour dies on its own almost immediately, so deleting it
# early changes nothing; a key expiring within a day needs a renew-or-
# let-go decision; anything longer-lived is kept by default.
CLEANUP_SAFE_TTL = 3600
CLEANUP_SOON_TTL = 86400

# Name segments that suggest a key holds temporary data: a no-expiry
# key in one of these namespaces is flagged as likely stale, but it
# still needs a human to confirm the delete — the name is a hint, not
# proof the key is safe to drop.
TEMP_NAME_HINTS = ("cache", "tmp", "temp", "session", "sess", "lock", "rate")

PROMPTS = [
    {
        "name": "keyspace-summary",
        "description": (
            "Summarize the current cinder keyspace and suggest what to "
            "check next: which keys to read, which may be stale, and "
            "which look out of place."
        ),
        "arguments": [
            {
                "name": "pattern",
                "description": "Glob pattern of keys to include (* and ?). Defaults to all keys.",
                "required": False,
            },
        ],
    },
    {
        "name": "key-deep-dive",
        "description": (
            "Deep dive on one key: its type, TTL, size, a sample of its "
            "value, and the keys related to it, and what looks off about it."
        ),
        "arguments": [
            {
                "name": "key",
                "description": "The key to inspect.",
                "required": True,
            },
        ],
    },
    {
        "name": "ttl-audit",
        "description": (
            "Audit TTLs across the keyspace: bucket keys by how soon "
            "they expire, list the soonest-expiring keys and the keys "
            "with no expiry, and flag what the operator should act on."
        ),
        "arguments": [
            {
                "name": "pattern",
                "description": "Glob pattern of keys to include (* and ?). Defaults to all keys.",
                "required": False,
            },
        ],
    },
    {
        "name": "cleanup-plan",
        "description": (
            "Plan a keyspace cleanup: inspect the live keyspace, "
            "classify every key as safe to delete, expiring soon, "
            "risky to delete without confirmation, or keep, and "
            "produce a concrete cleanup plan with exact kv_del calls."
        ),
        "arguments": [
            {
                "name": "pattern",
                "description": "Glob pattern of keys to include (* and ?). Defaults to all keys.",
                "required": False,
            },
        ],
    },
    {
        "name": "keyspace-health",
        "description": (
            "Report keyspace health in one view: total keys, type "
            "breakdown, keys without TTL, soonest-expiring keys, "
            "largest keys, and a short list of recommended actions."
        ),
        "arguments": [
            {
                "name": "pattern",
                "description": "Glob pattern of keys to include (* and ?). Defaults to all keys.",
                "required": False,
            },
        ],
    },
    {
        "name": "write-safety",
        "description": (
            "Audit a proposed write plan against the live keyspace "
            "before it runs: flag overwrites of keys that never "
            "expire, overwrites of large keys, SETs, MSETs, SETEXes "
            "and GETSETs that would destroy a container, GETDELs "
            "that would delete a key that never expires, INCRs and "
            "DECRs that would fail, HINCRBYs that would fail on a "
            "non-integer field or a container, HINCRBYFLOATs that "
            "would fail on a non-float field or a container, "
            "HSETNXes that would fail on a container, APPENDs that "
            "would fail, SETBITs that would fail on a container or "
            "with a bad offset, BITOPs that would fail on a container "
            "or overwrite a key that never expires, BITFIELDs that "
            "would fail on a container or with a bad offset or a bad "
            "value, GETEXes that "
            "would change or remove a TTL, "
            "ZPOPs that would drain a sorted set, ZREMRANGEBYSCOREs, "
            "ZREMRANGEBYRANKs and ZREMRANGEBYLEXes that would drain "
            "one, LPUSHXes and "
            "RPUSHXes that would fail on a container, LTRIMs that "
            "would delete a list outright, LMOVEs that would fail "
            "on a container or drain a source list, PFADDs that "
            "would fail on a plain string or a container, PFMERGEs "
            "that would discard a destination's registers or fail "
            "on a plain string or a container, GEOADDs that would "
            "fail on a key that is not a sorted set or move "
            "members of a geo set, GEORADIUSes and "
            "GEORADIUSBYMEMBERs that would store their hits at a "
            "destination, overwriting it whatever it held, clearing "
            "its TTL, or deleting it on an empty result — a plain "
            "GEORADIUS is a read, and GEOSEARCH, GEORADIUS_RO and "
            "GEORADIUSBYMEMBER_RO are reads too — "
            "GEOSEARCHSTOREs that would store their hits at a "
            "destination, overwriting it whatever it held, clearing "
            "its TTL, or deleting it on an empty result, XADDs that "
            "would fail on a container or trim entries off a stream, "
            "XREADGROUPs that would fail on a missing key or group "
            "or deliver new entries into a group's pending list, "
            "XGROUP CREATEs that would fail on a missing key or a "
            "group that already exists, XACKs that would fail on a "
            "missing key or group, "
            "and EXPIREs with "
            "a bad timeout, and give a go/no-go per risky op. Read "
            "ops in the plan are not audited — XRANGE, XREVRANGE, "
            "XLEN, XREAD and XPENDING are reads, like GET."
        ),
        "arguments": [
            {
                "name": "plan",
                "description": (
                    "JSON array of kv_batch-shaped ops to audit, e.g. "
                    '[{"op": "kv_set", "key": "user:1", "value": "x"}, '
                    '{"op": "kv_del", "key": "cache:old"}]. At most 50 '
                    "ops are audited."
                ),
                "required": True,
            },
        ],
    },
    {
        "name": "ttl-renewal",
        "description": (
            "Plan TTL renewals: read live TTLs for a key pattern or "
            "an explicit list of keys, flag keys that are already "
            "expired or missing and keys with no expiry, and propose "
            "one kv_expire renewal per key up to a safety cap, "
            "renewing each key to a configurable target TTL."
        ),
        "arguments": [
            {
                "name": "pattern",
                "description": "Glob pattern of keys to include (* and ?). Defaults to all keys. Ignored when keys is given.",
                "required": False,
            },
            {
                "name": "keys",
                "description": (
                    "JSON array of exact key names to plan renewals "
                    "for, e.g. '[\"session:1\", \"cache:x\"]'. "
                    "Overrides pattern when given."
                ),
                "required": False,
            },
            {
                "name": "target_ttl",
                "description": (
                    "TTL in seconds to renew each key to. Defaults "
                    "to 86400 (1 day)."
                ),
                "required": False,
            },
            {
                "name": "max_keys",
                "description": (
                    "Safety cap: at most this many keys are covered "
                    "by the plan. Defaults to 20, at most 100."
                ),
                "required": False,
            },
        ],
    },
    {
        "name": "key-migration",
        "description": (
            "Plan migrating keys matching a pattern to a new prefix: "
            "audit each key's type, size, and TTL, flag target "
            "names that already exist, and lay out the ordered "
            "copy steps — list keys move atomically one element "
            "at a time with kv_lmove, other keys copy and then "
            "delete the source with the exact kv_del calls — "
            "up to a safety cap."
        ),
        "arguments": [
            {
                "name": "pattern",
                "description": "Glob pattern of keys to migrate (* and ?). Defaults to all keys.",
                "required": False,
            },
            {
                "name": "target_prefix",
                "description": (
                    "The prefix migrated keys get, e.g. 'v2:': a key "
                    "'old:user:1' matching pattern 'old:*' migrates "
                    "to 'v2:user:1'."
                ),
                "required": True,
            },
            {
                "name": "max_keys",
                "description": (
                    "Safety cap: at most this many ready keys are "
                    "covered by the plan. Defaults to 20, at most 100."
                ),
                "required": False,
            },
        ],
    },
]


def _prompt_def(name):
    for prompt in PROMPTS:
        if prompt["name"] == name:
            return prompt
    raise ValueError("unknown prompt: %s" % name)


def get_prompt(client, name, arguments):
    """Build one prompt's messages from live cinder data. Returns the
    MCP prompts/get result dict: description plus a list of messages."""
    arguments = arguments or {}
    if name == "keyspace-summary":
        return _keyspace_summary(client, arguments)
    if name == "key-deep-dive":
        return _key_deep_dive(client, arguments)
    if name == "ttl-audit":
        return _ttl_audit(client, arguments)
    if name == "cleanup-plan":
        return _cleanup_plan(client, arguments)
    if name == "keyspace-health":
        return _keyspace_health(client, arguments)
    if name == "write-safety":
        return _write_safety(client, arguments)
    if name == "ttl-renewal":
        return _ttl_renewal(client, arguments)
    if name == "key-migration":
        return _key_migration(client, arguments)
    raise ValueError("unknown prompt: %s" % name)


def _keyspace_summary(client, arguments):
    pattern = arguments.get("pattern", "*")
    info = client.command("INFO")
    keys = client.command("KEYS", pattern)
    if keys is None:
        keys = []
    lines = [
        "Here is the current state of the cinder keyspace.",
        "",
        "Server info:",
        info.strip() if info else "(no INFO output)",
        "",
        "Keys matching %r (%d):" % (pattern, len(keys)),
    ]
    if keys:
        lines.extend("- %s" % key for key in sorted(keys))
    else:
        lines.append("(no keys)")
    lines.extend([
        "",
        "Summarize this keyspace: how many keys there are, what groups "
        "the key names fall into, and anything that looks out of place.",
        "Then suggest what to check next, in priority order: keys worth "
        "reading in full with kv_get or cinder://key/<key>, keys whose "
        "expiry is worth checking with kv_ttl, and any keys that look "
        "stale or orphaned and might be safe to delete with kv_del.",
    ])
    return {
        "description": _prompt_def("keyspace-summary")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _inspect_key(client, key):
    """Type and size of one key, plus a sample value for string keys.
    Returns (kind, size_value, size_text, sample) where sample is
    the string value for string keys and None for containers.
    size_value is the byte length for strings and the element count
    for containers, so callers can rank keys by size; size_text is
    the human rendering ("5 bytes", "2 elements"). Cinder has no
    TYPE command, so the type is probed the same way the per-key
    resource does: GET succeeds for strings, otherwise LLEN /
    SCARD / HLEN / ZCARD / XLEN are tried in turn and the first one
    that does not answer WRONGTYPE names it."""
    try:
        value = client.command("GET", key)
    except RespError:
        # Not a string: probe the container types.
        for probe, name in (("LLEN", "list"), ("SCARD", "set"),
                            ("HLEN", "hash"), ("ZCARD", "zset"),
                            ("XLEN", "stream")):
            try:
                length = client.command(probe, key)
            except RespError:
                continue
            return name, length, "%d elements" % length, None
        raise ValueError("key has an unreadable type: %s" % key)
    if value is None:
        # The key expired between EXISTS and GET, or was deleted.
        raise ValueError("key not found: %s" % key)
    size = len(value.encode("utf-8"))
    return "string", size, "%d bytes" % size, value


def _key_deep_dive(client, arguments):
    """One key in detail: type, TTL, size, a sample of its value, and
    the keys that share its namespace."""
    key = arguments.get("key")
    if not key:
        raise ValueError("key-deep-dive requires a key argument")
    if client.command("EXISTS", key) == 0:
        raise ValueError("key not found: %s" % key)
    ttl = client.command("TTL", key)
    kind, _size_value, size, sample = _inspect_key(client, key)
    if ttl == -2:
        ttl_text = "expired while reading"
    elif ttl == -1:
        ttl_text = "no expiry set"
    else:
        ttl_text = "%d seconds remaining" % ttl
    related = _related_keys(client, key)
    lines = [
        "Deep dive on key %r." % key,
        "",
        "Type: %s" % kind,
        "TTL: %s" % ttl_text,
        "Size: %s" % size,
    ]
    if sample is not None:
        if len(sample) > MAX_SAMPLE_CHARS:
            sample = sample[:MAX_SAMPLE_CHARS] + "... (truncated)"
        lines.extend(["", "Sample value:", sample])
    lines.extend([
        "",
        "Related keys (%d):" % len(related),
    ])
    if related:
        lines.extend("- %s" % other for other in related)
    else:
        lines.append("(none)")
    lines.extend([
        "",
        "Assess this key: is the TTL sane for what the value looks "
        "like, does the value look well-formed or corrupted, and do "
        "the related keys suggest this key belongs to a larger group "
        "that should be checked together? Say what, if anything, "
        "looks wrong, and what to do about it with kv_get, kv_ttl, "
        "kv_expire, kv_del, or cinder://key/%s." % key,
    ])
    return {
        "description": _prompt_def("key-deep-dive")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _bounded_insert(ordered, item, cap):
    """Insert `item` into the sorted list `ordered`, keeping at most
    `cap` smallest items. Items compare with <, so this works for
    keys, for (ttl, key) pairs, and for (key, line) pairs alike.
    The prompts use it to keep only the entries they actually print
    — the 10 soonest-expiring keys, the first 20 of a section —
    plus a count of the rest, instead of holding every key."""
    bisect.insort(ordered, item)
    if len(ordered) > cap:
        ordered.pop()


def _format_ttl(seconds):
    """Render a TTL in seconds as a short human duration: 45s, 12m,
    3h 20m, 2d 4h, 3w 1d."""
    if seconds < 60:
        return "%ds" % seconds
    if seconds < 3600:
        return "%dm" % (seconds // 60)
    if seconds < 86400:
        return "%dh %dm" % (seconds // 3600, (seconds % 3600) // 60)
    if seconds < 604800:
        return "%dd %dh" % (seconds // 86400, (seconds % 86400) // 3600)
    return "%dw %dd" % (seconds // 604800, (seconds % 604800) // 86400)


def _ttl_audit(client, arguments):
    """Scan the keyspace in bounded batches, group every key by how
    soon it expires, and list the soonest-expiring keys and the keys
    with no expiry so the operator can act on them. TTL is probed
    per key with TTL: -1 means no expiry, -2 means the key expired
    between the SCAN and the TTL probe and is counted
    separately rather than bucketed. The scan is streamed: keys are
    processed batch by batch and only counts plus the bounded
    soonest / no-expiry lists are kept, so the prompt text stays
    bounded however large the keyspace is."""
    pattern = arguments.get("pattern", "*")
    bucket_counts = {
        "no expiry": 0,
        "expiring in under 1 hour": 0,
        "expiring in under 1 day": 0,
        "expiring in under 1 week": 0,
        "expiring in over 1 week": 0,
    }
    expired = 0
    total = 0
    expiring = 0
    soonest = []  # bounded sorted (ttl, key), at most MAX_SOON_KEYS
    no_expiry = []  # bounded sorted keys, at most MAX_NO_EXPIRY_KEYS
    no_expiry_count = 0
    for batch in iter_keys(client, pattern, PROMPT_SCAN_BATCH_SIZE):
        for key in batch:
            total += 1
            ttl = client.command("TTL", key)
            if ttl == -2:
                expired += 1
            elif ttl == -1:
                bucket_counts["no expiry"] += 1
                no_expiry_count += 1
                _bounded_insert(no_expiry, key, MAX_NO_EXPIRY_KEYS)
            elif ttl < BUCKET_BOUNDS[0]:
                bucket_counts["expiring in under 1 hour"] += 1
                expiring += 1
                _bounded_insert(soonest, (ttl, key), MAX_SOON_KEYS)
            elif ttl < BUCKET_BOUNDS[1]:
                bucket_counts["expiring in under 1 day"] += 1
                expiring += 1
                _bounded_insert(soonest, (ttl, key), MAX_SOON_KEYS)
            elif ttl < BUCKET_BOUNDS[2]:
                bucket_counts["expiring in under 1 week"] += 1
                expiring += 1
                _bounded_insert(soonest, (ttl, key), MAX_SOON_KEYS)
            else:
                bucket_counts["expiring in over 1 week"] += 1
                expiring += 1
                _bounded_insert(soonest, (ttl, key), MAX_SOON_KEYS)
    lines = [
        "TTL audit of the cinder keyspace (pattern %r)." % pattern,
        "",
        "Total keys scanned: %d" % total,
    ]
    if expired:
        lines.append(
            "%d key(s) expired while scanning and were not bucketed."
            % expired
        )
    lines.extend(["", "TTL buckets:"])
    for label, count in bucket_counts.items():
        lines.append("- %s: %d" % (label, count))
    lines.extend(["", "Soonest expiring keys (%d):" % expiring])
    if soonest:
        for ttl, key in soonest:
            lines.append("- %s (in %s)" % (key, _format_ttl(ttl)))
        if expiring > MAX_SOON_KEYS:
            lines.append("... and %d more" % (expiring - MAX_SOON_KEYS))
    else:
        lines.append("(none expiring)")
    lines.extend(["", "Keys with no expiry (%d):" % no_expiry_count])
    if no_expiry:
        for key in no_expiry:
            lines.append("- %s" % key)
        if no_expiry_count > MAX_NO_EXPIRY_KEYS:
            lines.append(
                "... and %d more" % (no_expiry_count - MAX_NO_EXPIRY_KEYS)
            )
    else:
        lines.append("(none)")
    lines.extend([
        "",
        "Audit these TTLs: which keys expiring within the hour look "
        "like they should live longer, and should be renewed with "
        "kv_expire? Which keys with no expiry look like caches, "
        "sessions, or temporary data that should have an expiry set "
        "with kv_expire? Are there keys whose TTL looks wrong for "
        "their namespace — for example a session key expiring in a "
        "week, or a cache key with no expiry at all? List the "
        "actions in priority order, with the exact kv_expire or "
        "kv_del call for each.",
    ])
    return {
        "description": _prompt_def("ttl-audit")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _classify_cleanup(name, ttl):
    """Classify one key for the cleanup plan: "safe", "soon", "risky",
    or "keep". A key expiring within the hour is safe to delete now —
    it dies on its own almost immediately, so deleting early changes
    nothing. A key expiring within a day needs a renew-or-let-go
    decision. A key with no expiry is risky: only a human who knows
    what the key is for can say whether deleting it is safe, so it
    goes to the confirm list. A key living longer than a day is kept
    by default. ttl is the raw TTL reply: -1 means no expiry."""
    if ttl == -1:
        return "risky"
    if ttl < CLEANUP_SAFE_TTL:
        return "safe"
    if ttl < CLEANUP_SOON_TTL:
        return "soon"
    return "keep"


def _looks_temporary(name):
    """True when a key name suggests temporary data: one of its ':'
    segments is a temp hint (cache, tmp, session, lock, ...). A
    substring match would misfire on names like "mycache", so the
    segments are compared exactly."""
    return any(segment in TEMP_NAME_HINTS for segment in name.split(":"))


def _cleanup_plan(client, arguments):
    """Inspect the live keyspace in bounded batches — INFO, then a
    per-key TTL, type, and size probe — classify every key as safe
    to delete, expiring soon, risky to delete without confirmation,
    or keep, and ask the model to turn that into a concrete cleanup
    plan. Keys that expire between the SCAN and the TTL probe
    (TTL -2) are counted separately rather than classified. Keys
    that vanish between the TTL probe and the type probe are skipped
    the same way. The scan is streamed: each section keeps only its
    first 20 keys (in key order) plus a count of the rest, so the
    prompt text stays bounded however large the keyspace is."""
    pattern = arguments.get("pattern", "*")
    info = client.command("INFO")
    # Per section, a bounded sorted list of (key, rendered line).
    sections = {"safe": [], "soon": [], "risky": [], "keep": []}
    counts = {"safe": 0, "soon": 0, "risky": 0, "keep": 0}
    expired = 0
    total = 0
    for batch in iter_keys(client, pattern, PROMPT_SCAN_BATCH_SIZE):
        for key in batch:
            total += 1
            ttl = client.command("TTL", key)
            if ttl == -2:
                expired += 1
                continue
            try:
                kind, _size_value, size, _sample = _inspect_key(client, key)
            except ValueError:
                # The key vanished between the TTL probe and the type probe.
                expired += 1
                continue
            category = _classify_cleanup(key, ttl)
            if ttl == -1:
                ttl_text = "no expiry"
            else:
                ttl_text = "expires in %s" % _format_ttl(ttl)
            note = ""
            if category == "risky" and _looks_temporary(key):
                note = ", looks temporary"
            counts[category] += 1
            _bounded_insert(
                sections[category],
                (key, "- %s (%s, %s, %s%s)" % (key, kind, size, ttl_text, note)),
                MAX_CLEANUP_KEYS,
            )
    lines = [
        "Cleanup plan for the cinder keyspace (pattern %r)." % pattern,
        "",
        "Server info:",
        info.strip() if info else "(no INFO output)",
        "",
        "Total keys scanned: %d" % total,
    ]
    if expired:
        lines.append(
            "%d key(s) expired while scanning and were not classified."
            % expired
        )
    section_text = [
        ("safe",
         "Safe to delete (%d) — these expire within the hour, so "
         "deleting them now changes nothing:"),
        ("soon",
         "Expiring soon (%d) — these expire within a day; renew them "
         "with kv_expire or let them go:"),
        ("risky",
         "Risky — confirm before deleting (%d) — these have no "
         "expiry, so only a human who knows what each key is for can "
         "say whether deleting it is safe:"),
        ("keep",
         "Keep (%d) — long-lived by design, no action:"),
    ]
    for category, header in section_text:
        members = sections[category]
        lines.extend(["", header % counts[category]])
        if members:
            lines.extend(line for _key, line in members)
            if counts[category] > MAX_CLEANUP_KEYS:
                lines.append(
                    "... and %d more" % (counts[category] - MAX_CLEANUP_KEYS)
                )
        else:
            lines.append("(none)")
    lines.extend([
        "",
        "Produce a concrete cleanup plan, in this order: first the "
        "safe deletes, with the exact kv_del call for each key; then "
        "the keys expiring soon, saying for each whether to renew it "
        "with kv_expire or let it expire, and why; then the risky "
        "keys, saying what to check before deleting each one — its "
        "value with kv_get or cinder://key/<key>, its namespace, and "
        "whether its name suggests temporary data — and which ones, "
        "if any, you would still delete with kv_del. Challenge the "
        "classification where the key name or size suggests it is "
        "wrong: a key that looks like live user data must never be "
        "deleted on the basis of its TTL alone, and a no-expiry key "
        "in a temporary namespace is only a candidate until a human "
        "confirms it. Do not delete anything yourself: list the calls "
        "for the operator to run.",
    ])
    return {
        "description": _prompt_def("cleanup-plan")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _related_keys(client, key):
    """Keys that share the inspected key's namespace: the part before
    the first ':' (or the key's own prefix when there is no ':')."""
    if ":" in key:
        pattern = key.split(":", 1)[0] + ":*"
    else:
        pattern = key + "*"
    keys = client.command("KEYS", pattern)
    if keys is None:
        return []
    return sorted(k for k in keys if k != key)[:MAX_RELATED_KEYS]


def _keyspace_health(client, arguments):
    """One-view health report: total keys, type breakdown, keys
    without TTL, soonest-expiring keys, the largest keys, and a
    short list of recommended actions. Scanned in bounded batches
    like ttl-audit and cleanup-plan; only counts plus the bounded
    top-10 lists are kept, so the prompt text stays bounded however
    large the keyspace is. "Largest" is measured where it is cheap:
    string keys by byte length and containers by element count,
    reported separately because bytes and element counts are not
    comparable. Keys that expire between the SCAN and the
    probes are counted separately rather than reported. The
    recommended actions are derived from the data, not invented:
    no-expiry keys get a kv_expire suggestion (temporary-looking
    names first), keys expiring within the hour get a renew-or-let-
    go decision, and a largest key only earns an inspection action
    when it is big enough to be remarkable."""
    pattern = arguments.get("pattern", "*")
    info = client.command("INFO")
    type_counts = {"string": 0, "list": 0, "set": 0, "hash": 0}
    total = 0
    expired = 0
    no_expiry = []  # bounded sorted keys, at most MAX_HEALTH_KEYS
    no_expiry_count = 0
    expiring = 0
    expiring_soon = 0  # expiring within the hour
    soonest = []  # bounded sorted (ttl, key), at most MAX_HEALTH_KEYS
    # Largest keys, stored negated so _bounded_insert keeps the
    # biggest: (-size, key) sorts smallest-first, i.e. largest size
    # first, and pop() drops the smallest size.
    largest_strings = []  # (-bytes, key)
    largest_containers = []  # (-elements, key)
    for batch in iter_keys(client, pattern, PROMPT_SCAN_BATCH_SIZE):
        for key in batch:
            total += 1
            ttl = client.command("TTL", key)
            if ttl == -2:
                expired += 1
                continue
            try:
                kind, size_value, _size_text, _sample = _inspect_key(client, key)
            except ValueError:
                # The key vanished between the TTL probe and the type probe.
                expired += 1
                continue
            type_counts[kind] += 1
            if ttl == -1:
                no_expiry_count += 1
                _bounded_insert(no_expiry, key, MAX_HEALTH_KEYS)
            else:
                expiring += 1
                _bounded_insert(soonest, (ttl, key), MAX_HEALTH_KEYS)
                if ttl < CLEANUP_SAFE_TTL:
                    expiring_soon += 1
            if kind == "string":
                _bounded_insert(
                    largest_strings, (-size_value, key), MAX_HEALTH_KEYS
                )
            else:
                _bounded_insert(
                    largest_containers, (-size_value, key), MAX_HEALTH_KEYS
                )
    lines = [
        "Keyspace health report (pattern %r)." % pattern,
        "",
        "Server info:",
        info.strip() if info else "(no INFO output)",
        "",
        "Total keys scanned: %d" % total,
    ]
    if expired:
        lines.append(
            "%d key(s) expired while scanning and were not reported."
            % expired
        )
    lines.extend(["", "Type breakdown:"])
    for kind in ("string", "list", "set", "hash"):
        lines.append("- %s: %d" % (kind, type_counts[kind]))
    lines.extend(["", "Keys with no expiry (%d):" % no_expiry_count])
    if no_expiry:
        for key in no_expiry:
            lines.append("- %s" % key)
        if no_expiry_count > MAX_HEALTH_KEYS:
            lines.append(
                "... and %d more" % (no_expiry_count - MAX_HEALTH_KEYS)
            )
    else:
        lines.append("(none)")
    lines.extend(["", "Soonest expiring keys (%d):" % expiring])
    if soonest:
        for ttl, key in soonest:
            lines.append("- %s (in %s)" % (key, _format_ttl(ttl)))
        if expiring > MAX_HEALTH_KEYS:
            lines.append("... and %d more" % (expiring - MAX_HEALTH_KEYS))
    else:
        lines.append("(none expiring)")
    lines.extend(["", "Largest string keys (by bytes):"])
    if largest_strings:
        for neg_size, key in largest_strings:
            lines.append("- %s (%d bytes)" % (key, -neg_size))
        if type_counts["string"] > MAX_HEALTH_KEYS:
            lines.append(
                "... and %d more" % (type_counts["string"] - MAX_HEALTH_KEYS)
            )
    else:
        lines.append("(none)")
    containers = (
        type_counts["list"] + type_counts["set"] + type_counts["hash"]
    )
    lines.extend(["", "Largest container keys (by element count):"])
    if largest_containers:
        for neg_size, key in largest_containers:
            lines.append("- %s (%d elements)" % (key, -neg_size))
        if containers > MAX_HEALTH_KEYS:
            lines.append("... and %d more" % (containers - MAX_HEALTH_KEYS))
    else:
        lines.append("(none)")
    actions = []
    if total == 0:
        actions.append("Nothing to do: the keyspace is empty.")
    else:
        if no_expiry_count:
            temp = [k for k in no_expiry if _looks_temporary(k)]
            if temp:
                actions.append(
                    "Give the %d key(s) with no expiry a TTL with "
                    "kv_expire, starting with the temporary-looking "
                    "ones: %s." % (no_expiry_count, ", ".join(temp))
                )
            else:
                actions.append(
                    "Give the %d key(s) with no expiry a TTL with "
                    "kv_expire, starting with the ones listed above."
                    % no_expiry_count
                )
        if expiring_soon:
            actions.append(
                "Decide on the %d key(s) expiring within the hour: "
                "renew them with kv_expire or let them go."
                % expiring_soon
            )
        if largest_strings and -largest_strings[0][0] >= HEALTH_BIG_STRING_BYTES:
            big_key = largest_strings[0][1]
            actions.append(
                "Inspect the largest string key %r (%d bytes) with "
                "key-deep-dive or cinder://key/%s: a multi-kilobyte "
                "value may be a runaway cache entry."
                % (big_key, -largest_strings[0][0], big_key)
            )
        if (
            largest_containers
            and -largest_containers[0][0] >= HEALTH_BIG_CONTAINER_ELEMENTS
        ):
            big_key = largest_containers[0][1]
            actions.append(
                "Inspect the largest container %r (%d elements) with "
                "key-deep-dive or cinder://key/%s: a very long list, "
                "set, or hash may be growing without bound."
                % (big_key, -largest_containers[0][0], big_key)
            )
        dominant_kind, dominant_count = max(
            type_counts.items(), key=lambda item: item[1]
        )
        if total >= 5 and dominant_count * 5 >= total * 4:
            actions.append(
                "The keyspace is %d%% %s keys — check that matches "
                "what this cinder instance is for."
                % (dominant_count * 100 // total, dominant_kind)
            )
        if not actions:
            actions.append(
                "Nothing urgent: no key needs an expiry, a renewal, "
                "or a size check."
            )
    lines.extend(["", "Recommended actions:"])
    lines.extend("- %s" % action for action in actions)
    lines.extend([
        "",
        "Assess the health of this keyspace: which of the recommended "
        "actions matter most, in what order, and is there anything in "
        "the type breakdown or the largest keys that suggests a "
        "problem the actions above miss? Give the exact kv_expire, "
        "kv_del, or key-deep-dive call for each action you endorse, "
        "and say which actions you would not take and why.",
    ])
    return {
        "description": _prompt_def("keyspace-health")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _is_int(text):
    """True when `text` parses as an integer. Used for kv_incr's
    current value and kv_expire's seconds: cinder answers INCR on a
    non-integer and EXPIRE with a bad timeout with an error, so the
    audit can predict those failures instead of letting the plan
    discover them at runtime."""
    try:
        int(text)
    except (TypeError, ValueError):
        return False
    return True


def _hincrby_audit_increment(op):
    """The increment for a kv_hincrby op in a write plan, validated
    like the tool's own argument: it must be an integer, and a
    negative one counts down. Anything else raises ValueError, so
    the caller reports the op as not audited instead of guessing."""
    increment = op.get("increment")
    if increment is None:
        raise ValueError("kv_hincrby is missing increment: %r" % (op,))
    if not _is_int(increment):
        raise ValueError(
            "kv_hincrby increment is not an integer: %r" % (increment,)
        )
    return increment


def _hexpire_audit_args(op):
    """The arguments of a hash-field TTL op in a write plan,
    validated like the tool's own arguments: `fields` a non-empty
    list of strings, at most 1000; the expire family's time an
    integer, 0 or more when relative, within cinder's range when
    absolute; the condition one of nx, xx, gt, lt. Returns
    (fields, condition, time_value, is_ms, absolute) — the time
    parts are None for kv_hpersist, which takes no time. Anything
    wrong raises ValueError, so the caller reports the op as not
    audited instead of guessing."""
    name = op.get("op")
    fields = op.get("fields")
    if not isinstance(fields, list) or not fields:
        raise ValueError(
            "%s fields must be a non-empty list: %r" % (name, fields)
        )
    if len(fields) > 1000:
        raise ValueError(
            "%s fields must have at most 1000 entries: %r"
            % (name, fields)
        )
    for field in fields:
        if not isinstance(field, str):
            raise ValueError(
                "%s fields must be strings: %r" % (name, field)
            )
    condition = op.get("condition")
    if condition is not None:
        if not isinstance(condition, str) \
                or condition.lower() not in ("nx", "xx", "gt", "lt"):
            raise ValueError(
                "%s condition must be one of nx, xx, gt, lt: %r"
                % (name, condition)
            )
        condition = condition.lower()
    if name == "kv_hpersist":
        return fields, None, None, None, False
    absolute = name.endswith("at")
    is_ms = name in ("kv_hpexpire", "kv_hpexpireat")
    time_field = "milliseconds" if is_ms else "seconds"
    time_value = op.get(time_field)
    if time_value is None:
        raise ValueError(
            "%s is missing %s: %r" % (name, time_field, op)
        )
    if isinstance(time_value, bool) or not isinstance(time_value, int):
        raise ValueError(
            "%s %s is not an integer: %r"
            % (name, time_field, time_value)
        )
    if absolute:
        if is_ms:
            lo, hi = -(2 ** 63), 2 ** 63 - 1
        else:
            lo = -((2 ** 63 - 1) // 1000)
            hi = (2 ** 63 - 1) // 1000
        if time_value < lo or time_value > hi:
            raise ValueError(
                "%s %s is out of range: %r"
                % (name, time_field, time_value)
            )
    elif time_value < 0:
        raise ValueError(
            "%s %s must be 0 or more: %r"
            % (name, time_field, time_value)
        )
    return fields, condition, time_value, is_ms, absolute


def _hexpire_condition_applies(condition, current_ms, effective_ms):
    """Whether a HEXPIRE-family op with `condition` would change a
    field whose current TTL is `current_ms` milliseconds (-1 for
    no expiry), setting it to expire in `effective_ms` — 0 or less
    deletes it at once. A field with no expiry counts as never
    expiring, as in cinder: GT never applies to it, LT always
    does."""
    if condition is None:
        return True
    if condition == "nx":
        return current_ms == -1
    if condition == "xx":
        return current_ms != -1
    if condition == "gt":
        return current_ms != -1 and effective_ms > current_ms
    return current_ms == -1 or effective_ms < current_ms


def _hexpire_effective_ms(time_value, is_ms, absolute):
    """The new field TTL a HEXPIRE-family op would set, in
    milliseconds from now — 0 or less means the fields are
    deleted at once. A relative time is already a duration; an
    absolute one is measured against now."""
    if absolute:
        now_ms = int(time.time() * 1000)
        at_ms = time_value if is_ms else time_value * 1000
        return at_ms - now_ms
    return time_value if is_ms else time_value * 1000


def _lset_audit_args(op):
    """The index and value for a kv_lset op in a write plan,
    validated like the tool's own arguments: the index must be an
    integer and the value a string. Anything else raises
    ValueError, so the caller reports the op as not audited
    instead of guessing."""
    index = op.get("index")
    if index is None:
        raise ValueError("kv_lset is missing index: %r" % (op,))
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError(
            "kv_lset index is not an integer: %r" % (index,)
        )
    if not isinstance(op.get("value"), str):
        raise ValueError(
            "kv_lset value must be a string: %r" % (op.get("value"),)
        )
    return index


def _linsert_audit_args(op):
    """The where, pivot, and element for a kv_linsert op in a write
    plan, validated like the tool's own arguments: `where` is
    "before" or "after" in any case, and the pivot and element are
    strings. Anything else raises ValueError, so the caller
    reports the op as not audited instead of guessing."""
    where = op.get("where")
    if not isinstance(where, str) or where.lower() not in ("before", "after"):
        raise ValueError(
            "kv_linsert where must be \"before\" or \"after\": %r" % (where,)
        )
    if not isinstance(op.get("pivot"), str):
        raise ValueError(
            "kv_linsert pivot must be a string: %r" % (op.get("pivot"),)
        )
    if not isinstance(op.get("element"), str):
        raise ValueError(
            "kv_linsert element must be a string: %r"
            % (op.get("element"),)
        )
    return where.lower()


def _lpushx_audit_elements(op):
    """The elements for a kv_lpushx / kv_rpushx op in a write plan,
    validated like the tool's own argument: a non-empty list of
    strings. Anything else raises ValueError, so the caller reports
    the op as not audited instead of guessing."""
    name = op.get("op")
    elements = op.get("elements")
    if not isinstance(elements, list) or not elements:
        raise ValueError(
            "%s elements must be a non-empty list: %r" % (name, elements)
        )
    for element in elements:
        if not isinstance(element, str):
            raise ValueError(
                "%s elements must be strings: %r" % (name, elements)
            )
    return elements


def _pfadd_audit_elements(op):
    """The elements for a kv_pfadd op in a write plan, validated
    like the tool's own argument: a non-empty list of strings.
    Anything else raises ValueError, so the caller reports the op
    as not audited instead of guessing."""
    elements = op.get("elements")
    if not isinstance(elements, list) or not elements:
        raise ValueError(
            "kv_pfadd elements must be a non-empty list: %r" % (elements,)
        )
    for element in elements:
        if not isinstance(element, str):
            raise ValueError(
                "kv_pfadd elements must be strings: %r" % (elements,)
            )
    return elements


def _geoadd_audit_members(op):
    """The members for a kv_geoadd op in a write plan, validated
    like the tool's own arguments: a non-empty object mapping
    member names to [longitude, latitude] pairs, each coordinate
    finite and in range (longitude -180 to 180, latitude
    -85.05112878 to 85.05112878). Anything else raises ValueError,
    so the caller reports the op as not audited instead of
    guessing. Returns the member names, in the object's order."""
    members = op.get("members")
    if not isinstance(members, dict) or not members:
        raise ValueError(
            "kv_geoadd members must be a non-empty object: %r"
            % (members,)
        )
    for member, pair in members.items():
        if not isinstance(member, str):
            raise ValueError(
                "kv_geoadd members must be strings: %r" % (members,)
            )
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError(
                "kv_geoadd member %r must be a [longitude, latitude] "
                "pair: %r" % (member, pair)
            )
        for value, low, high, axis in (
            (pair[0], -180.0, 180.0, "longitude"),
            (pair[1], -85.05112878, 85.05112878, "latitude"),
        ):
            if isinstance(value, bool) \
                    or not isinstance(value, (int, float)):
                raise ValueError(
                    "kv_geoadd %s must be a number: %r" % (axis, value)
                )
            if not math.isfinite(value):
                raise ValueError(
                    "kv_geoadd %s must be finite: %r" % (axis, value)
                )
            if value < low or value > high:
                raise ValueError(
                    "kv_geoadd %s must be between %s and %s: %r"
                    % (axis, low, high, value)
                )
    return list(members)


def _geoadd_audit_options(op):
    """The NX / XX / CH flags for a kv_geoadd op in a write plan,
    validated like the tool's own arguments: each flag must be a
    boolean when present, and NX with XX raises ValueError, so the
    caller reports the op as not audited instead of guessing.
    Returns (nx, xx, ch)."""
    flags = []
    for name in ("nx", "xx", "ch"):
        value = op.get(name, False)
        if not isinstance(value, bool):
            raise ValueError(
                "kv_geoadd %s must be true or false: %r" % (name, value)
            )
        flags.append(value)
    if flags[0] and flags[1]:
        raise ValueError(
            "kv_geoadd nx and xx cannot be used together: %r" % (op,)
        )
    return tuple(flags)


def _ltrim_audit_args(op):
    """The start and stop for a kv_ltrim op in a write plan,
    validated like the tool's own arguments: both must be integers.
    Anything else raises ValueError, so the caller reports the op
    as not audited instead of guessing."""
    start = op.get("start")
    if start is None:
        raise ValueError("kv_ltrim is missing start: %r" % (op,))
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError(
            "kv_ltrim start is not an integer: %r" % (start,)
        )
    stop = op.get("stop")
    if stop is None:
        raise ValueError("kv_ltrim is missing stop: %r" % (op,))
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError(
            "kv_ltrim stop is not an integer: %r" % (stop,)
        )
    return start, stop


def _lmove_audit_args(op):
    """The source, destination, and sides for a kv_lmove op in a
    write plan, validated like the tool's own arguments: `from`
    and `to` are "left" or "right" in any case. Anything else
    raises ValueError, so the caller reports the op as not audited
    instead of guessing."""
    source = op.get("source")
    if not isinstance(source, str):
        raise ValueError(
            "kv_lmove source must be a string: %r" % (source,)
        )
    destination = op.get("destination")
    if not isinstance(destination, str):
        raise ValueError(
            "kv_lmove destination must be a string: %r" % (destination,)
        )
    from_side = op.get("from")
    if not isinstance(from_side, str) \
            or from_side.lower() not in ("left", "right"):
        raise ValueError(
            "kv_lmove from must be \"left\" or \"right\": %r" % (from_side,)
        )
    to_side = op.get("to")
    if not isinstance(to_side, str) \
            or to_side.lower() not in ("left", "right"):
        raise ValueError(
            "kv_lmove to must be \"left\" or \"right\": %r" % (to_side,)
        )
    return source, destination, from_side.lower(), to_side.lower()


def _is_float(text):
    """True when `text` parses as a finite float. Cinder's float
    parser accepts "inf" as a value, but adding anything to it
    overflows, so a stored infinity is not a field HINCRBYFLOAT
    can bump — the audit treats it as not a float, like NaN."""
    try:
        value = float(text)
    except (TypeError, ValueError):
        return False
    return value == value and value not in (float("inf"), float("-inf"))


def _hincrbyfloat_audit_increment(op):
    """The increment for a kv_hincrbyfloat op in a write plan,
    validated like the tool's own argument: it must be a finite
    number, an int or a float, and a negative one counts down.
    Anything else raises ValueError, so the caller reports the op
    as not audited instead of guessing."""
    increment = op.get("increment")
    if increment is None:
        raise ValueError(
            "kv_hincrbyfloat is missing increment: %r" % (op,))
    if isinstance(increment, bool) or not isinstance(
        increment, (int, float)
    ):
        raise ValueError(
            "kv_hincrbyfloat increment is not a number: %r" % (increment,)
        )
    if isinstance(increment, float) and not _is_float(increment):
        raise ValueError(
            "kv_hincrbyfloat increment is not a finite number: %r"
            % (increment,)
        )
    return increment


def _getex_option(op):
    """The GETEX option from a write-plan op: (ex, px, persist).
    At most one option may be given, and persist must be a
    boolean; anything else raises ValueError, so the caller
    reports the op as not audited instead of guessing."""
    ex = op.get("ex")
    px = op.get("px")
    persist = op.get("persist", False)
    if not isinstance(persist, bool):
        raise ValueError(
            "kv_getex persist must be true or false: %r" % (persist,)
        )
    given = [name for name, value in (("ex", ex), ("px", px))
             if value is not None]
    if persist:
        given.append("persist")
    if len(given) > 1:
        raise ValueError(
            "kv_getex takes at most one of ex, px, persist: %r" % (op,)
        )
    return ex, px, persist


def _setrange_audit_args(op):
    """The (offset, value) for a kv_setrange op in a write plan,
    validated like the tool's own arguments: the offset must be an
    integer and the value a string. A negative offset is returned
    as-is — the caller reports it as risky (it would fail in
    cinder) rather than not audited. Anything else raises
    ValueError, so the caller reports the op as not audited
    instead of guessing."""
    offset = op.get("offset")
    if offset is None:
        raise ValueError("kv_setrange is missing offset: %r" % (op,))
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError(
            "kv_setrange offset must be an integer: %r" % (offset,)
        )
    value = op.get("value")
    if not isinstance(value, str):
        raise ValueError(
            "kv_setrange value must be a string: %r" % (value,)
        )
    return offset, value


def _setbit_audit_args(op):
    """The (offset, bit) for a kv_setbit op in a write plan,
    validated like the tool's own arguments: the offset must be
    an integer and the bit an integer. An out-of-range offset or
    a bit outside 0/1 is returned as-is — the caller reports it
    as risky (it would fail in cinder) rather than not audited.
    Anything else raises ValueError, so the caller reports the op
    as not audited instead of guessing."""
    offset = op.get("offset")
    if offset is None:
        raise ValueError("kv_setbit is missing offset: %r" % (op,))
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError(
            "kv_setbit offset must be an integer: %r" % (offset,)
        )
    bit = op.get("bit")
    if bit is None:
        raise ValueError("kv_setbit is missing bit: %r" % (op,))
    if isinstance(bit, bool) or not isinstance(bit, int):
        raise ValueError(
            "kv_setbit bit must be an integer: %r" % (bit,)
        )
    return offset, bit


def _bitop_audit_args(op):
    """The (operation, destination, sources) for a kv_bitop op in
    a write plan, validated like the tool's own arguments: the
    operation is "and", "or", "xor" or "not" in any case, the
    destination a string, the sources a non-empty list of
    strings, NOT with exactly one source and the rest with at
    least two. Anything else raises ValueError, so the caller
    reports the op as not audited instead of guessing."""
    operation = op.get("operation")
    if not isinstance(operation, str) \
            or operation.lower() not in ("and", "or", "xor", "not"):
        raise ValueError(
            "kv_bitop operation must be \"and\", \"or\", \"xor\" or "
            "\"not\": %r" % (op,)
        )
    destination = op.get("destination")
    if not isinstance(destination, str):
        raise ValueError(
            "kv_bitop destination must be a string: %r" % (op,)
        )
    sources = op.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(
            "kv_bitop sources must be a non-empty list: %r" % (op,)
        )
    for source in sources:
        if not isinstance(source, str):
            raise ValueError(
                "kv_bitop sources must be strings: %r" % (op,)
            )
    operation = operation.upper()
    if operation == "NOT":
        if len(sources) != 1:
            raise ValueError(
                "kv_bitop NOT takes exactly one source key: %r" % (op,)
            )
    elif len(sources) < 2:
        raise ValueError(
            "kv_bitop %s takes at least two source keys: %r"
            % (operation, op)
        )
    return operation, destination, sources


def _pfmerge_audit_args(op):
    """The (destination, sources) for a kv_pfmerge op in a write
    plan, validated like the tool's own arguments: the
    destination a string and the sources a non-empty list of
    strings, at most 1000. Anything else raises ValueError, so
    the caller reports the op as not audited instead of
    guessing."""
    destination = op.get("destination")
    if not isinstance(destination, str):
        raise ValueError(
            "kv_pfmerge destination must be a string: %r" % (destination,)
        )
    sources = op.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError(
            "kv_pfmerge sources must be a non-empty list: %r" % (sources,)
        )
    if len(sources) > 1000:
        raise ValueError(
            "kv_pfmerge merges at most 1000 sources; narrow the list"
        )
    for source in sources:
        if not isinstance(source, str):
            raise ValueError(
                "kv_pfmerge sources must be strings: %r" % (sources,)
            )
    return destination, sources


def _bitfield_audit_args(op):
    """The parsed ops for a kv_bitfield op in a write plan,
    validated like the tool's own arguments: each op is an object
    with "op" naming "get", "set", "incrby" or "overflow"; get /
    set / incrby take a type (i1..i64, u1..u63) and an offset (an
    integer or '#n'); set / incrby take an integer value; overflow
    takes a policy ("wrap", "sat" or "fail"). Returns a list of
    (kind, bits, bit_offset, value) tuples — bits and bit_offset
    None for overflow, value None for get / overflow. An offset
    that would run a field past 2^32 bits, or a value outside the
    signed 64-bit range, is returned as-is — the caller reports it
    as risky (it would fail in cinder) rather than not audited.
    Anything else raises ValueError, so the caller reports the op
    as not audited instead of guessing."""
    ops = op.get("ops")
    if not isinstance(ops, list) or not ops:
        raise ValueError(
            "kv_bitfield requires a non-empty ops list: %r" % (op,)
        )
    parsed = []
    for sub in ops:
        if not isinstance(sub, dict):
            raise ValueError(
                "kv_bitfield ops must be objects: %r" % (sub,)
            )
        kind = sub.get("op")
        if not isinstance(kind, str):
            raise ValueError(
                "kv_bitfield op needs an 'op': %r" % (sub,)
            )
        kind = kind.lower()
        if kind == "overflow":
            policy = sub.get("policy")
            if not isinstance(policy, str) \
                    or policy.lower() not in ("wrap", "sat", "fail"):
                raise ValueError(
                    "kv_bitfield overflow policy must be 'wrap', "
                    "'sat' or 'fail': %r" % (sub,)
                )
            parsed.append(("overflow", None, None, None))
            continue
        if kind not in ("get", "set", "incrby"):
            raise ValueError(
                "kv_bitfield op must be 'get', 'set', 'incrby' or "
                "'overflow': %r" % (sub,)
            )
        type_name = sub.get("type")
        if not isinstance(type_name, str):
            raise ValueError(
                "kv_bitfield type must be a string like 'i8' or "
                "'u8': %r" % (sub,)
            )
        text = type_name.lower()
        if len(text) < 2 or text[0] not in ("i", "u") \
                or not text[1:].isdigit():
            raise ValueError(
                "kv_bitfield type must be like 'i8' or 'u8': %r"
                % (sub,)
            )
        bits = int(text[1:])
        if bits < 1 or bits > 64 or (text[0] == "u" and bits == 64):
            raise ValueError(
                "kv_bitfield type must be i1..i64 or u1..u63: %r"
                % (sub,)
            )
        offset = sub.get("offset")
        if isinstance(offset, bool):
            raise ValueError(
                "kv_bitfield offset must be an integer or '#n': %r"
                % (sub,)
            )
        if isinstance(offset, int):
            bit_offset = offset
        elif isinstance(offset, str) and offset.startswith("#") \
                and offset[1:].isdigit():
            bit_offset = int(offset[1:]) * bits
        else:
            raise ValueError(
                "kv_bitfield offset must be an integer or '#n': %r"
                % (sub,)
            )
        value = None
        if kind in ("set", "incrby"):
            value = sub.get("value")
            if value is None:
                raise ValueError(
                    "kv_bitfield %s needs a value: %r" % (kind, sub)
                )
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(
                    "kv_bitfield %s value must be an integer: %r"
                    % (kind, sub)
                )
        parsed.append((kind, bits, bit_offset, value))
    return parsed


def _bitfield_audit_problem(parsed):
    """The first thing a parsed kv_bitfield op would fail on in
    cinder, or None: an offset that would run a field past 2^32
    bits, or a SET / INCRBY value outside the signed 64-bit
    range."""
    for kind, bits, bit_offset, value in parsed:
        if kind == "overflow":
            continue
        if bit_offset < 0 or bit_offset + bits > 4294967296:
            return "bit offset is out of range"
        if kind in ("set", "incrby") and (
                value < -(1 << 63) or value > (1 << 63) - 1):
            return "value is not an integer or out of range"
    return None


def _format_key_list(keys):
    """Key names quoted and comma-joined for one audit line, with
    the rest counted when there are more than a few: a kv_mset can
    hold many keys and the audit line still has to stay readable."""
    keys = sorted(keys)
    shown = keys[:5]
    text = ", ".join(repr(k) for k in shown)
    if len(keys) > len(shown):
        text += ", and %d more" % (len(keys) - len(shown))
    return text


def _mset_values(op):
    """The key/value pairs for a kv_mset in a write plan: a
    non-empty object of string key names to string values, as in
    the tool itself. Anything else raises ValueError, so the
    caller reports the op as not audited instead of guessing."""
    values = op.get("values")
    if not isinstance(values, dict) or not values:
        raise ValueError(
            "kv_mset values must be a non-empty object: %r" % (values,)
        )
    for key, value in values.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(
                "kv_mset values must map string key names to string "
                "values: %r" % (values,)
            )
    return values


def _audit_mset(client, op):
    """Audit one kv_mset op: every key in `values` is probed live,
    because one MSET can overwrite several keys at once and each
    has its own type, size, and TTL. Returns (verdict, line)."""
    values = _mset_values(op)
    keys = sorted(values)
    flags = []
    existed = 0
    for key in keys:
        if client.command("EXISTS", key) == 0:
            continue
        existed += 1
        ttl = client.command("TTL", key)
        if ttl == -2:
            # The key expired while auditing; the write creates it.
            existed -= 1
            continue
        try:
            kind, size_value, size, _sample = _inspect_key(client, key)
        except ValueError:
            # The key expired between the TTL read and the probe.
            existed -= 1
            continue
        large = (
            (kind == "string" and size_value >= HEALTH_BIG_STRING_BYTES)
            or (kind != "string" and size_value >= HEALTH_BIG_CONTAINER_ELEMENTS)
        )
        if kind != "string":
            flags.append(
                "%r would replace a %s of %s with a string, destroying "
                "its contents" % (key, kind, size)
            )
        if ttl == -1:
            flags.append("%r overwrites a key that never expires" % key)
        if large:
            flags.append("%r overwrites a large key (%s)" % (key, size))
    if flags:
        return "risky", "kv_mset %s — %s" % (
            _format_key_list(keys), "; ".join(flags))
    new = len(keys) - existed
    if existed == 0:
        return "caution", (
            "kv_mset %s — creates %d new key(s) with no expiry"
            % (_format_key_list(keys), len(keys))
        )
    if new:
        return "caution", (
            "kv_mset %s — overwrites %d existing key(s) and creates "
            "%d new key(s) with no expiry"
            % (_format_key_list(keys), existed, new)
        )
    return "caution", (
        "kv_mset %s — overwrites %d existing key(s)"
        % (_format_key_list(keys), existed)
    )


def _audit_xreadgroup(client, op):
    """Audit one kv_xreadgroup op: every stream in `streams` is
    probed live, because one read can deliver entries on several
    streams at once and each has its own type, TTL, and group. A
    ">" read delivers new entries to the consumer and records them
    in the group's pending list until XACK; an explicit-ID read
    only re-reads this consumer's pending entries and changes no
    delivery state. BLOCK does not change the verdict: a blocked
    ">" read still delivers when entries arrive, and a blocked
    explicit-ID read still changes no delivery state — it only
    waits out the timeout, since new entries are never pending
    for that consumer. Returns (verdict, line)."""
    group, consumer, keys, ids, _count, block = _xreadgroup_args(op)
    risky = []
    caution = []
    safe = []
    wait = ("; waits up to %dms for new entries" % block
            if block is not None else "")
    for key, id_value in zip(keys, ids):
        if client.command("EXISTS", key) == 0:
            risky.append(
                "%r would fail: no such key or consumer group %r"
                % (key, group)
            )
            continue
        ttl = client.command("TTL", key)
        if ttl == -2:
            # The key expired while auditing; the read would fail.
            risky.append(
                "%r would fail: no such key or consumer group %r"
                % (key, group)
            )
            continue
        try:
            kind, _size_value, size, _sample = _inspect_key(client, key)
        except ValueError:
            # The key expired between the TTL read and the probe.
            risky.append(
                "%r would fail: no such key or consumer group %r"
                % (key, group)
            )
            continue
        if kind != "stream":
            risky.append(
                "%r would fail with WRONGTYPE: the key is a %s of %s"
                % (key, kind, size)
            )
            continue
        try:
            client.command("XPENDING", key, group)
        except RespError as exc:
            if "NOGROUP" in str(exc):
                risky.append(
                    "%r would fail: no such consumer group %r"
                    % (key, group)
                )
                continue
            raise
        if id_value == ">":
            if ttl == -1:
                caution.append(
                    "delivers new entries to consumer %r in group %r "
                    "on stream %r, recording them in the pending list "
                    "until XACK%s, on a stream that never expires"
                    % (consumer, group, key, wait)
                )
            else:
                caution.append(
                    "delivers new entries to consumer %r in group %r "
                    "on stream %r, recording them in the pending list "
                    "until XACK%s" % (consumer, group, key, wait)
                )
        else:
            safe.append(
                "re-reads the pending entries of consumer %r in group "
                "%r on stream %r without changing delivery state%s"
                % (consumer, group, key, wait)
            )
    if risky:
        return "risky", "kv_xreadgroup — %s" % "; ".join(
            risky + caution + safe)
    if caution:
        return "caution", "kv_xreadgroup — %s" % "; ".join(caution + safe)
    return "safe", "kv_xreadgroup — %s" % "; ".join(safe)


def _audit_xgroup_create(client, op):
    """Audit one kv_xgroup_create op: the stream is probed live,
    and the group is probed with XPENDING — it answers for a group
    that exists and fails NOGROUP for one that does not. A group
    that already exists fails BUSYGROUP, and creating one on a
    missing key fails unless mkstream is set. Returns (verdict,
    line)."""
    key, group, id_value, mkstream = _xgroup_create_args(op)
    if client.command("EXISTS", key) == 0:
        if mkstream:
            return "caution", (
                "kv_xgroup_create — creates consumer group %r on a "
                "new empty stream %r, with no expiry"
                % (group, key)
            )
        return "risky", (
            "kv_xgroup_create — %r would fail: no such key; pass "
            "mkstream to create the stream" % key
        )
    ttl = client.command("TTL", key)
    if ttl == -2:
        # The key expired while auditing; the create would fail.
        if mkstream:
            return "caution", (
                "kv_xgroup_create — creates consumer group %r on a "
                "new empty stream %r, with no expiry"
                % (group, key)
            )
        return "risky", (
            "kv_xgroup_create — %r would fail: no such key; pass "
            "mkstream to create the stream" % key
        )
    try:
        kind, _size_value, size, _sample = _inspect_key(client, key)
    except ValueError:
        # The key expired between the TTL read and the probe.
        if mkstream:
            return "caution", (
                "kv_xgroup_create — creates consumer group %r on a "
                "new empty stream %r, with no expiry"
                % (group, key)
            )
        return "risky", (
            "kv_xgroup_create — %r would fail: no such key; pass "
            "mkstream to create the stream" % key
        )
    if kind != "stream":
        return "risky", (
            "kv_xgroup_create — %r would fail with WRONGTYPE: the "
            "key is a %s of %s" % (key, kind, size)
        )
    try:
        client.command("XPENDING", key, group)
    except RespError as exc:
        if "NOGROUP" in str(exc):
            if ttl == -1:
                return "caution", (
                    "kv_xgroup_create — creates consumer group %r on "
                    "stream %r starting at %r, on a stream that never "
                    "expires" % (group, key, id_value)
                )
            return "safe", (
                "kv_xgroup_create — creates consumer group %r on "
                "stream %r starting at %r" % (group, key, id_value)
            )
        raise
    return "risky", (
        "kv_xgroup_create — %r would fail with BUSYGROUP: consumer "
        "group %r already exists" % (key, group)
    )


def _audit_xack(client, op):
    """Audit one kv_xack op: the stream and the group are probed
    live, and the pending list is read with the extended XPENDING
    form so the ids that are actually pending are known — acking
    drops them from the pending list, while the entries stay in
    the stream, so nothing is lost. A bare-millisecond id is
    normalised to its first sequence before comparing, as cinder
    reads it. Returns (verdict, line)."""
    key, group, ids = _xack_args(op)
    if client.command("EXISTS", key) == 0:
        return "risky", (
            "kv_xack — %r would fail: no such key or consumer group "
            "%r" % (key, group)
        )
    ttl = client.command("TTL", key)
    if ttl == -2:
        # The key expired while auditing; the ack would fail.
        return "risky", (
            "kv_xack — %r would fail: no such key or consumer group "
            "%r" % (key, group)
        )
    try:
        kind, _size_value, size, _sample = _inspect_key(client, key)
    except ValueError:
        # The key expired between the TTL read and the probe.
        return "risky", (
            "kv_xack — %r would fail: no such key or consumer group "
            "%r" % (key, group)
        )
    if kind != "stream":
        return "risky", (
            "kv_xack — %r would fail with WRONGTYPE: the key is a "
            "%s of %s" % (key, kind, size)
        )
    try:
        total = client.command("XPENDING", key, group)[0]
    except RespError as exc:
        if "NOGROUP" in str(exc):
            return "risky", (
                "kv_xack — %r would fail: no such consumer group %r"
                % (key, group)
            )
        raise
    if total == 0:
        return "safe", (
            "kv_xack — no-op, nothing is pending in consumer group "
            "%r on stream %r" % (group, key)
        )
    checked = min(total, MAX_XPENDING_ENTRIES)
    pending = client.command("XPENDING", key, group, "-", "+", checked)
    pending_ids = {entry[0] for entry in pending}
    acked = [i for i in ids if _xack_normalised_id(i) in pending_ids]
    missed = [i for i in ids if _xack_normalised_id(i) not in pending_ids]
    if total > MAX_XPENDING_ENTRIES and missed:
        # Only the first 1000 pending entries were checked, so an
        # id outside them may still be pending.
        return "caution", (
            "kv_xack — drops %d pending %s from consumer group %r "
            "on stream %r, but only the first %d of %d pending "
            "entries were checked, so the other %d %s may still be "
            "pending"
            % (len(acked), "entry" if len(acked) == 1 else "entries",
               group, key, MAX_XPENDING_ENTRIES, total, len(missed),
               "id" if len(missed) == 1 else "ids")
        )
    if not acked:
        return "safe", (
            "kv_xack — no-op, none of the %d %s are pending in "
            "consumer group %r on stream %r"
            % (len(ids), "id" if len(ids) == 1 else "ids", group, key)
        )
    if not missed:
        return "safe", (
            "kv_xack — drops %d pending %s from consumer group %r "
            "on stream %r; the entries stay in the stream"
            % (len(acked), "entry" if len(acked) == 1 else "entries",
               group, key)
        )
    return "safe", (
        "kv_xack — drops %d pending %s from consumer group %r on "
        "stream %r and %d %s change nothing, since they are not "
        "pending; the entries stay in the stream"
        % (len(acked), "entry" if len(acked) == 1 else "entries",
           group, key, len(missed),
           "id" if len(missed) == 1 else "ids")
    )


def _xack_normalised_id(id_value):
    """One kv_xack id as the pending list spells it: a bare
    millisecond is the first sequence of that millisecond, so
    "2000" is "2000-0"; "ms-seq" is already spelled that way."""
    if "-" not in id_value:
        return "%s-0" % id_value
    return id_value


def _audit_xclaim(client, op):
    """Audit one kv_xclaim op: the stream and the group are probed
    live, and the pending list is read with the extended XPENDING
    form so the ids that are actually pending — and how long each
    has been idle — are known. A claim moves pending entries to
    another consumer and bumps their delivery count (or sets it
    with retrycount); the entries stay in the stream, so nothing
    is lost, but a claim on a stream that never expires leaves
    the moved entries pending there until XACK. With FORCE,
    entries in the stream but not pending are claimed too,
    creating new pending records — the audit cannot tell from the
    pending list alone whether such an id is in the stream, so it
    says so instead of guessing. A bare-millisecond id is
    normalised to its first sequence before comparing, as cinder
    reads it. Returns (verdict, line)."""
    (key, group, consumer, min_idle_ms, ids, idle_ms, time_ms,
     retrycount, force, justid) = _xclaim_args(op)
    if client.command("EXISTS", key) == 0:
        return "risky", (
            "kv_xclaim — %r would fail: no such key or consumer "
            "group %r" % (key, group)
        )
    ttl = client.command("TTL", key)
    if ttl == -2:
        # The key expired while auditing; the claim would fail.
        return "risky", (
            "kv_xclaim — %r would fail: no such key or consumer "
            "group %r" % (key, group)
        )
    try:
        kind, _size_value, size, _sample = _inspect_key(client, key)
    except ValueError:
        # The key expired between the TTL read and the probe.
        return "risky", (
            "kv_xclaim — %r would fail: no such key or consumer "
            "group %r" % (key, group)
        )
    if kind != "stream":
        return "risky", (
            "kv_xclaim — %r would fail with WRONGTYPE: the key is "
            "a %s of %s" % (key, kind, size)
        )
    try:
        total = client.command("XPENDING", key, group)[0]
    except RespError as exc:
        if "NOGROUP" in str(exc):
            return "risky", (
                "kv_xclaim — %r would fail: no such consumer group "
                "%r" % (key, group)
            )
        raise
    checked = min(total, MAX_XPENDING_ENTRIES)
    pending = (client.command("XPENDING", key, group, "-", "+", checked)
               if checked else [])
    pending_by_id = {entry[0]: entry for entry in pending}
    wanted = []
    for id_value in ids:
        normalised = _xack_normalised_id(id_value)
        if normalised not in wanted:
            wanted.append(normalised)
    claimable = []
    too_fresh = []
    forced = []
    left_out = []
    for normalised in wanted:
        entry = pending_by_id.get(normalised)
        if entry is not None:
            if force or entry[2] >= min_idle_ms:
                claimable.append(normalised)
            else:
                too_fresh.append(normalised)
        elif force:
            forced.append(normalised)
        else:
            left_out.append(normalised)
    if total > MAX_XPENDING_ENTRIES and (too_fresh or left_out):
        # Only the first 1000 pending entries were checked, so an
        # id outside them may still be pending — and idle enough.
        return "caution", (
            "kv_xclaim — moves %d pending %s to consumer %r in "
            "group %r on stream %r, but only the first %d of %d "
            "pending entries were checked, so the other %d %s may "
            "still be claimed"
            % (len(claimable), "entry" if len(claimable) == 1
               else "entries", consumer, group, key,
               MAX_XPENDING_ENTRIES, total,
               len(too_fresh) + len(left_out),
               "id" if len(too_fresh) + len(left_out) == 1 else "ids")
        )
    if not claimable and not forced:
        return "safe", (
            "kv_xclaim — no-op, none of the %d %s can be claimed "
            "by consumer %r in group %r on stream %r"
            % (len(wanted), "id" if len(wanted) == 1 else "ids",
               consumer, group, key)
        )
    retry = (" with the delivery count set to %d" % retrycount
             if retrycount is not None else "")
    parts = []
    if claimable:
        parts.append(
            "moves %d pending %s to consumer %r%s"
            % (len(claimable),
               "entry" if len(claimable) == 1 else "entries",
               consumer, retry)
        )
    if forced:
        parts.append(
            "claims %d %s not currently pending — only the ones "
            "in the stream — creating pending records for them"
            % (len(forced), "entry" if len(forced) == 1 else "entries")
        )
    if too_fresh:
        parts.append(
            "%d %s are not idle enough yet and stay where they are"
            % (len(too_fresh),
               "id" if len(too_fresh) == 1 else "ids")
        )
    if left_out:
        parts.append(
            "%d %s are not pending and stay out of the claim"
            % (len(left_out),
               "id" if len(left_out) == 1 else "ids")
        )
    line = ("kv_xclaim — %s in group %r on stream %r; the entries "
            "stay in the stream"
            % ("; ".join(parts), group, key))
    if ttl == -1:
        return "caution", (
            "%s, on a stream that never expires, where they stay "
            "pending until XACK" % line
        )
    return "safe", line


def _stream_id_parts(id_text):
    """One validated stream ID as an (ms, seq) pair for comparing
    IDs: "ms-seq" is exact, a bare millisecond is the first
    sequence of that millisecond, "-" is the first ID and "+" the
    last. "$" is not an ID — the caller resolves it to the
    stream's top ID first."""
    if id_text == "-":
        return 0, 0
    if id_text == "+":
        return 2 ** 64 - 1, 2 ** 64 - 1
    if "-" not in id_text:
        return int(id_text), 0
    ms_text, seq_text = id_text.split("-", 1)
    return int(ms_text), int(seq_text)


def _audit_xgroup_setid(client, op):
    """Audit one kv_xgroup_setid op: the stream and the group are
    probed live, and the stream's top ID is read with XREVRANGE
    so the move is judged against it — cinder exposes no way to
    read the group's current cursor, so the audit says what the
    next ">" read does from the new ID instead of whether the
    cursor moved. Moving back re-delivers the entries after the
    new ID, bumping their delivery counts and re-stamping their
    delivery times; moving to or past the top delivers nothing
    already in the stream. Either way the pending list is
    untouched by the move itself, and the entries stay in the
    stream either way. Returns (verdict, line)."""
    key, group, id_value = _xgroup_setid_args(op)
    if client.command("EXISTS", key) == 0:
        return "risky", (
            "kv_xgroup_setid — %r would fail: no such key or "
            "consumer group %r" % (key, group)
        )
    ttl = client.command("TTL", key)
    if ttl == -2:
        # The key expired while auditing; the setid would fail.
        return "risky", (
            "kv_xgroup_setid — %r would fail: no such key or "
            "consumer group %r" % (key, group)
        )
    try:
        kind, _size_value, size, _sample = _inspect_key(client, key)
    except ValueError:
        # The key expired between the TTL read and the probe.
        return "risky", (
            "kv_xgroup_setid — %r would fail: no such key or "
            "consumer group %r" % (key, group)
        )
    if kind != "stream":
        return "risky", (
            "kv_xgroup_setid — %r would fail with WRONGTYPE: the "
            "key is a %s of %s" % (key, kind, size)
        )
    try:
        client.command("XPENDING", key, group)
    except RespError as exc:
        if "NOGROUP" in str(exc):
            return "risky", (
                "kv_xgroup_setid — %r would fail: no such consumer "
                "group %r" % (key, group)
            )
        raise
    top_entries = client.command("XREVRANGE", key, "+", "-", "COUNT", 1)
    top = (_stream_id_parts(top_entries[0][0])
           if top_entries else (0, 0))
    target = top if id_value == "$" else _stream_id_parts(id_value)
    if target < top:
        return "caution", (
            "kv_xgroup_setid — moves consumer group %r on stream "
            "%r back to %r; the next '>' read delivers the entries "
            "after %r again, recording them in the pending list "
            "until XACK — the move itself leaves the pending list "
            "untouched%s"
            % (group, key, id_value, id_value,
               ", on a stream that never expires" if ttl == -1 else "")
        )
    if target > top:
        return "safe", (
            "kv_xgroup_setid — moves consumer group %r on stream "
            "%r past the top ID to %r; the next '>' read delivers "
            "only entries added after %r, and the entries already "
            "in the stream are never delivered as new entries — "
            "the pending list is untouched"
            % (group, key, id_value, id_value)
        )
    return "safe", (
        "kv_xgroup_setid — moves consumer group %r on stream %r "
        "to %r, the top ID; the next '>' read delivers only "
        "entries added after it, and the pending list is untouched"
        % (group, key, id_value)
    )


def _audit_lmove(client, op):
    """Audit one kv_lmove op: the source and the destination are
    both probed live, because the move reads the source, writes the
    destination, and deletes the source when its last element
    leaves. Cinder errors on a wrong-type destination before
    touching the source, and a missing source moves nothing, so
    both are checked in that order. Returns (verdict, line)."""
    source, destination, _from, _to = _lmove_audit_args(op)
    if client.command("EXISTS", source) == 0:
        return "safe", (
            "kv_lmove %r — no-op, the source key does not exist"
            % source
        )
    ttl = client.command("TTL", source)
    if ttl == -2:
        return "safe", (
            "kv_lmove %r — no-op, the source expired while auditing"
            % source
        )
    try:
        kind, size_value, size, _sample = _inspect_key(client, source)
    except ValueError:
        return "safe", (
            "kv_lmove %r — no-op, the source expired while auditing"
            % source
        )
    if kind != "list":
        return "risky", (
            "kv_lmove %r — would fail with WRONGTYPE: the source is "
            "a %s of %s" % (source, kind, size)
        )
    dest_exists = client.command("EXISTS", destination) != 0
    dest_text = "into %r" % destination
    if dest_exists:
        try:
            dest_kind, _dv, dest_size, _ds = _inspect_key(
                client, destination)
        except ValueError:
            # The destination expired while auditing; the move
            # creates it.
            dest_exists = False
            dest_text = "creating %r" % destination
        else:
            if dest_kind != "list":
                return "risky", (
                    "kv_lmove %r — would fail with WRONGTYPE: the "
                    "destination %r is a %s of %s"
                    % (source, destination, dest_kind, dest_size)
                )
    else:
        dest_text = "creating %r" % destination
    if source == destination:
        # A move within one key is a rotation: the element stays
        # in the same list, so nothing is added or removed.
        return "safe", (
            "kv_lmove %r — rotates one element within the list; "
            "nothing is added or removed" % source
        )
    if size_value <= 1:
        # The only element leaves: the source key is deleted.
        if ttl == -1:
            return "risky", (
                "kv_lmove %r — moves the only element out of a list "
                "that never expires, deleting the key" % source
            )
        return "caution", (
            "kv_lmove %r — moves the only element out, deleting the "
            "source key" % source
        )
    if ttl == -1:
        return "caution", (
            "kv_lmove %r — moves one element from a list of %s that "
            "never expires, %s" % (source, size, dest_text)
        )
    return "safe", (
        "kv_lmove %r — moves one element from a list of %s that %s, "
        "%s" % (source, size,
                "expires in %s" % _format_ttl(ttl), dest_text)
    )


def _audit_bitop(client, op):
    """Audit one kv_bitop op: the destination and every source are
    probed live, because the op reads the sources, overwrites the
    destination wholesale and clears its TTL — or deletes the
    destination when every source is missing. Cinder fails with
    WRONGTYPE on a container anywhere, destination or source, and
    a missing source counts as empty. Returns (verdict, line)."""
    operation, destination, sources = _bitop_audit_args(op)
    # Sources first: a container source fails before the
    # destination is touched.
    live = 0
    for source in sources:
        if client.command("EXISTS", source) == 0:
            continue
        try:
            kind, _sv, size, _sample = _inspect_key(client, source)
        except ValueError:
            # The source expired while auditing; it counts as
            # missing now.
            continue
        if kind != "string":
            return "risky", (
                "kv_bitop %r — would fail with WRONGTYPE: source "
                "%r is a %s of %s"
                % (destination, source, kind, size)
            )
        live += 1
    if live == 0:
        # Every source is missing: the result is empty and the
        # destination is deleted, as in Redis.
        if client.command("EXISTS", destination) == 0:
            return "safe", (
                "kv_bitop %r — no-op, every source is missing and "
                "there is no destination to delete" % destination
            )
        ttl = client.command("TTL", destination)
        if ttl == -2:
            return "safe", (
                "kv_bitop %r — no-op, the destination expired while "
                "auditing" % destination
            )
        try:
            kind, size_value, size, _sample = _inspect_key(
                client, destination)
        except ValueError:
            return "safe", (
                "kv_bitop %r — no-op, the destination expired while "
                "auditing" % destination
            )
        if kind != "string":
            return "risky", (
                "kv_bitop %r — would fail with WRONGTYPE: the "
                "destination is a %s of %s"
                % (destination, kind, size)
            )
        large = size_value >= HEALTH_BIG_STRING_BYTES
        flags = []
        if ttl == -1:
            flags.append("deletes a key that never expires")
        if large:
            flags.append("deletes a large key (%s)" % size)
        if flags:
            return "risky", "kv_bitop %r — %s" % (
                destination, "; ".join(flags))
        return "caution", (
            "kv_bitop %r — deletes a string of %s that %s, since "
            "every source is missing"
            % (destination, size,
               "expires in %s" % _format_ttl(ttl))
        )
    # At least one source lives: the destination is overwritten
    # wholesale and its TTL is cleared.
    if client.command("EXISTS", destination) == 0:
        return "caution", (
            "kv_bitop %r — creates a new key with no expiry from "
            "the %s of %d source(s)"
            % (destination, operation, live)
        )
    ttl = client.command("TTL", destination)
    if ttl == -2:
        return "caution", (
            "kv_bitop %r — creates a new key with no expiry from "
            "the %s of %d source(s)"
            % (destination, operation, live)
        )
    try:
        kind, size_value, size, _sample = _inspect_key(
            client, destination)
    except ValueError:
        return "caution", (
            "kv_bitop %r — creates a new key with no expiry from "
            "the %s of %d source(s)"
            % (destination, operation, live)
        )
    if kind != "string":
        return "risky", (
            "kv_bitop %r — would fail with WRONGTYPE: the "
            "destination is a %s of %s"
            % (destination, kind, size)
        )
    large = size_value >= HEALTH_BIG_STRING_BYTES
    flags = []
    if ttl == -1:
        flags.append("overwrites a key that never expires")
    if large:
        flags.append("overwrites a large key (%s)" % size)
    if flags:
        return "risky", "kv_bitop %r — %s; its TTL is cleared too" % (
            destination, "; ".join(flags))
    return "caution", (
        "kv_bitop %r — overwrites a string of %s that %s with the "
        "%s of %d source(s), clearing its TTL"
        % (destination, size,
           "expires in %s" % _format_ttl(ttl), operation, live)
    )


def _hll_estimate(client, key):
    """The PFCOUNT estimate for a key, or None when the key is not
    a HyperLogLog. PFCOUNT is the probe: it answers for a
    HyperLogLog and fails with WRONGTYPE for a plain string or a
    container. GET alone cannot tell them apart — a HyperLogLog
    reads back as a string value with an HLL1 header — so the
    audit asks PFCOUNT instead of trusting the GET type."""
    try:
        return client.command("PFCOUNT", key)
    except RespError:
        return None


def _audit_pfmerge(client, op):
    """Audit one kv_pfmerge op: the destination and every source
    are probed live, because the merge reads the sources,
    overwrites the destination wholesale and clears its TTL — or
    creates it when it does not exist. Cinder checks the
    destination first, then the sources in order, and a failed
    merge leaves the destination and its TTL untouched, so the
    audit follows that order. A missing source counts as empty;
    the destination may itself be a source, in which case its
    own registers are unioned in instead of discarded. Returns
    (verdict, line)."""
    destination, sources = _pfmerge_audit_args(op)
    dest_exists = client.command("EXISTS", destination) != 0
    dest_estimate = None
    dest_ttl = None
    if dest_exists:
        dest_ttl = client.command("TTL", destination)
        if dest_ttl == -2:
            # The destination expired while auditing; the merge
            # creates it.
            dest_exists = False
        else:
            try:
                kind, _sv, size, _sample = _inspect_key(
                    client, destination)
            except ValueError:
                # The destination expired between the TTL read and
                # the probe; the merge creates it.
                dest_exists = False
            else:
                if kind != "string":
                    return "risky", (
                        "kv_pfmerge %r — would fail with WRONGTYPE: "
                        "the destination is a %s of %s"
                        % (destination, kind, size)
                    )
                dest_estimate = _hll_estimate(client, destination)
                if dest_estimate is None:
                    return "risky", (
                        "kv_pfmerge %r — would fail with WRONGTYPE: "
                        "the destination is a plain string, not a "
                        "HyperLogLog" % destination
                    )
    # Sources next, in order: a bad source fails the merge before
    # the destination is touched, and sources are never modified.
    live = 0
    for source in sources:
        if source == destination and dest_exists:
            # Already probed as the destination: it is a
            # HyperLogLog, and it counts as a live source.
            live += 1
            continue
        if client.command("EXISTS", source) == 0:
            continue
        try:
            kind, _sv, size, _sample = _inspect_key(client, source)
        except ValueError:
            # The source expired while auditing; it counts as
            # missing now.
            continue
        if kind != "string":
            return "risky", (
                "kv_pfmerge %r — would fail with WRONGTYPE: source "
                "%r is a %s of %s"
                % (destination, source, kind, size)
            )
        if _hll_estimate(client, source) is None:
            return "risky", (
                "kv_pfmerge %r — would fail with WRONGTYPE: source "
                "%r is a plain string, not a HyperLogLog"
                % (destination, source)
            )
        live += 1
    if not dest_exists:
        return "caution", (
            "kv_pfmerge %r — creates a new HyperLogLog with no "
            "expiry from the union of %d source(s)"
            % (destination, live)
        )
    if destination in sources:
        # The destination's own registers are unioned in, so the
        # merge can only keep or grow its estimate — but it
        # clears the destination's TTL.
        if dest_ttl == -1:
            return "safe", (
                "kv_pfmerge %r — merges %d source(s) including "
                "itself; its estimate of %d stays or grows"
                % (destination, live, dest_estimate)
            )
        return "caution", (
            "kv_pfmerge %r — merges %d source(s) including itself; "
            "its estimate of %d stays or grows, but its expiry "
            "(currently %s) is cleared"
            % (destination, live, dest_estimate,
               _format_ttl(dest_ttl))
        )
    if dest_estimate > 0:
        # The merge overwrites the destination wholesale: its own
        # registers are discarded, not unioned in.
        if dest_ttl == -1:
            return "risky", (
                "kv_pfmerge %r — would discard the destination's "
                "registers, currently counting %d distinct "
                "element(s), from a HyperLogLog that never expires"
                % (destination, dest_estimate)
            )
        return "caution", (
            "kv_pfmerge %r — discards the destination's registers, "
            "currently counting %d distinct element(s), replacing "
            "them with the union of %d source(s); its expiry is "
            "cleared too"
            % (destination, dest_estimate, live)
        )
    if dest_ttl == -1:
        return "safe", (
            "kv_pfmerge %r — merges the union of %d source(s) into "
            "an empty HyperLogLog" % (destination, live)
        )
    return "caution", (
        "kv_pfmerge %r — merges the union of %d source(s) into an "
        "empty HyperLogLog, clearing its expiry (currently %s)"
        % (destination, live, _format_ttl(dest_ttl))
    )


def _zstore_audit_args(op, name):
    """The (destination, keys, weights, aggregate) for a
    kv_zunionstore / kv_zinterstore / kv_zdiffstore op in a write
    plan, validated like the tool's own arguments: the
    destination a string and the keys a non-empty list of
    strings, at most 1000; weights, when given, a list of numbers,
    one per key, with no NaN; aggregate, when given, "sum", "min"
    or "max" in any case, returned lowercased. kv_zdiffstore takes
    neither option, so passing either raises ValueError here
    instead of being silently ignored. Anything else raises
    ValueError, so the caller reports the op as not audited
    instead of guessing."""
    destination = op.get("destination")
    if not isinstance(destination, str):
        raise ValueError(
            "%s destination must be a string: %r"
            % (name, destination)
        )
    keys = op.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError(
            "%s keys must be a non-empty list: %r" % (name, keys)
        )
    if len(keys) > 1000:
        raise ValueError(
            "%s reads at most 1000 keys; narrow the list" % name
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError(
                "%s keys must be strings: %r" % (name, keys)
            )
    weights = op.get("weights")
    if weights is not None:
        if not isinstance(weights, list):
            raise ValueError(
                "%s weights must be a list: %r" % (name, weights)
            )
        if len(weights) != len(keys):
            raise ValueError(
                "%s weights must have one weight per key" % name
            )
        for weight in weights:
            if isinstance(weight, bool) or not isinstance(
                    weight, (int, float)):
                raise ValueError(
                    "%s weights must be numbers: %r"
                    % (name, weights)
                )
            if isinstance(weight, float) and weight != weight:
                raise ValueError(
                    "%s weights must not be NaN" % name
                )
    aggregate = op.get("aggregate")
    if aggregate is not None:
        if not isinstance(aggregate, str):
            raise ValueError(
                "%s aggregate must be a string: %r"
                % (name, aggregate)
            )
        if aggregate.lower() not in ("sum", "min", "max"):
            raise ValueError(
                "%s aggregate must be sum, min or max" % name
            )
        aggregate = aggregate.lower()
    if name == "kv_zdiffstore" and (weights is not None
                                    or aggregate is not None):
        raise ValueError(
            "%s takes no weights or aggregate: cinder's ZDIFFSTORE "
            "has no options" % name
        )
    return destination, keys, weights, aggregate


def _zstore_members(client, key):
    """The {member: score} of one sorted set, read live with
    ZRANGE WITHSCORES, for comparing a store's destination
    against the result it would hold."""
    flat = client.command("ZRANGE", key, 0, -1, "WITHSCORES") or []
    return {member: float(score)
            for member, score in zip(flat[0::2], flat[1::2])}


def _zstore_expected(client, name, keys, weights, aggregate):
    """The {member: score} a store would write, probed live with
    the matching read command (ZUNION / ZINTER / ZDIFF
    WITHSCORES, with the store's weights and aggregate where the
    read command takes them). ZUNION takes no WEIGHTS or
    AGGREGATE, so a weighted union is combined here in Python
    from each input's ZRANGE WITHSCORES instead, in the same
    order cinder combines them — keys in order, members in score
    order within a key — so the sums match exactly. Raises
    RespError when the probe fails, so the caller reports the op
    as would-fail rather than guessing."""
    if name == "kv_zunionstore" and (weights is not None
                                     or aggregate is not None):
        totals = {}
        for index, key in enumerate(keys):
            weight = weights[index] if weights is not None else 1.0
            for member, score in _zstore_members(client, key).items():
                value = weight * score
                if member in totals:
                    if aggregate == "min":
                        totals[member] = min(totals[member], value)
                    elif aggregate == "max":
                        totals[member] = max(totals[member], value)
                    else:
                        totals[member] += value
                else:
                    totals[member] = value
        return totals
    command = {"kv_zunionstore": "ZUNION",
               "kv_zinterstore": "ZINTER",
               "kv_zdiffstore": "ZDIFF"}[name]
    argv = [command, len(keys)] + list(keys)
    if weights is not None:
        argv.append("WEIGHTS")
        argv += [repr(weight) for weight in weights]
    if aggregate is not None:
        argv += ["AGGREGATE", aggregate.upper()]
    argv.append("WITHSCORES")
    flat = client.command(*argv) or []
    return {member: float(score)
            for member, score in zip(flat[0::2], flat[1::2])}


def _audit_zstore_empty(client, name, destination):
    """The verdicts when a store would store nothing — the result
    is empty, so the destination is deleted when it exists and
    nothing is written otherwise."""
    if client.command("EXISTS", destination) == 0:
        return "safe", (
            "%s %r — no-op: the result is empty and the "
            "destination is missing too" % (name, destination)
        )
    dest_ttl = client.command("TTL", destination)
    if dest_ttl == -2:
        return "safe", (
            "%s %r — no-op: the result is empty and the "
            "destination expired while auditing"
            % (name, destination)
        )
    try:
        kind, _sv, size, _sample = _inspect_key(
            client, destination)
    except ValueError:
        return "safe", (
            "%s %r — no-op: the result is empty and the "
            "destination expired while auditing"
            % (name, destination)
        )
    if dest_ttl == -1:
        return "risky", (
            "%s %r — stores nothing and deletes the destination, "
            "a %s of %s that never expires"
            % (name, destination, kind, size)
        )
    return "caution", (
        "%s %r — stores nothing and deletes the destination, a "
        "%s of %s that %s"
        % (name, destination, kind, size,
           "expires in %s" % _format_ttl(dest_ttl))
    )


def _audit_zstore(client, op):
    """Audit one kv_zunionstore / kv_zinterstore / kv_zdiffstore
    op: the inputs and the destination are probed live, because
    the store reads the inputs, overwrites the destination
    wholesale and clears its TTL — or creates it when it does
    not exist, or deletes it when the result is empty. Cinder
    checks every input key's type before any set is read, and a
    failed store leaves the destination and its TTL untouched, so
    the audit follows that order; a missing input counts as an
    empty set. The expected result is probed with the matching
    read command, so a store that would write exactly what the
    destination already holds is a safe no-op — cinder writes
    nothing then and keeps the TTL — and a store that only adds
    members to it loses nothing but the TTL. The destination may
    itself be an input key, in which case the result was computed
    from the pre-store sets and the members it leaves out are
    dropped. Returns (verdict, line)."""
    name = op.get("op")
    destination, keys, weights, aggregate = _zstore_audit_args(
        op, name)
    for key in keys:
        if client.command("EXISTS", key) == 0:
            continue
        try:
            kind, _sv, size, _sample = _inspect_key(client, key)
        except ValueError:
            # The input expired while auditing; it counts as
            # missing now.
            continue
        if kind != "zset":
            return "risky", (
                "%s %r — would fail with WRONGTYPE: input %r is "
                "a %s of %s"
                % (name, destination, key, kind, size)
            )
    try:
        expected = _zstore_expected(
            client, name, keys, weights, aggregate)
    except RespError as exc:
        return "risky", (
            "%s %r — would fail: %s" % (name, destination, exc))
    if not expected:
        return _audit_zstore_empty(client, name, destination)
    if client.command("EXISTS", destination) == 0:
        return "caution", (
            "%s %r — creates a new sorted set with no expiry "
            "holding %d member(s)"
            % (name, destination, len(expected))
        )
    dest_ttl = client.command("TTL", destination)
    if dest_ttl == -2:
        return "caution", (
            "%s %r — creates a new sorted set with no expiry "
            "holding %d member(s)"
            % (name, destination, len(expected))
        )
    try:
        dkind, _dsv, dsize, _ds = _inspect_key(client, destination)
    except ValueError:
        return "caution", (
            "%s %r — creates a new sorted set with no expiry "
            "holding %d member(s)"
            % (name, destination, len(expected))
        )
    if dkind == "zset":
        current = _zstore_members(client, destination)
        if current == expected:
            # Cinder writes nothing when the destination already
            # holds exactly the result, so its TTL is kept.
            return "safe", (
                "%s %r — no-op: the destination already holds the "
                "same %d member(s) with the same scores"
                % (name, destination, len(expected))
            )
        if set(current) <= set(expected) and all(
                current[member] == expected[member]
                for member in current):
            # Only additions: nothing is lost, only the TTL is
            # cleared by the rewrite.
            added = len(expected) - len(current)
            if dest_ttl == -1:
                return "safe", (
                    "%s %r — only adds %d member(s) to the "
                    "destination" % (name, destination, added)
                )
            return "caution", (
                "%s %r — only adds %d member(s) to the "
                "destination, but its expiry (currently %s) is "
                "cleared"
                % (name, destination, added,
                   _format_ttl(dest_ttl))
            )
        lost = [member for member in current
                if member not in expected]
        changed = [member for member in current
                   if member in expected
                   and current[member] != expected[member]]
        self_text = ""
        if destination in keys:
            self_text = (" (the destination is also an input key, "
                         "so the result was computed from the "
                         "pre-store sets)")
        if lost:
            if dest_ttl == -1:
                return "risky", (
                    "%s %r — would discard %d member(s) from the "
                    "destination, a sorted set of %s that never "
                    "expires, replacing it with %d member(s)%s"
                    % (name, destination, len(lost), dsize,
                       len(expected), self_text)
                )
            return "caution", (
                "%s %r — replaces the destination, a sorted set "
                "of %s that %s, with %d member(s), dropping %d "
                "member(s)%s; its expiry is cleared too"
                % (name, destination, dsize,
                   "expires in %s" % _format_ttl(dest_ttl),
                   len(expected), len(lost), self_text)
            )
        # No member is lost: only scores change (and members are
        # added), so the damage is bounded either way.
        if dest_ttl == -1:
            return "caution", (
                "%s %r — changes the scores of %d member(s) in "
                "the destination, a sorted set of %s that never "
                "expires, storing %d member(s)%s"
                % (name, destination, len(changed), dsize,
                   len(expected), self_text)
            )
        return "caution", (
            "%s %r — changes the scores of %d member(s) in the "
            "destination, a sorted set of %s that %s, storing %d "
            "member(s)%s; its expiry is cleared too"
            % (name, destination, len(changed), dsize,
               "expires in %s" % _format_ttl(dest_ttl),
               len(expected), self_text)
        )
    if dest_ttl == -1:
        return "risky", (
            "%s %r — would discard the destination, a %s of %s "
            "that never expires, replacing it with a sorted set "
            "of %d member(s)"
            % (name, destination, dkind, dsize, len(expected))
        )
    return "caution", (
        "%s %r — replaces the destination, a %s of %s that %s, "
        "with a sorted set of %d member(s); its expiry is "
        "cleared too"
        % (name, destination, dkind, dsize,
           "expires in %s" % _format_ttl(dest_ttl),
           len(expected))
    )


def _geo_audit_coordinate(value, axis, tool):
    """One GEORADIUS centre coordinate in a write plan: a finite
    number in the GEOADD range, not a boolean."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            "%s %s must be a number: %r" % (tool, axis, value))
    if not math.isfinite(value):
        raise ValueError(
            "%s %s must be finite: %r" % (tool, axis, value))
    low, high = (-180.0, 180.0) if axis == "longitude" \
        else (-85.05112878, 85.05112878)
    if value < low or value > high:
        raise ValueError(
            "%s %s must be between %s and %s: %r"
            % (tool, axis, low, high, value))
    return value


def _geo_audit_number(value, name, tool):
    """One GEORADIUS radius in a write plan: a finite number, 0 or
    more, and not a boolean."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(
            "%s %s must be a number: %r" % (tool, name, value))
    if not math.isfinite(value):
        raise ValueError(
            "%s %s must be finite: %r" % (tool, name, value))
    if value < 0:
        raise ValueError(
            "%s %s must be 0 or more: %r" % (tool, name, value))
    return value


def _geo_search_audit_options(op, tool):
    """The sort / count / any / with* options of a geo search op
    in a write plan, validated like the tool's own. Returns
    (sort_desc, count, count_any, withdist, withhash, withcoord)."""
    sort = op.get("sort", "asc")
    if not isinstance(sort, str) or sort.lower() not in ("asc", "desc"):
        raise ValueError(
            "%s sort must be \"asc\" or \"desc\": %r" % (tool, sort))
    count = op.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError(
                "%s count must be an integer: %r" % (tool, count))
        if count < 0:
            raise ValueError(
                "%s count must be 0 or more: %r" % (tool, count))
        if count > MAX_GEOSEARCH_MEMBERS:
            raise ValueError(
                "%s returns at most %d members; narrow the count"
                % (tool, MAX_GEOSEARCH_MEMBERS))
    any_ = op.get("any", False)
    if not isinstance(any_, bool):
        raise ValueError(
            "%s any must be true or false: %r" % (tool, any_))
    if any_ and count is None:
        raise ValueError("%s any needs a count" % tool)
    flags = []
    for flag in ("withdist", "withhash", "withcoord"):
        value = op.get(flag, False)
        if not isinstance(value, bool):
            raise ValueError(
                "%s %s must be true or false: %r" % (tool, flag, value))
        flags.append(value)
    return (sort.lower() == "desc", count, any_,
            flags[0], flags[1], flags[2])


def _georadius_audit_args(op):
    """The arguments of a kv_georadius / kv_georadiusbymember op
    in a write plan, validated like the tool's own: a key, a
    centre (longitude/latitude or a member name), a radius in a
    unit, the shared search options, and at most one of store /
    storedist. Returns (name, key, centre, radius, unit, options,
    store) where centre is ("lonlat", lon, lat) or ("member",
    name) and store is ("store", key), ("storedist", key) or
    None. A bad argument raises ValueError, so the op is skipped
    instead of being reported as a safe no-op."""
    name = op.get("op")
    tool = name
    key = op.get("key")
    if not isinstance(key, str):
        raise ValueError("%s key must be a string: %r" % (tool, key))
    if name == "kv_georadiusbymember":
        member = op.get("member")
        if not isinstance(member, str):
            raise ValueError(
                "%s member must be a string: %r" % (tool, member))
        centre = ("member", member)
    else:
        lon = op.get("longitude")
        lat = op.get("latitude")
        if lon is None or lat is None:
            raise ValueError(
                "%s needs both longitude and latitude: %r"
                % (tool, op))
        centre = ("lonlat",
                  _geo_audit_coordinate(lon, "longitude", tool),
                  _geo_audit_coordinate(lat, "latitude", tool))
    radius = op.get("radius")
    if radius is None:
        raise ValueError("%s needs a radius: %r" % (tool, op))
    radius = _geo_audit_number(radius, "radius", tool)
    unit = op.get("unit", "m")
    if not isinstance(unit, str) \
            or unit.lower() not in ("m", "km", "ft", "mi"):
        raise ValueError(
            "%s unit must be one of m, km, ft, mi: %r" % (tool, unit))
    options = _geo_search_audit_options(op, tool)
    _sort_desc, _count, _any, withdist, withhash, withcoord = options
    store = op.get("store")
    storedist = op.get("storedist")
    if store is not None and storedist is not None:
        raise ValueError(
            "%s takes either store or storedist, not both" % tool)
    dest = store if store is not None else storedist
    if dest is None:
        return name, key, centre, radius, unit.lower(), options, None
    if not isinstance(dest, str):
        raise ValueError(
            "%s store must be a string: %r" % (tool, dest))
    if withdist or withhash or withcoord:
        raise ValueError(
            "%s store cannot be combined with withdist, withhash "
            "or withcoord" % tool)
    return (name, key, centre, radius, unit.lower(), options,
            ("store" if store is not None else "storedist", dest))


def _georadius_audit_probe_argv(name, key, centre, radius, unit,
                                options):
    """The same search as the audited op, read-only: no STORE /
    STOREDIST, and a COUNT one past the tool's cap so the reply
    stays bounded however large the geo set is. The op's own
    COUNT still applies when it is smaller — the probe stores the
    same hits the op would."""
    sort_desc, count, count_any, _wd, _wh, _wc = options
    if name == "kv_georadiusbymember":
        argv = ["GEORADIUSBYMEMBER", key, centre[1],
                repr(radius), unit]
    else:
        argv = ["GEORADIUS", key, repr(centre[1]), repr(centre[2]),
                repr(radius), unit]
    argv.append("DESC" if sort_desc else "ASC")
    bound = MAX_GEOSEARCH_MEMBERS + 1
    if count is not None:
        bound = min(count, bound)
    argv += ["COUNT", bound]
    if count_any:
        argv.append("ANY")
    return argv


def _geo_hits_text(hits, exact):
    """The hit count of a storing GEORADIUS for an audit line:
    the exact count, or "at least 1001 members" when the probe
    hit its bound."""
    if exact:
        return "%d member(s)" % hits
    return "at least %d members" % (MAX_GEOSEARCH_MEMBERS + 1)


def _audit_georadius_empty(client, name, key, dest, why):
    """The verdicts when a storing GEORADIUS stores nothing — the
    source key does not exist, or no member is inside the shape:
    the destination is deleted when it exists, and nothing is
    written otherwise. `why` names the cause."""
    if client.command("EXISTS", dest) == 0:
        return "safe", (
            "%s %r — no-op: %s and the destination %r is missing "
            "too" % (name, key, why, dest)
        )
    dest_ttl = client.command("TTL", dest)
    if dest_ttl == -2:
        return "safe", (
            "%s %r — no-op: %s and the destination %r expired "
            "while auditing" % (name, key, why, dest)
        )
    try:
        kind, _sv, size, _sample = _inspect_key(client, dest)
    except ValueError:
        return "safe", (
            "%s %r — no-op: %s and the destination %r expired "
            "while auditing" % (name, key, why, dest)
        )
    if dest_ttl == -1:
        return "risky", (
            "%s %r — stores nothing and deletes the destination "
            "%r, a %s of %s that never expires"
            % (name, key, dest, kind, size)
        )
    return "caution", (
        "%s %r — stores nothing and deletes the destination %r, "
        "a %s of %s that %s"
        % (name, key, dest, kind, size,
           "expires in %s" % _format_ttl(dest_ttl))
    )


def _audit_georadius_self(name, key, source_ttl, size_value, size,
                          hits, exact, store_kind):
    """The verdicts when a storing GEORADIUS stores its hits back
    into the source key itself: the search ran first, so the hits
    are the members that survive — every member outside the shape
    is dropped — and the key's TTL is cleared with the overwrite.
    STOREDIST also replaces every member's geohash score with its
    distance, so the key stops being a geo set at all."""
    if store_kind == "storedist":
        dropped = ""
        if exact and hits < size_value:
            dropped = ("; %d member(s) outside the shape are dropped "
                       "too" % (size_value - hits))
        return "risky", (
            "%s %r — stores %s back into the source key itself "
            "with their distances as scores, so it stops being a "
            "geo set%s"
            % (name, key, _geo_hits_text(hits, exact), dropped)
        )
    if exact and hits == size_value:
        # Every member is inside the shape: the set is rewritten
        # with the same members and the same scores.
        if source_ttl == -1:
            return "safe", (
                "%s %r — stores its %s back into itself; every "
                "member is inside the shape, so nothing is dropped"
                % (name, key, _geo_hits_text(hits, exact))
            )
        return "caution", (
            "%s %r — stores its %s back into itself; every member "
            "is inside the shape, so nothing is dropped, but its "
            "expiry (currently %s) is cleared"
            % (name, key, _geo_hits_text(hits, exact),
               _format_ttl(source_ttl))
        )
    if not exact:
        if source_ttl == -1:
            return "caution", (
                "%s %r — stores %s back into itself; any member "
                "outside the shape is dropped"
                % (name, key, _geo_hits_text(hits, exact))
            )
        return "caution", (
            "%s %r — stores %s back into itself; any member "
            "outside the shape is dropped, and its expiry "
            "(currently %s) is cleared"
            % (name, key, _geo_hits_text(hits, exact),
               _format_ttl(source_ttl))
        )
    if source_ttl == -1:
        return "risky", (
            "%s %r — drops %d member(s) outside the shape from a "
            "geo set of %s that never expires"
            % (name, key, size_value - hits, size)
        )
    return "caution", (
        "%s %r — drops %d member(s) outside the shape from a geo "
        "set of %s that %s; its expiry is cleared too"
        % (name, key, size_value - hits, size,
           "expires in %s" % _format_ttl(source_ttl))
    )


def _audit_storing_geo_search(client, name, key, centre, probe_argv,
                              store_kind, dest, unit):
    """Audit one geo search that stores its hits: the source key
    and the destination are probed live. The search is run
    read-only first (`probe_argv`, the same centre and shape
    without STORE) to count the hits, then the destination is
    judged: the hits overwrite it whatever it held and clear its
    TTL, an empty result deletes it instead, and the destination
    may be the source key itself. Cinder checks the source
    first — a key that is not a sorted set fails before the
    destination is touched — and a FROMMEMBER / GEORADIUSBYMEMBER
    centre member with no position fails too, so the audit
    follows that order. `store_kind` is "store" (geohash scores)
    or "storedist" (distances in `unit` as scores). Returns
    (verdict, line)."""
    if client.command("EXISTS", key) == 0:
        return _audit_georadius_empty(
            client, name, key, dest, "the source key does not exist")
    source_ttl = client.command("TTL", key)
    if source_ttl == -2:
        return _audit_georadius_empty(
            client, name, key, dest, "the source key does not exist")
    try:
        kind, size_value, size, _sample = _inspect_key(client, key)
    except ValueError:
        return _audit_georadius_empty(
            client, name, key, dest, "the source key does not exist")
    if kind != "zset":
        return "risky", (
            "%s %r — would fail with WRONGTYPE: the key is a %s of "
            "%s" % (name, key, kind, size)
        )
    # The centre member of a FROMMEMBER / GEORADIUSBYMEMBER
    # search needs a position: a member that is not in the set,
    # or one whose score does not decode as a geohash, fails the
    # call.
    if centre[0] == "member":
        pos = client.command("GEOPOS", key, centre[1])
        if not pos or pos[0] is None:
            return "risky", (
                "%s %r — would fail: member %r has no position in "
                "the geo set" % (name, key, centre[1])
            )
    # Count the hits with a read-only run of the same search. A
    # probe failure is the op failing at runtime, so it is risky
    # rather than a skipped op.
    try:
        probe = client.command(*probe_argv)
    except RespError as exc:
        return "risky", (
            "%s %r — would fail: %s" % (name, key, exc))
    hits = len(probe or [])
    exact = hits <= MAX_GEOSEARCH_MEMBERS
    if store_kind == "storedist":
        score_text = "their distances in %s as scores" % unit
    else:
        score_text = "their geohash scores"
    if hits == 0:
        return _audit_georadius_empty(
            client, name, key, dest, "no member is inside the shape")
    if dest == key:
        return _audit_georadius_self(
            name, key, source_ttl, size_value, size, hits, exact,
            store_kind)
    if client.command("EXISTS", dest) == 0:
        return "caution", (
            "%s %r — creates a new sorted set with no expiry "
            "holding %s with %s"
            % (name, dest, _geo_hits_text(hits, exact), score_text)
        )
    dest_ttl = client.command("TTL", dest)
    if dest_ttl == -2:
        return "caution", (
            "%s %r — creates a new sorted set with no expiry "
            "holding %s with %s"
            % (name, dest, _geo_hits_text(hits, exact), score_text)
        )
    try:
        dkind, dsize_value, dsize, _ds = _inspect_key(client, dest)
    except ValueError:
        return "caution", (
            "%s %r — creates a new sorted set with no expiry "
            "holding %s with %s"
            % (name, dest, _geo_hits_text(hits, exact), score_text)
        )
    if dkind == "zset" and dsize_value == 0:
        # An empty destination: nothing is discarded, only its
        # expiry is cleared.
        if dest_ttl == -1:
            return "safe", (
                "%s %r — stores %s with %s into an empty sorted "
                "set" % (name, dest, _geo_hits_text(hits, exact),
                         score_text)
            )
        return "caution", (
            "%s %r — stores %s with %s into an empty sorted set, "
            "clearing its expiry (currently %s)"
            % (name, dest, _geo_hits_text(hits, exact), score_text,
               _format_ttl(dest_ttl))
        )
    if dest_ttl == -1:
        return "risky", (
            "%s %r — would discard the destination %r, a %s of %s "
            "that never expires, replacing it with %s with %s"
            % (name, key, dest, dkind, dsize,
               _geo_hits_text(hits, exact), score_text)
        )
    return "caution", (
        "%s %r — replaces the destination %r, a %s of %s that %s, "
        "with %s with %s; its expiry is cleared too"
        % (name, key, dest, dkind, dsize,
           "expires in %s" % _format_ttl(dest_ttl),
           _geo_hits_text(hits, exact), score_text)
    )


def _audit_georadius(client, op):
    """Audit one kv_georadius / kv_georadiusbymember op: the source
    key and, when the op stores its hits, the destination are
    probed live. A plain search writes nothing, so it is safe. A
    storing search is audited by _audit_storing_geo_search.
    Returns (verdict, line)."""
    name, key, centre, radius, unit, options, store = \
        _georadius_audit_args(op)
    if store is None:
        return "safe", (
            "%s %r — read-only: no STORE or STOREDIST, nothing is "
            "written" % (name, key)
        )
    store_kind, dest = store
    return _audit_storing_geo_search(
        client, name, key, centre,
        _georadius_audit_probe_argv(
            name, key, centre, radius, unit, options),
        store_kind, dest, unit)


def _geosearch_audit_args(op):
    """The arguments of a kv_geosearchstore op in a write plan,
    validated like the tool's own: a destination, a source key, a
    centre (a member name or longitude/latitude), a shape (a
    radius or a width/height) in a unit, the shared search
    options, and `storedist`. Returns (name, destination, key,
    centre, shape, options, storedist) where centre is
    ("member", name) or ("lonlat", lon, lat) and shape is
    ("radius", radius, unit) or ("box", width, height, unit). A
    bad argument raises ValueError, so the op is skipped instead
    of being reported as a safe no-op."""
    name = "kv_geosearchstore"
    destination = op.get("destination")
    if not isinstance(destination, str):
        raise ValueError(
            "%s destination must be a string: %r"
            % (name, destination))
    key = op.get("key")
    if not isinstance(key, str):
        raise ValueError("%s key must be a string: %r" % (name, key))
    member = op.get("member")
    has_lonlat = "longitude" in op or "latitude" in op
    if member is not None and has_lonlat:
        raise ValueError(
            "%s takes either member or longitude/latitude, not "
            "both" % name)
    if member is None and not has_lonlat:
        raise ValueError(
            "%s needs a centre: member or longitude/latitude"
            % name)
    if member is not None:
        if not isinstance(member, str):
            raise ValueError(
                "%s member must be a string: %r" % (name, member))
        centre = ("member", member)
    else:
        lon = op.get("longitude")
        lat = op.get("latitude")
        if lon is None or lat is None:
            raise ValueError(
                "%s needs both longitude and latitude: %r"
                % (name, op))
        centre = ("lonlat",
                  _geo_audit_coordinate(lon, "longitude", name),
                  _geo_audit_coordinate(lat, "latitude", name))
    radius = op.get("radius")
    has_box = "width" in op or "height" in op
    if radius is not None and has_box:
        raise ValueError(
            "%s takes either radius or width/height, not both"
            % name)
    if radius is None and not has_box:
        raise ValueError(
            "%s needs a shape: radius or width/height" % name)
    unit = op.get("unit", "m")
    if not isinstance(unit, str) \
            or unit.lower() not in ("m", "km", "ft", "mi"):
        raise ValueError(
            "%s unit must be one of m, km, ft, mi: %r"
            % (name, unit))
    unit = unit.lower()
    if radius is not None:
        shape = ("radius",
                 _geo_audit_number(radius, "radius", name), unit)
    else:
        width = op.get("width")
        height = op.get("height")
        if width is None or height is None:
            raise ValueError(
                "%s needs both width and height: %r" % (name, op))
        shape = ("box",
                 _geo_audit_number(width, "width", name),
                 _geo_audit_number(height, "height", name),
                 unit)
    options = _geo_search_audit_options(op, name)
    _sort_desc, _count, _any, withdist, withhash, withcoord = options
    if withdist or withhash or withcoord:
        raise ValueError(
            "%s cannot be combined with withdist, withhash or "
            "withcoord" % name)
    storedist = op.get("storedist", False)
    if not isinstance(storedist, bool):
        raise ValueError(
            "%s storedist must be true or false: %r"
            % (name, storedist))
    return (name, destination, key, centre, shape, options,
            storedist)


def _geosearch_audit_probe_argv(key, centre, shape, options):
    """The same search as the audited GEOSEARCHSTORE op, read-only:
    a GEOSEARCH with the same centre and shape, no STOREDIST,
    and a COUNT one past the tool's cap so the reply stays
    bounded however large the geo set is. The op's own COUNT
    still applies when it is smaller — the probe stores the same
    hits the op would."""
    sort_desc, count, count_any, _wd, _wh, _wc = options
    argv = ["GEOSEARCH", key]
    if centre[0] == "member":
        argv += ["FROMMEMBER", centre[1]]
    else:
        argv += ["FROMLONLAT", repr(centre[1]), repr(centre[2])]
    if shape[0] == "radius":
        argv += ["BYRADIUS", repr(shape[1]), shape[2]]
    else:
        argv += ["BYBOX", repr(shape[1]), repr(shape[2]), shape[3]]
    argv.append("DESC" if sort_desc else "ASC")
    bound = MAX_GEOSEARCH_MEMBERS + 1
    if count is not None:
        bound = min(count, bound)
    argv += ["COUNT", bound]
    if count_any:
        argv.append("ANY")
    return argv


def _audit_geosearchstore(client, op):
    """Audit one kv_geosearchstore op: GEOSEARCHSTORE always
    stores its hits, so it is always a write, audited by
    _audit_storing_geo_search with a read-only GEOSEARCH probe
    of the same centre and shape. Returns (verdict, line)."""
    name, destination, key, centre, shape, options, storedist = \
        _geosearch_audit_args(op)
    unit = shape[2] if shape[0] == "radius" else shape[3]
    return _audit_storing_geo_search(
        client, name, key, centre,
        _geosearch_audit_probe_argv(key, centre, shape, options),
        "storedist" if storedist else "store", destination, unit)


def _zremrangebyscore_audit_bounds(op):
    """The min/max bounds for a kv_zremrangebyscore op in a write
    plan, as RESP arguments, validated like the tool's own: numbers
    or strings with an optional leading '(' for exclusivity,
    -inf/+inf by default. NaN and anything unparsable raises
    ValueError, so a bad bound fails the audit instead of being
    reported as a safe no-op."""
    name = "kv_zremrangebyscore"
    bounds = []
    for arg, default in (("min", "-inf"), ("max", "+inf")):
        value = op.get(arg, default)
        if isinstance(value, bool):
            raise ValueError(
                "%s %s must be a number or a string: %r"
                % (name, arg, value)
            )
        if isinstance(value, (int, float)):
            if isinstance(value, float) and value != value:
                raise ValueError(
                    "%s bounds must not be NaN" % name
                )
            bounds.append(repr(value))
            continue
        if isinstance(value, str):
            text = value[1:] if value.startswith("(") else value
            if not text:
                raise ValueError(
                    "%s bound %r is not a valid score" % (name, value)
                )
            try:
                parsed = float(text)
            except ValueError:
                raise ValueError(
                    "%s bound %r is not a valid score" % (name, value)
                )
            if parsed != parsed:
                raise ValueError(
                    "%s bounds must not be NaN" % name
                )
            bounds.append(value)
            continue
        raise ValueError(
            "%s %s must be a number or a string: %r"
            % (name, arg, value)
        )
    return bounds[0], bounds[1]


def _zremrangebyrank_audit_ranks(op):
    """The start/stop ranks for a kv_zremrangebyrank op in a write
    plan, validated like the tool's own: integers, 0 and -1 by
    default. Anything else raises ValueError."""
    name = "kv_zremrangebyrank"
    ranks = []
    for arg, default in (("start", 0), ("stop", -1)):
        value = op.get(arg, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                "%s %s must be an integer: %r" % (name, arg, value)
            )
        ranks.append(value)
    return ranks[0], ranks[1]


def _zremrangebylex_audit_bounds(op):
    """The min/max bounds for a kv_zremrangebylex op in a write
    plan, validated like the tool's own: "-" / "+" or "[x" / "(x",
    defaulting to "-" / "+". A bare member, the wrong infinity,
    an empty bracket, or anything that is not a string raises
    ValueError, so a bad bound fails the audit instead of being
    reported as a safe no-op."""
    name = "kv_zremrangebylex"
    bounds = []
    for arg, default in (("min", "-"), ("max", "+")):
        value = op.get(arg, default)
        if not isinstance(value, str):
            raise ValueError(
                "%s %s bound must be a string: %r" % (name, arg, value)
            )
        if value == "-":
            if arg != "min":
                raise ValueError(
                    "%s max bound must not be \"-\"" % name
                )
        elif value == "+":
            if arg != "max":
                raise ValueError(
                    "%s min bound must not be \"+\"" % name
                )
        elif not (value.startswith(("[", "(")) and len(value) > 1):
            raise ValueError(
                "%s %s bound %r is not a valid lex bound: use \"-\", "
                "\"+\", \"[member\" or \"(member\""
                % (name, arg, value)
            )
        bounds.append(value)
    return bounds[0], bounds[1]


def _zremrange_window(start, stop, length):
    """How many members a [start, stop] rank range covers in a
    sorted set of `length` members, resolving negative indices
    the way Redis does: -1 is the last member, out-of-range ends
    clamped. Returns 0 for an empty range."""
    if start < 0:
        start += length
    if stop < 0:
        stop += length
    if start < 0:
        start = 0
    if stop >= length:
        stop = length - 1
    if start > stop or start >= length:
        return 0
    return stop - start + 1


def _audit_write_op(client, op):
    """Audit one write op from a write plan against the live
    keyspace. Returns (verdict, line) where verdict is "safe",
    "caution", or "risky", and line is the one-line rendering for
    the prompt text. Raises ValueError when the op is not a write
    op at all, is missing its key, or has a malformed argument, so
    the caller can report it as not audited instead of guessing.
    The op's value is never printed: values can be large or hold
    secrets, and the audit is about the key, not its new value.
    Verdicts: "risky" destroys data that is hard to get back or
    would fail outright — overwriting or deleting a key that never
    expires, overwriting or deleting a large key, a SET, MSET,
    SETEX or GETSET that would replace a list, set, or hash with a
    string, a GETDEL on a container, an INCR or DECR on
    a non-integer or a container, a HINCRBY on a non-integer field
    or a container, a HINCRBYFLOAT on a non-float field or a
    container, a HSETNX on a container, an APPEND or SETRANGE on a
    container, a SETRANGE with a negative offset, a SETBIT on a
    container or with an offset out of range, a BITOP on a
    container source or destination, a BITFIELD on a container or
    with a bad offset or a bad value, a GETEX or ZPOP
    on a container, an LSET or LINSERT
    on a container, an LSET on a missing key or with an index out
    of range, an LPUSHX or RPUSHX on a container, an LTRIM that
    would delete a never-expiring or large list outright, an
    LMOVE out of a container, into a container, or that would
    delete a never-expiring source by taking its only element,
    a ZPOP that would drain a never-expiring or large
    sorted set, a PFMERGE that would discard a never-expiring
    destination's registers, an XADD with a MAXLEN that would trim
    entries off a never-expiring stream, or a MAXLEN 0 that would
    delete a stream outright, an XREADGROUP on a missing key or a
    missing group, an XGROUP CREATE on a missing key or a group
    that already exists, an XACK on a missing key or group, or an
    XCLAIM on a missing key or group, or an EXPIRE,
    SETEX or GETEX with a bad timeout. "caution" changes
    something but the damage is bounded — an overwrite or delete
    of a key that expires soon anyway, a SET, MSET, SETNX, APPEND,
    SETRANGE or GETSET that creates a key with no expiry, a PFADD
    or PFMERGE that creates a HyperLogLog with no expiry, a
    PFMERGE that discards an expiring destination's registers or
    clears its expiry, an XADD that creates a stream with no
    expiry, appends to a stream that never expires, or trims
    entries off a stream that expires soon, an XREADGROUP that
    delivers new entries into a group's pending list, an XGROUP
    CREATE that creates a group on a stream that never expires or
    a new stream with no expiry, an XACK whose pending list is
    wider than the audit can read, an XCLAIM that moves pending
    entries to another consumer on a stream that never expires, or
    whose pending list is wider than the audit can read, a HSETNX
    that creates a hash with no expiry or adds a field to a hash
    that never expires, a GETEX that gives a never-expiring key
    an expiry or removes one, a ZPOP that takes some but not all
    members, a ZREMRANGEBYSCORE, ZREMRANGEBYRANK or ZREMRANGEBYLEX that removes
    some but not all members, an LSET that replaces one element
    of a list, or an
    LINSERT that adds one element to a list, an LPUSHX or RPUSHX
    that adds elements to a list that never expires, an LTRIM
    that shortens a list that never expires or deletes a list
    that expires soon, a SETRANGE that overwrites part of a large
    string, or an LMOVE that moves one element out of a list with
    more to spare or empties a source that expires soon, a GEOADD
    that creates a geo set with no expiry or moves members of an
    existing one (NX never moves a member, so it only adds; XX
    never creates a key or adds a member, so it is a no-op on a
    missing key or when none of its members are already in the
    set). SETNX on
    a key that
    already exists writes nothing, so it is safe, and so is HSETNX
    on a field that already exists, an LSET that writes the value
    the element already holds, and an LINSERT whose pivot is not
    in the list. Everything else is "safe": creating an expiring key,
    INCR or DECR on a missing key, HINCRBY on a missing key or a
    missing field, HINCRBYFLOAT on a missing key or a missing
    field, an EXPIRE on an existing key, a GETEX that
    only reads a value, an LPUSHX, RPUSHX, or LTRIM on a missing
    key, an LMOVE out of a missing key or within one key, a
    SETRANGE that overwrites part of a string or writes an empty
    value, a SETBIT that flips one bit of a string or finds the
    bit already set, a BITFIELD that changes fields of a string
    in place or reads fields and changes nothing, a BITOP over missing sources with no
    destination to delete, or a no-op on a missing key.
    kv_mset has no single key — it writes several at once — so it
    is audited by _audit_mset instead of the single-key flow below.
    kv_lmove has two keys — a source and a destination — so it is
    audited by _audit_lmove instead. kv_bitop writes a destination
    from several sources, so it is audited by _audit_bitop
    instead. kv_pfmerge writes a destination from several sources,
    so it is audited by _audit_pfmerge instead. kv_zunionstore,
    kv_zinterstore and kv_zdiffstore write a destination from
    several sources, so they are audited by _audit_zstore instead.
    """
    name = op.get("op")
    if name not in WRITE_SAFETY_WRITE_OPS:
        raise ValueError("not a write op: %s" % name)
    if name == "kv_mset":
        # MSET writes several keys at once and has no single key.
        return _audit_mset(client, op)
    if name == "kv_lmove":
        # LMOVE writes two keys at once — a source and a
        # destination — so it is audited on its own.
        return _audit_lmove(client, op)
    if name == "kv_bitop":
        # BITOP writes a destination from several sources, so it
        # is audited on its own.
        return _audit_bitop(client, op)
    if name == "kv_pfmerge":
        # PFMERGE writes a destination from several sources, so it
        # is audited on its own.
        return _audit_pfmerge(client, op)
    if name in ("kv_georadius", "kv_georadiusbymember"):
        # GEORADIUS writes a destination from a source search, so
        # it is audited on its own — a plain search with no STORE
        # / STOREDIST is a read, and _audit_georadius says so.
        return _audit_georadius(client, op)
    if name == "kv_geosearchstore":
        # GEOSEARCHSTORE always stores its hits at a destination,
        # so it is audited on its own too.
        return _audit_geosearchstore(client, op)
    if name in ("kv_zunionstore", "kv_zinterstore", "kv_zdiffstore"):
        # A sorted-set store writes a destination from several
        # sources, so it is audited on its own.
        return _audit_zstore(client, op)
    if name == "kv_xreadgroup":
        # XREADGROUP reads several streams at once — a group and a
        # consumer per call, not one key — so it is audited on its
        # own.
        return _audit_xreadgroup(client, op)
    if name == "kv_xgroup_create":
        # XGROUP CREATE makes a group on one stream, and may
        # create the stream itself with MKSTREAM, so it is audited
        # on its own.
        return _audit_xgroup_create(client, op)
    if name == "kv_xack":
        # XACK drops entries from one group's pending list, so it
        # is audited on its own.
        return _audit_xack(client, op)
    if name == "kv_xclaim":
        # XCLAIM moves pending entries of one group's pending list
        # to another consumer, so it is audited on its own.
        return _audit_xclaim(client, op)
    if name == "kv_xgroup_setid":
        # XGROUP SETID moves one group's last-delivered ID, so it
        # is audited on its own.
        return _audit_xgroup_setid(client, op)
    key = op.get("key")
    if not key:
        raise ValueError("op is missing a key: %r" % (op,))
    if client.command("EXISTS", key) == 0:
        if name == "kv_set":
            ttl_arg = op.get("ex", op.get("px"))
            if ttl_arg is not None and not _is_int(ttl_arg):
                return "risky", (
                    "kv_set %r — would fail: bad TTL %r (not an integer)"
                    % (key, ttl_arg)
                )
            if op.get("ex") is not None or op.get("px") is not None:
                return "safe", (
                    "kv_set %r — creates a new key expiring in %s"
                    % (key, _format_ttl(int(op["ex"])) if op.get("ex") is not None
                       else "%dms" % int(op["px"]))
                )
            return "caution", (
                "kv_set %r — creates a new key with no expiry"
                % key
            )
        if name == "kv_del":
            return "safe", "kv_del %r — no-op, the key does not exist" % key
        if name == "kv_incr":
            by = op.get("by", 1)
            if not _is_int(by):
                raise ValueError("kv_incr by is not an integer: %r" % (by,))
            return "safe", (
                "kv_incr %r — creates a counter starting at %s"
                % (key, by)
            )
        if name == "kv_append":
            if not isinstance(op.get("value"), str):
                raise ValueError(
                    "kv_append value must be a string: %r"
                    % (op.get("value"),)
                )
            return "caution", (
                "kv_append %r — creates a new string key with no expiry"
                % key
            )
        if name == "kv_pfadd":
            _pfadd_audit_elements(op)
            return "caution", (
                "kv_pfadd %r — creates a new HyperLogLog with no "
                "expiry" % key
            )
        if name == "kv_geoadd":
            _geoadd_audit_members(op)
            nx, xx, _ch = _geoadd_audit_options(op)
            if xx:
                # GEOADD XX on a missing key adds nothing and
                # creates nothing: only members already in the
                # set are updated, and there is no set.
                return "safe", (
                    "kv_geoadd %r — no-op, xx only updates members "
                    "already in the set and the key does not exist"
                    % key
                )
            return "caution", (
                "kv_geoadd %r — creates a new geo sorted set with no "
                "expiry" % key
            )
        if name == "kv_xadd":
            # XADD on a missing key creates a stream — unless
            # MAXLEN 0 trims the entry at once, in which case
            # nothing persists and no key is left behind.
            _key, _id, _fields, maxlen, _approx = _xadd_args(op)
            if maxlen == 0:
                return "safe", (
                    "kv_xadd %r — no-op, MAXLEN 0 trims the entry "
                    "at once" % key
                )
            return "caution", (
                "kv_xadd %r — creates a new stream with no expiry"
                % key
            )
        if name in ("kv_decr", "kv_decrby"):
            if name == "kv_decrby" and "by" not in op:
                raise ValueError("kv_decrby is missing by: %r" % (op,))
            by = op.get("by", 1)
            if not _is_int(by):
                raise ValueError(
                    "%s by is not an integer: %r" % (name, by)
                )
            return "safe", (
                "%s %r — creates a counter starting at %d"
                % (name, key, -int(by))
            )
        if name == "kv_getex":
            ex, px, _persist = _getex_option(op)
            ttl_arg = ex if ex is not None else px
            if ttl_arg is not None and (
                not _is_int(ttl_arg) or int(ttl_arg) <= 0
            ):
                return "risky", (
                    "kv_getex %r — would fail: invalid expire time %r"
                    % (key, ttl_arg)
                )
            return "safe", (
                "kv_getex %r — no-op, the key does not exist" % key
            )
        if name == "kv_setnx":
            if not isinstance(op.get("value"), str):
                raise ValueError(
                    "kv_setnx value must be a string: %r"
                    % (op.get("value"),)
                )
            return "caution", (
                "kv_setnx %r — creates a new key with no expiry" % key
            )
        if name == "kv_setex":
            seconds = op.get("seconds")
            if seconds is None:
                raise ValueError("kv_setex is missing seconds: %r" % (op,))
            if not isinstance(op.get("value"), str):
                raise ValueError(
                    "kv_setex value must be a string: %r"
                    % (op.get("value"),)
                )
            if not _is_int(seconds) or int(seconds) <= 0:
                return "risky", (
                    "kv_setex %r — would fail: invalid expire time %r"
                    % (key, seconds)
                )
            return "safe", (
                "kv_setex %r — creates a new key expiring in %s"
                % (key, _format_ttl(int(seconds)))
            )
        if name == "kv_getset":
            if not isinstance(op.get("value"), str):
                raise ValueError(
                    "kv_getset value must be a string: %r"
                    % (op.get("value"),)
                )
            return "caution", (
                "kv_getset %r — creates a new key with no expiry" % key
            )
        if name == "kv_setrange":
            # SETRANGE on a missing key creates it zero-padded to
            # the offset, as in Redis — unless the value is empty,
            # which changes nothing and creates nothing.
            offset, value = _setrange_audit_args(op)
            if offset < 0:
                return "risky", (
                    "kv_setrange %r — would fail: offset is out of "
                    "range" % key
                )
            if value == "":
                return "safe", (
                    "kv_setrange %r — no-op, an empty value creates "
                    "nothing" % key
                )
            if offset > 0:
                return "caution", (
                    "kv_setrange %r — creates a new string key with "
                    "no expiry, zero-padded to offset %d"
                    % (key, offset)
                )
            return "caution", (
                "kv_setrange %r — creates a new string key with no "
                "expiry" % key
            )
        if name == "kv_setbit":
            # SETBIT on a missing key creates it zero-padded to
            # the byte holding the offset, as in Redis — even
            # when the bit being set is 0, the key comes into
            # being.
            offset, bit = _setbit_audit_args(op)
            if offset < 0 or offset > 4294967295:
                return "risky", (
                    "kv_setbit %r — would fail: offset is out of "
                    "range" % key
                )
            if bit not in (0, 1):
                return "risky", (
                    "kv_setbit %r — would fail: bit must be 0 or 1"
                    % key
                )
            return "caution", (
                "kv_setbit %r — creates a new string key with no "
                "expiry, zero-padded to %d byte(s)"
                % (key, offset // 8 + 1)
            )
        if name == "kv_bitfield":
            # BITFIELD on a missing key: a GET-only call reads 0
            # and creates nothing, as in Redis — any SET / INCRBY
            # creates the key zero-padded to the farthest field,
            # even one that then answers nil under OVERFLOW FAIL.
            parsed = _bitfield_audit_args(op)
            problem = _bitfield_audit_problem(parsed)
            if problem:
                return "risky", (
                    "kv_bitfield %r — would fail: %s" % (key, problem)
                )
            writes = [p for p in parsed if p[0] in ("set", "incrby")]
            if not writes:
                return "safe", (
                    "kv_bitfield %r — no-op, a GET-only call reads 0 "
                    "and creates nothing" % key
                )
            end = max(p[2] + p[1] for p in writes)
            return "caution", (
                "kv_bitfield %r — creates a new string key with no "
                "expiry, zero-padded to %d byte(s)"
                % (key, (end + 7) // 8)
            )
        if name == "kv_getdel":
            return "safe", (
                "kv_getdel %r — no-op, the key does not exist" % key
            )
        if name == "kv_hsetnx":
            if not isinstance(op.get("field"), str):
                raise ValueError(
                    "kv_hsetnx field must be a string: %r"
                    % (op.get("field"),)
                )
            if not isinstance(op.get("value"), str):
                raise ValueError(
                    "kv_hsetnx value must be a string: %r"
                    % (op.get("value"),)
                )
            return "caution", (
                "kv_hsetnx %r — creates a new hash with no expiry"
                % key
            )
        if name == "kv_hincrby":
            increment = _hincrby_audit_increment(op)
            if not isinstance(op.get("field"), str):
                raise ValueError(
                    "kv_hincrby field must be a string: %r"
                    % (op.get("field"),)
                )
            return "safe", (
                "kv_hincrby %r — creates a counter field starting at %d"
                % (key, int(increment))
            )
        if name == "kv_hincrbyfloat":
            increment = _hincrbyfloat_audit_increment(op)
            if not isinstance(op.get("field"), str):
                raise ValueError(
                    "kv_hincrbyfloat field must be a string: %r"
                    % (op.get("field"),)
                )
            return "safe", (
                "kv_hincrbyfloat %r — creates a float field starting "
                "at %r" % (key, increment)
            )
        if name in ("kv_zpopmin", "kv_zpopmax"):
            count = op.get("count", 1)
            if not _is_int(count) or int(count) < 1:
                raise ValueError(
                    "%s count is not a positive integer: %r" % (name, count)
                )
            return "safe", (
                "%s %r — no-op, the key does not exist" % (name, key)
            )
        if name == "kv_zremrangebyscore":
            # A bad bound fails the audit instead of being
            # reported as a safe no-op on a missing key.
            _zremrangebyscore_audit_bounds(op)
            return "safe", (
                "kv_zremrangebyscore %r — no-op, the key does not exist"
                % key
            )
        if name == "kv_zremrangebyrank":
            _zremrangebyrank_audit_ranks(op)
            return "safe", (
                "kv_zremrangebyrank %r — no-op, the key does not exist"
                % key
            )
        if name == "kv_zremrangebylex":
            # A bad bound fails the audit instead of being
            # reported as a safe no-op on a missing key.
            _zremrangebylex_audit_bounds(op)
            return "safe", (
                "kv_zremrangebylex %r — no-op, the key does not exist"
                % key
            )
        if name == "kv_lset":
            # LSET on a missing key fails outright in cinder.
            _lset_audit_args(op)
            return "risky", (
                "kv_lset %r — would fail: no such key" % key
            )
        if name == "kv_linsert":
            # LINSERT on a missing key answers -1 and changes
            # nothing, as in Redis.
            _linsert_audit_args(op)
            return "safe", (
                "kv_linsert %r — no-op, the key does not exist" % key
            )
        if name in ("kv_lpushx", "kv_rpushx"):
            # LPUSHX/RPUSHX on a missing key answers 0 and never
            # creates the list, as in Redis.
            _lpushx_audit_elements(op)
            return "safe", (
                "%s %r — no-op, the key does not exist" % (name, key)
            )
        if name == "kv_ltrim":
            # LTRIM on a missing key answers OK and changes
            # nothing, as in Redis.
            _ltrim_audit_args(op)
            return "safe", (
                "kv_ltrim %r — no-op, the key does not exist" % key
            )
        if name in ("kv_hexpire", "kv_hpexpire", "kv_hexpireat",
                    "kv_hpexpireat", "kv_hpersist"):
            # A hash-field TTL op on a missing key answers -2 per
            # field and changes nothing, as in Redis — but the
            # arguments still have to parse.
            _hexpire_audit_args(op)
            return "safe", (
                "%s %r — no-op, the key does not exist" % (name, key)
            )
        # kv_expire on a missing key.
        seconds = op.get("seconds")
        if seconds is None:
            raise ValueError("kv_expire is missing seconds: %r" % (op,))
        if not _is_int(seconds) or int(seconds) < 0:
            return "risky", (
                "kv_expire %r — would fail: invalid expire time %r"
                % (key, seconds)
            )
        return "safe", "kv_expire %r — no-op, the key does not exist" % key
    ttl = client.command("TTL", key)
    if ttl == -2:
        return "safe", (
            "%s %r — no-op, the key expired while auditing"
            % (name, key)
        )
    try:
        kind, size_value, size, sample = _inspect_key(client, key)
    except ValueError:
        return "safe", (
            "%s %r — no-op, the key expired while auditing"
            % (name, key)
        )
    if ttl == -1:
        ttl_text = "no expiry"
    else:
        ttl_text = "expires in %s" % _format_ttl(ttl)
    large = (
        (kind == "string" and size_value >= HEALTH_BIG_STRING_BYTES)
        or (kind != "string" and size_value >= HEALTH_BIG_CONTAINER_ELEMENTS)
    )
    if name == "kv_set":
        ttl_arg = op.get("ex", op.get("px"))
        if ttl_arg is not None and not _is_int(ttl_arg):
            return "risky", (
                "kv_set %r — would fail: bad TTL %r (not an integer); "
                "the key is a %s of %s with %s"
                % (key, ttl_arg, kind, size, ttl_text)
            )
        flags = []
        if kind != "string":
            flags.append(
                "would replace a %s of %s with a string, destroying "
                "its contents" % (kind, size)
            )
        if ttl == -1:
            flags.append("overwrites a key that never expires")
        if large:
            flags.append("overwrites a large key (%s)" % size)
        if flags:
            return "risky", "kv_set %r — %s" % (key, "; ".join(flags))
        return "caution", (
            "kv_set %r — overwrites a %s of %s that %s"
            % (key, kind, size, ttl_text)
        )
    if name == "kv_del":
        flags = []
        if ttl == -1:
            flags.append("deletes a key that never expires")
        if large:
            flags.append("deletes a large key (%s)" % size)
        if kind != "string":
            flags.append("deletes a %s of %s" % (kind, size))
        if flags:
            return "risky", "kv_del %r — %s" % (key, "; ".join(flags))
        return "caution", (
            "kv_del %r — deletes a %s of %s that %s"
            % (key, kind, size, ttl_text)
        )
    if name == "kv_incr":
        by = op.get("by", 1)
        if not _is_int(by):
            raise ValueError("kv_incr by is not an integer: %r" % (by,))
        if kind != "string":
            return "risky", (
                "kv_incr %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        if not _is_int(sample):
            return "risky", (
                "kv_incr %r — would fail: the current value is not "
                "an integer" % key
            )
        return "safe", (
            "kv_incr %r — increments a counter currently at %s"
            % (key, sample)
        )
    if name == "kv_append":
        if not isinstance(op.get("value"), str):
            raise ValueError(
                "kv_append value must be a string: %r" % (op.get("value"),)
            )
        if kind != "string":
            return "risky", (
                "kv_append %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        if large:
            return "caution", (
                "kv_append %r — appends to a large string of %s that %s"
                % (key, size, ttl_text)
            )
        return "safe", (
            "kv_append %r — appends to a string of %s that %s"
            % (key, size, ttl_text)
        )
    if name == "kv_pfadd":
        # PFADD grows the registers in place and never destroys
        # data, so a HyperLogLog's size is no risk on its own —
        # only a key that is not a HyperLogLog at all can fail.
        # The register blob reads back as a 16KB string, so the
        # `large` flag above does not apply here.
        elements = _pfadd_audit_elements(op)
        if kind != "string":
            return "risky", (
                "kv_pfadd %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        estimate = _hll_estimate(client, key)
        if estimate is None:
            return "risky", (
                "kv_pfadd %r — would fail with WRONGTYPE: the key is "
                "a plain string, not a HyperLogLog" % key
            )
        return "safe", (
            "kv_pfadd %r — adds %d element(s) to a HyperLogLog "
            "currently counting %d distinct element(s) that %s"
            % (key, len(elements), estimate, ttl_text)
        )
    if name == "kv_geoadd":
        # GEOADD adds members to a sorted set of geohash scores
        # and moves any member it re-adds to new coordinates, so
        # the members it would move are the risk: their stored
        # positions are overwritten, while new members only grow
        # the set. NX never moves a member, so an NX op only adds;
        # XX never adds one, so an XX op only moves the members
        # already in the set — and is a no-op when none of them
        # are. CH only changes what the reply counts, not what is
        # written. A ZMSCORE probe, chunked at 1000, tells which
        # members already exist — the set's size is no risk on its
        # own, since nothing is removed.
        members = _geoadd_audit_members(op)
        nx, xx, _ch = _geoadd_audit_options(op)
        if kind != "zset":
            return "risky", (
                "kv_geoadd %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        existing = 0
        for i in range(0, len(members), 1000):
            scores = client.command(
                "ZMSCORE", key, *members[i:i + 1000]
            ) or []
            existing += sum(
                1 for score in scores if score is not None
            )
        new = len(members) - existing
        if xx:
            if not existing:
                return "safe", (
                    "kv_geoadd %r — no-op, xx only updates members "
                    "already in the set and none of the %d are"
                    % (key, len(members))
                )
            return "caution", (
                "kv_geoadd %r — updates %d existing member(s) to new "
                "coordinates (xx adds no new members) in a geo set "
                "of %s that %s"
                % (key, existing, size, ttl_text)
            )
        if nx:
            if not new:
                return "safe", (
                    "kv_geoadd %r — no-op, nx only adds new members "
                    "and all %d are already in the set"
                    % (key, len(members))
                )
            return "safe", (
                "kv_geoadd %r — adds %d new member(s) (nx leaves the "
                "%d existing member(s) alone) to a geo set of %s "
                "that %s"
                % (key, new, existing, size, ttl_text)
            )
        if existing:
            return "caution", (
                "kv_geoadd %r — moves %d existing member(s) to new "
                "coordinates and adds %d new member(s) in a geo set "
                "of %s that %s"
                % (key, existing, new, size, ttl_text)
            )
        return "safe", (
            "kv_geoadd %r — adds %d new member(s) to a geo set of "
            "%s that %s"
            % (key, len(members), size, ttl_text)
        )
    if name == "kv_xadd":
        # XADD only appends, so it never destroys an entry on its
        # own — but MAXLEN trims the oldest entries, and MAXLEN 0
        # trims the whole stream at once, deleting the key. A
        # stream that never expires also grows without bound, so
        # appending to one is caution, not safe. The audit cannot
        # see the stream's top ID without reading the whole
        # stream, so an ID at or below the top still fails at
        # runtime; only the ID's shape is validated here.
        _key, _id, _fields, maxlen, _approx = _xadd_args(op)
        if kind != "stream":
            return "risky", (
                "kv_xadd %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        if maxlen == 0:
            if ttl == -1 or large:
                return "risky", (
                    "kv_xadd %r — would delete the whole stream of "
                    "%s outright (MAXLEN 0 trims every entry)%s"
                    % (key, size,
                       " that never expires" if ttl == -1 else "")
                )
            return "caution", (
                "kv_xadd %r — would delete the whole stream of %s "
                "outright (MAXLEN 0 trims every entry), but it %s"
                % (key, size, ttl_text)
            )
        if maxlen is not None and size_value > maxlen:
            trimmed = size_value - maxlen
            if ttl == -1:
                return "risky", (
                    "kv_xadd %r — would trim the %d oldest entr%s "
                    "from a stream of %s that never expires"
                    % (key, trimmed,
                       "y" if trimmed == 1 else "ies", size)
                )
            return "caution", (
                "kv_xadd %r — would trim the %d oldest entr%s from "
                "a stream of %s that %s"
                % (key, trimmed,
                   "y" if trimmed == 1 else "ies", size, ttl_text)
            )
        if ttl == -1:
            return "caution", (
                "kv_xadd %r — appends one entry to a stream of %s "
                "that never expires" % (key, size)
            )
        return "safe", (
            "kv_xadd %r — appends one entry to a stream of %s that "
            "%s" % (key, size, ttl_text)
        )
    if name == "kv_setrange":
        # SETRANGE rewrites part of the string in place and keeps
        # its TTL, like APPEND — it never replaces the key, so a
        # never-expiring string is not on its own a risk. An empty
        # value changes nothing at all.
        offset, value = _setrange_audit_args(op)
        if offset < 0:
            return "risky", (
                "kv_setrange %r — would fail: offset is out of range"
                % key
            )
        if value == "":
            return "safe", (
                "kv_setrange %r — no-op, an empty value changes "
                "nothing" % key
            )
        if kind != "string":
            return "risky", (
                "kv_setrange %r — would fail with WRONGTYPE: the key "
                "is a %s of %s" % (key, kind, size)
            )
        if large:
            return "caution", (
                "kv_setrange %r — overwrites part of a large string "
                "of %s that %s" % (key, size, ttl_text)
            )
        return "safe", (
            "kv_setrange %r — overwrites part of a string of %s "
            "that %s" % (key, size, ttl_text)
        )
    if name == "kv_setbit":
        # SETBIT flips one bit in place and keeps the key's TTL,
        # like SETRANGE — it never replaces the key, so a
        # never-expiring string is not on its own a risk. A bit
        # that already holds the requested value changes nothing.
        offset, bit = _setbit_audit_args(op)
        if offset < 0 or offset > 4294967295:
            return "risky", (
                "kv_setbit %r — would fail: offset is out of range"
                % key
            )
        if bit not in (0, 1):
            return "risky", (
                "kv_setbit %r — would fail: bit must be 0 or 1"
                % key
            )
        if kind != "string":
            return "risky", (
                "kv_setbit %r — would fail with WRONGTYPE: the key "
                "is a %s of %s" % (key, kind, size)
            )
        if client.command("GETBIT", key, offset) == bit:
            return "safe", (
                "kv_setbit %r — no-op, bit %d already holds %d"
                % (key, offset, bit)
            )
        if large:
            return "caution", (
                "kv_setbit %r — flips one bit of a large string "
                "of %s that %s" % (key, size, ttl_text)
            )
        return "safe", (
            "kv_setbit %r — flips bit %d of a string of %s that %s"
            % (key, offset, size, ttl_text)
        )
    if name == "kv_bitfield":
        # BITFIELD rewrites fields in place and keeps the key's
        # TTL, like SETBIT — it never replaces the key, so a
        # never-expiring string is not on its own a risk. A
        # GET-only call changes nothing at all.
        parsed = _bitfield_audit_args(op)
        problem = _bitfield_audit_problem(parsed)
        if problem:
            return "risky", (
                "kv_bitfield %r — would fail: %s" % (key, problem)
            )
        if kind != "string":
            return "risky", (
                "kv_bitfield %r — would fail with WRONGTYPE: the key "
                "is a %s of %s" % (key, kind, size)
            )
        writes = [p for p in parsed if p[0] in ("set", "incrby")]
        if not writes:
            return "safe", (
                "kv_bitfield %r — reads fields, changes nothing"
                % key
            )
        if large:
            return "caution", (
                "kv_bitfield %r — changes fields of a large string "
                "of %s that %s" % (key, size, ttl_text)
            )
        return "safe", (
            "kv_bitfield %r — changes fields of a string of %s "
            "that %s" % (key, size, ttl_text)
        )
    if name in ("kv_decr", "kv_decrby"):
        if name == "kv_decrby" and "by" not in op:
            raise ValueError("kv_decrby is missing by: %r" % (op,))
        by = op.get("by", 1)
        if not _is_int(by):
            raise ValueError(
                "%s by is not an integer: %r" % (name, by)
            )
        if kind != "string":
            return "risky", (
                "%s %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (name, key, kind, size)
            )
        if not _is_int(sample):
            return "risky", (
                "%s %r — would fail: the current value is not "
                "an integer" % (name, key)
            )
        return "safe", (
            "%s %r — decrements a counter currently at %s"
            % (name, key, sample)
        )
    if name == "kv_getex":
        ex, px, persist = _getex_option(op)
        if kind != "string":
            return "risky", (
                "kv_getex %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        ttl_arg = ex if ex is not None else px
        if ttl_arg is not None and (
            not _is_int(ttl_arg) or int(ttl_arg) <= 0
        ):
            return "risky", (
                "kv_getex %r — would fail: invalid expire time %r"
                % (key, ttl_arg)
            )
        if persist:
            if ttl == -1:
                return "safe", (
                    "kv_getex %r — returns the value; the key has "
                    "no expiry to remove" % key
                )
            return "caution", (
                "kv_getex %r — returns the value and removes its "
                "expiry (currently %s)" % (key, ttl_text)
            )
        if ex is not None:
            if ttl == -1:
                return "caution", (
                    "kv_getex %r — returns the value and gives a key "
                    "that never expires an expiry of %s"
                    % (key, _format_ttl(int(ex)))
                )
            return "safe", (
                "kv_getex %r — returns the value and sets its expiry "
                "to %s" % (key, _format_ttl(int(ex)))
            )
        if px is not None:
            if ttl == -1:
                return "caution", (
                    "kv_getex %r — returns the value and gives a key "
                    "that never expires an expiry of %dms" % (key, int(px))
                )
            return "safe", (
                "kv_getex %r — returns the value and sets its expiry "
                "to %dms" % (key, int(px))
            )
        return "safe", (
            "kv_getex %r — returns the value and leaves its TTL alone"
            % key
        )
    if name == "kv_setnx":
        if not isinstance(op.get("value"), str):
            raise ValueError(
                "kv_setnx value must be a string: %r" % (op.get("value"),)
            )
        # SETNX never writes to a key that already exists, whatever
        # it holds, so there is nothing to flag about it.
        return "safe", (
            "kv_setnx %r — no-op, the key already exists" % key
        )
    if name == "kv_setex":
        seconds = op.get("seconds")
        if seconds is None:
            raise ValueError("kv_setex is missing seconds: %r" % (op,))
        if not isinstance(op.get("value"), str):
            raise ValueError(
                "kv_setex value must be a string: %r" % (op.get("value"),)
            )
        if not _is_int(seconds) or int(seconds) <= 0:
            return "risky", (
                "kv_setex %r — would fail: invalid expire time %r"
                % (key, seconds)
            )
        flags = []
        if kind != "string":
            flags.append(
                "would replace a %s of %s with a string, destroying "
                "its contents" % (kind, size)
            )
        if ttl == -1:
            flags.append("overwrites a key that never expires")
        if large:
            flags.append("overwrites a large key (%s)" % size)
        if flags:
            return "risky", "kv_setex %r — %s" % (key, "; ".join(flags))
        return "caution", (
            "kv_setex %r — overwrites a %s of %s that %s, giving it "
            "an expiry of %s"
            % (key, kind, size, ttl_text, _format_ttl(int(seconds)))
        )
    if name == "kv_getset":
        if not isinstance(op.get("value"), str):
            raise ValueError(
                "kv_getset value must be a string: %r" % (op.get("value"),)
            )
        if kind != "string":
            return "risky", (
                "kv_getset %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        flags = []
        if ttl == -1:
            flags.append("overwrites a key that never expires")
        if large:
            flags.append("overwrites a large key (%s)" % size)
        if flags:
            return "risky", "kv_getset %r — %s" % (key, "; ".join(flags))
        return "caution", (
            "kv_getset %r — overwrites a %s of %s that %s and clears "
            "its TTL" % (key, kind, size, ttl_text)
        )
    if name == "kv_getdel":
        if kind != "string":
            return "risky", (
                "kv_getdel %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        flags = []
        if ttl == -1:
            flags.append("deletes a key that never expires")
        if large:
            flags.append("deletes a large key (%s)" % size)
        if flags:
            return "risky", "kv_getdel %r — %s" % (key, "; ".join(flags))
        return "caution", (
            "kv_getdel %r — deletes a %s of %s that %s"
            % (key, kind, size, ttl_text)
        )
    if name == "kv_hsetnx":
        field = op.get("field")
        if not isinstance(field, str):
            raise ValueError(
                "kv_hsetnx field must be a string: %r" % (field,)
            )
        if not isinstance(op.get("value"), str):
            raise ValueError(
                "kv_hsetnx value must be a string: %r"
                % (op.get("value"),)
            )
        if kind != "hash":
            return "risky", (
                "kv_hsetnx %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        if client.command("HEXISTS", key, field) == 1:
            # The field is already there: nothing is written.
            return "safe", (
                "kv_hsetnx %r — no-op, the field already exists" % key
            )
        if ttl == -1:
            return "caution", (
                "kv_hsetnx %r — adds a field to a hash that never "
                "expires" % key
            )
        return "safe", (
            "kv_hsetnx %r — adds a new field to a hash of %s that %s"
            % (key, size, ttl_text)
        )
    if name == "kv_hincrby":
        increment = _hincrby_audit_increment(op)
        field = op.get("field")
        if not isinstance(field, str):
            raise ValueError(
                "kv_hincrby field must be a string: %r" % (field,)
            )
        if kind != "hash":
            return "risky", (
                "kv_hincrby %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        current = client.command("HGET", key, field)
        if current is None:
            return "safe", (
                "kv_hincrby %r — creates a counter field starting at %d"
                % (key, int(increment))
            )
        if not _is_int(current):
            return "risky", (
                "kv_hincrby %r — would fail: the field value is not "
                "an integer" % key
            )
        return "safe", (
            "kv_hincrby %r — increments a counter field currently at %s"
            % (key, current)
        )
    if name == "kv_hincrbyfloat":
        increment = _hincrbyfloat_audit_increment(op)
        field = op.get("field")
        if not isinstance(field, str):
            raise ValueError(
                "kv_hincrbyfloat field must be a string: %r" % (field,)
            )
        if kind != "hash":
            return "risky", (
                "kv_hincrbyfloat %r — would fail with WRONGTYPE: the "
                "key is a %s of %s" % (key, kind, size)
            )
        current = client.command("HGET", key, field)
        if current is None:
            return "safe", (
                "kv_hincrbyfloat %r — creates a float field starting "
                "at %r" % (key, increment)
            )
        if not _is_float(current):
            return "risky", (
                "kv_hincrbyfloat %r — would fail: the field value is "
                "not a float" % key
            )
        return "safe", (
            "kv_hincrbyfloat %r — increments a float field currently "
            "at %s" % (key, current)
        )
    if name == "kv_lset":
        index = _lset_audit_args(op)
        if kind != "list":
            return "risky", (
                "kv_lset %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (key, kind, size)
            )
        resolved = index if index >= 0 else index + size_value
        if resolved < 0 or resolved >= size_value:
            return "risky", (
                "kv_lset %r — would fail: index %d is out of range "
                "for a list of %s" % (key, index, size)
            )
        current = client.command("LINDEX", key, index)
        if current == op.get("value"):
            # Cinder treats setting an element to the value it
            # already holds as a no-op.
            return "safe", (
                "kv_lset %r — no-op, the element at index %d already "
                "holds that value" % (key, index)
            )
        return "caution", (
            "kv_lset %r — replaces the element at index %d of a "
            "list of %s that %s" % (key, index, size, ttl_text)
        )
    if name == "kv_linsert":
        where = _linsert_audit_args(op)
        if kind != "list":
            return "risky", (
                "kv_linsert %r — would fail with WRONGTYPE: the key "
                "is a %s of %s" % (key, kind, size)
            )
        if size_value > 1000:
            # The pivot check needs the whole list, and a list this
            # wide is past the audit's read bound: the insert is
            # still one bounded element, but whether the pivot is
            # even there is unchecked.
            return "caution", (
                "kv_linsert %r — adds an element to a large list of "
                "%s; the pivot was not checked" % (key, size)
            )
        members = client.command("LRANGE", key, 0, -1) or []
        if op.get("pivot") not in members:
            # The pivot is not in the list: LINSERT answers 0 and
            # changes nothing.
            return "safe", (
                "kv_linsert %r — no-op, the pivot is not in the list"
                % key
            )
        if ttl == -1:
            return "caution", (
                "kv_linsert %r — inserts an element %s the pivot in "
                "a list that never expires" % (key, where)
            )
        return "safe", (
            "kv_linsert %r — inserts an element %s the pivot in a "
            "list of %s that %s" % (key, where, size, ttl_text)
        )
    if name in ("kv_lpushx", "kv_rpushx"):
        elements = _lpushx_audit_elements(op)
        if kind != "list":
            return "risky", (
                "%s %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (name, key, kind, size)
            )
        if ttl == -1:
            return "caution", (
                "%s %r — adds %d element(s) to a list that never "
                "expires" % (name, key, len(elements))
            )
        return "safe", (
            "%s %r — adds %d element(s) to a list of %s that %s"
            % (name, key, len(elements), size, ttl_text)
        )
    if name == "kv_ltrim":
        start, stop = _ltrim_audit_args(op)
        if kind != "list":
            return "risky", (
                "kv_ltrim %r — would fail with WRONGTYPE: the key "
                "is a %s of %s" % (key, kind, size)
            )
        # Resolve the range like cinder does: negative bounds count
        # from the end, then clamp to the list.
        lo = start if start >= 0 else start + size_value
        hi = stop if stop >= 0 else stop + size_value
        if lo < 0:
            lo = 0
        if hi >= size_value:
            hi = size_value - 1
        if lo > hi or lo >= size_value:
            # An empty range deletes the key, as in Redis.
            flags = []
            if ttl == -1:
                flags.append(
                    "trims away the whole list, deleting a key "
                    "that never expires"
                )
            if large:
                flags.append(
                    "trims away a large list (%s)" % size
                )
            if flags:
                return "risky", "kv_ltrim %r — %s" % (key, "; ".join(flags))
            return "caution", (
                "kv_ltrim %r — trims away the whole list, deleting "
                "the key" % key
            )
        kept = hi - lo + 1
        if kept == size_value:
            # The range keeps the whole list: nothing changes.
            return "safe", (
                "kv_ltrim %r — no-op, the range keeps the whole list"
                % key
            )
        if ttl == -1:
            return "caution", (
                "kv_ltrim %r — trims a list that never expires from "
                "%s to %d elements" % (key, size, kept)
            )
        return "safe", (
            "kv_ltrim %r — trims a list of %s that %s to %d elements"
            % (key, size, ttl_text, kept)
        )
    if name in ("kv_zpopmin", "kv_zpopmax"):
        count = op.get("count", 1)
        if not _is_int(count) or int(count) < 1:
            raise ValueError(
                "%s count is not a positive integer: %r" % (name, count)
            )
        if kind != "zset":
            return "risky", (
                "%s %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (name, key, kind, size)
            )
        count = int(count)
        if count >= size_value:
            # Popping every member deletes the key outright.
            flags = []
            if ttl == -1:
                flags.append(
                    "pops every member, deleting a sorted set that "
                    "never expires"
                )
            if large:
                flags.append(
                    "pops every member of a large sorted set (%s)" % size
                )
            if flags:
                return "risky", "%s %r — %s" % (name, key, "; ".join(flags))
            return "caution", (
                "%s %r — pops every member of a sorted set of %s "
                "that %s" % (name, key, size, ttl_text)
            )
        return "caution", (
            "%s %r — removes %d of %d members"
            % (name, key, count, size_value)
        )
    if name == "kv_zremrangebyscore":
        min_b, max_b = _zremrangebyscore_audit_bounds(op)
        if kind != "zset":
            return "risky", (
                "kv_zremrangebyscore %r — would fail with WRONGTYPE: "
                "the key is a %s of %s" % (key, kind, size)
            )
        # The count comes from the server: fetch the range with
        # one extra member, so a range wider than the audit's
        # read bound is reported as more than 1000 instead of a
        # silently truncated count.
        members = client.command(
            "ZRANGEBYSCORE", key, min_b, max_b,
            "LIMIT", 0, 1001,
        ) or []
        if len(members) > 1000:
            return "risky", (
                "kv_zremrangebyscore %r — removes more than 1000 "
                "members of a sorted set of %s" % (key, size)
            )
        removed = len(members)
        if removed == 0:
            return "safe", (
                "kv_zremrangebyscore %r — no-op, the range is empty"
                % key
            )
        if removed >= size_value:
            # Removing every member deletes the key outright.
            flags = []
            if ttl == -1:
                flags.append(
                    "removes every member, deleting a sorted set "
                    "that never expires"
                )
            if large:
                flags.append(
                    "removes every member of a large sorted set (%s)"
                    % size
                )
            if flags:
                return "risky", (
                    "kv_zremrangebyscore %r — %s" % (key, "; ".join(flags))
                )
            return "caution", (
                "kv_zremrangebyscore %r — removes every member of a "
                "sorted set of %s that %s"
                % (key, size, ttl_text)
            )
        return "caution", (
            "kv_zremrangebyscore %r — removes %d of %d members"
            % (key, removed, size_value)
        )
    if name == "kv_zremrangebyrank":
        start, stop = _zremrangebyrank_audit_ranks(op)
        if kind != "zset":
            return "risky", (
                "kv_zremrangebyrank %r — would fail with WRONGTYPE: "
                "the key is a %s of %s" % (key, kind, size)
            )
        removed = _zremrange_window(start, stop, size_value)
        if removed == 0:
            return "safe", (
                "kv_zremrangebyrank %r — no-op, the range is empty"
                % key
            )
        if removed >= size_value:
            # Removing every member deletes the key outright.
            flags = []
            if ttl == -1:
                flags.append(
                    "removes every member, deleting a sorted set "
                    "that never expires"
                )
            if large:
                flags.append(
                    "removes every member of a large sorted set (%s)"
                    % size
                )
            if flags:
                return "risky", (
                    "kv_zremrangebyrank %r — %s" % (key, "; ".join(flags))
                )
            return "caution", (
                "kv_zremrangebyrank %r — removes every member of a "
                "sorted set of %s that %s"
                % (key, size, ttl_text)
            )
        return "caution", (
            "kv_zremrangebyrank %r — removes %d of %d members"
            % (key, removed, size_value)
        )
    if name == "kv_zremrangebylex":
        min_b, max_b = _zremrangebylex_audit_bounds(op)
        if kind != "zset":
            return "risky", (
                "kv_zremrangebylex %r — would fail with WRONGTYPE: "
                "the key is a %s of %s" % (key, kind, size)
            )
        # The count comes from the server: fetch the range with
        # one extra member, so a range wider than the audit's
        # read bound is reported as more than 1000 instead of a
        # silently truncated count.
        members = client.command(
            "ZRANGEBYLEX", key, min_b, max_b,
            "LIMIT", 0, 1001,
        ) or []
        if len(members) > 1000:
            return "risky", (
                "kv_zremrangebylex %r — removes more than 1000 "
                "members of a sorted set of %s" % (key, size)
            )
        removed = len(members)
        if removed == 0:
            return "safe", (
                "kv_zremrangebylex %r — no-op, the range is empty"
                % key
            )
        if removed >= size_value:
            # Removing every member deletes the key outright.
            flags = []
            if ttl == -1:
                flags.append(
                    "removes every member, deleting a sorted set "
                    "that never expires"
                )
            if large:
                flags.append(
                    "removes every member of a large sorted set (%s)"
                    % size
                )
            if flags:
                return "risky", (
                    "kv_zremrangebylex %r — %s" % (key, "; ".join(flags))
                )
            return "caution", (
                "kv_zremrangebylex %r — removes every member of a "
                "sorted set of %s that %s"
                % (key, size, ttl_text)
            )
        return "caution", (
            "kv_zremrangebylex %r — removes %d of %d members"
            % (key, removed, size_value)
        )
    if name in ("kv_hexpire", "kv_hpexpire", "kv_hexpireat",
                "kv_hpexpireat"):
        fields, condition, time_value, is_ms, absolute = \
            _hexpire_audit_args(op)
        if kind != "hash":
            return "risky", (
                "%s %r — would fail with WRONGTYPE: the key is "
                "a %s of %s" % (name, key, kind, size)
            )
        # The current field TTLs, probed live in the op's unit
        # and converted to milliseconds for the comparison: -2
        # the field does not exist, -1 no expiry.
        probe = "HPTTL" if is_ms else "HTTL"
        current = client.command(
            probe, key, "FIELDS", len(fields), *fields) or []
        effective = _hexpire_effective_ms(time_value, is_ms, absolute)
        if ttl == -1:
            hash_text = "a hash of %s that never expires" % size
        else:
            hash_text = "a hash of %s that %s" % (size, ttl_text)
        changed = 0
        deleted = 0
        for ttl_value in current:
            if ttl_value == -2:
                continue
            current_ms = -1 if ttl_value == -1 else ttl_value * (
                1 if is_ms else 1000)
            if not _hexpire_condition_applies(
                    condition, current_ms, effective):
                continue
            changed += 1
            if effective <= 0:
                deleted += 1
        if changed == 0:
            return "safe", (
                "%s %r — no-op, the condition was not met for any "
                "field" % (name, key)
            )
        if deleted:
            if deleted >= size_value:
                # Every field goes, so the key goes with them.
                flags = []
                if ttl == -1:
                    flags.append(
                        "deletes every field of a hash that never "
                        "expires"
                    )
                if large:
                    flags.append(
                        "deletes every field of a large hash (%s)"
                        % size
                    )
                if flags:
                    return "risky", "%s %r — %s" % (
                        name, key, "; ".join(flags))
                return "caution", (
                    "%s %r — deletes every field of %s"
                    % (name, key, hash_text)
                )
            return "caution", (
                "%s %r — deletes %d of %d fields of %s"
                % (name, key, deleted, size_value, hash_text)
            )
        if is_ms:
            new_text = "%dms" % effective
        else:
            new_text = _format_ttl(max(effective // 1000, 0))
        return "safe", (
            "%s %r — sets a field expiry of %s on %d field(s) of %s"
            % (name, key, new_text, changed, hash_text)
        )
    if name == "kv_hpersist":
        fields, _condition, _time, _is_ms, _absolute = \
            _hexpire_audit_args(op)
        if kind != "hash":
            return "risky", (
                "kv_hpersist %r — would fail with WRONGTYPE: the "
                "key is a %s of %s" % (key, kind, size)
            )
        current = client.command(
            "HPTTL", key, "FIELDS", len(fields), *fields) or []
        expiring = sum(1 for value in current if value >= 0)
        if expiring == 0:
            return "safe", (
                "kv_hpersist %r — no-op, none of the fields has an "
                "expiry" % key
            )
        if ttl == -1:
            return "caution", (
                "kv_hpersist %r — removes the expiry from %d "
                "field(s) of a hash that never expires"
                % (key, expiring)
            )
        return "safe", (
            "kv_hpersist %r — removes the expiry from %d field(s) "
            "of a hash of %s that %s"
            % (key, expiring, size, ttl_text)
        )
    # kv_expire on an existing key.
    seconds = op.get("seconds")
    if seconds is None:
        raise ValueError("kv_expire is missing seconds: %r" % (op,))
    if not _is_int(seconds) or int(seconds) < 0:
        return "risky", (
            "kv_expire %r — would fail: invalid expire time %r"
            % (key, seconds)
        )
    return "safe", (
        "kv_expire %r — sets a %s of %s that currently has %s to "
        "expire in %s" % (key, kind, size, ttl_text, _format_ttl(int(seconds)))
    )


def _write_safety(client, arguments):
    """Audit a proposed write plan against the live keyspace before
    anything runs. `plan` is a JSON array of kv_batch-shaped ops;
    each write op is probed live (EXISTS, TTL, type, size) and
    given a verdict of safe, caution, or risky. Read ops are not
    audited — they change nothing — and malformed ops are reported
    as not audited rather than guessed at. Only the first
    MAX_WRITE_SAFETY_OPS ops are audited, so the prompt text stays
    bounded however long the plan is. Values are never printed.
    One honest limit: cinder keeps no per-key access counts, so
    there is no way to tell a hot key from a cold one — the audit
    flags size, permanence, and type instead of hotness."""
    raw_plan = arguments.get("plan")
    if not raw_plan:
        raise ValueError("write-safety requires a plan argument")
    try:
        plan = json.loads(raw_plan)
    except (TypeError, ValueError):
        raise ValueError(
            "write-safety plan must be a JSON array of ops, got: %r"
            % (raw_plan[:100],)
        )
    if not isinstance(plan, list):
        raise ValueError(
            "write-safety plan must be a JSON array of ops, got a %s"
            % type(plan).__name__
        )
    audited = {"safe": [], "caution": [], "risky": []}
    counts = {"safe": 0, "caution": 0, "risky": 0}
    skipped = []  # (op index, reason) for ops not audited
    for index, op in enumerate(plan):
        if index >= MAX_WRITE_SAFETY_OPS:
            skipped.append(
                (index, "past the %d-op audit cap" % MAX_WRITE_SAFETY_OPS)
            )
            continue
        if not isinstance(op, dict):
            skipped.append((index, "not an op object: %r" % (op,)))
            continue
        name = op.get("op")
        if name in WRITE_SAFETY_READ_OPS:
            skipped.append((index, "%s is a read, not a write" % name))
            continue
        try:
            verdict, line = _audit_write_op(client, op)
        except ValueError as exc:
            skipped.append((index, str(exc)))
            continue
        counts[verdict] += 1
        audited[verdict].append((index, line))
    lines = [
        "Write-safety audit of a proposed write plan.",
        "",
        "Plan: %d op(s), %d audited, %d not audited."
        % (len(plan), sum(counts.values()), len(skipped)),
    ]
    section_text = [
        ("risky", "Risky (%d) — do not run these as written:"),
        ("caution", "Caution (%d) — safe to run only if the overwrite is intended:"),
        ("safe", "Safe (%d):"),
    ]
    for verdict, header in section_text:
        lines.extend(["", header % counts[verdict]])
        if audited[verdict]:
            for index, line in audited[verdict]:
                lines.append("op %d: %s" % (index, line))
        else:
            lines.append("(none)")
    if skipped:
        lines.extend(["", "Not audited (%d):" % len(skipped)])
        for index, reason in skipped:
            lines.append("op %d: %s" % (index, reason))
    lines.extend([
        "",
        "Give a go/no-go verdict for the plan as a whole, then per "
        "risky op: what exactly would go wrong if it ran, and what "
        "to change — a different key, a kv_expire first, a backup "
        "read with kv_get or cinder://key/<key> before overwriting, "
        "or dropping the op — to make it safe. For the caution ops, "
        "say which ones are fine as written and which need a "
        "second look, and why. Then list the exact safe subset as "
        "one kv_batch call, in plan order, leaving out every risky "
        "op and every op you would not endorse. Do not run anything "
        "yourself: the plan has not run yet, and nothing in this "
        "audit changed the keyspace.",
    ])
    return {
        "description": _prompt_def("write-safety")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _parse_positive_int(raw, name, default):
    """A prompt argument as a positive integer, or ValueError.
    `raw` arrives as a string from prompts/get; `default` is used
    when the argument was not given at all. Bools are rejected —
    True is 1 to int() but is not a TTL anyone meant."""
    if raw is None:
        return default
    if isinstance(raw, bool):
        raise ValueError("%s must be a positive integer, got: %r" % (name, raw))
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ValueError("%s must be a positive integer, got: %r" % (name, raw))
    if value <= 0:
        raise ValueError("%s must be a positive integer, got: %r" % (name, raw))
    return value


def _ttl_renewal(client, arguments):
    """Plan TTL renewals: read the live TTL of every key matching a
    pattern (or an explicit list of keys) and propose one kv_expire
    renewal per key that needs one. Keys expiring sooner than the
    target TTL are renewed to it, soonest first; keys with no
    expiry get a first expiry at the target TTL. Keys already
    living at least as long as the target need nothing. Keys that
    are already expired or missing are flagged and never proposed
    for renewal. The plan covers at most max_keys keys in total
    (renewals plus first expiries); the rest are counted as not
    covered, so the prompt text stays bounded however large the
    keyspace is. Values are never read and never printed: only
    TTLs are probed. One honest limit: renewals run as kv_expire
    (EXPIRE, whole seconds); kv_pexpire exists for sub-second
    precision when a key needs it, but this plan stays in whole
    seconds."""
    pattern = arguments.get("pattern", "*")
    target_ttl = _parse_positive_int(
        arguments.get("target_ttl"), "target_ttl",
        DEFAULT_RENEWAL_TARGET_TTL,
    )
    max_keys = _parse_positive_int(
        arguments.get("max_keys"), "max_keys", DEFAULT_RENEWAL_MAX_KEYS
    )
    if max_keys > MAX_RENEWAL_MAX_KEYS:
        raise ValueError(
            "max_keys must be at most %d, got: %d"
            % (MAX_RENEWAL_MAX_KEYS, max_keys)
        )
    raw_keys = arguments.get("keys")
    if raw_keys is not None:
        try:
            keys = json.loads(raw_keys)
        except (TypeError, ValueError):
            raise ValueError(
                "ttl-renewal keys must be a JSON array of key names, "
                "got: %r" % (raw_keys[:100],)
            )
        if not isinstance(keys, list) or not all(
            isinstance(key, str) for key in keys
        ):
            raise ValueError(
                "ttl-renewal keys must be a JSON array of key names"
            )
        key_batches = [keys]
        source = "keys %r" % (keys,)
    else:
        key_batches = iter_keys(client, pattern, PROMPT_SCAN_BATCH_SIZE)
        source = "pattern %r" % pattern
    renew = []  # (ttl, key), soonest first
    no_expiry = []  # bounded sorted keys, at most MAX_RENEWAL_MAX_KEYS
    no_expiry_count = 0
    already_ok = []  # bounded sorted (ttl, key)
    already_ok_count = 0
    missing = []  # bounded sorted keys
    missing_count = 0
    total = 0
    for batch in key_batches:
        for key in batch:
            total += 1
            ttl = client.command("TTL", key)
            if ttl == -2:
                missing_count += 1
                _bounded_insert(missing, key, MAX_RENEWAL_LISTED)
            elif ttl == -1:
                no_expiry_count += 1
                _bounded_insert(no_expiry, key, MAX_RENEWAL_MAX_KEYS)
            elif ttl < target_ttl:
                renew.append((ttl, key))
            else:
                already_ok_count += 1
                _bounded_insert(
                    already_ok, (ttl, key), MAX_RENEWAL_LISTED
                )
    renew.sort()
    no_expiry.sort()
    # The cap covers renewals plus first expiries, soonest first:
    # renewals fill the plan first, no-expiry keys take what is left.
    plan_renew = renew[:max_keys]
    plan_no_expiry = no_expiry[:max(0, max_keys - len(plan_renew))]
    not_covered = (
        (len(renew) - len(plan_renew))
        + (no_expiry_count - len(plan_no_expiry))
    )
    target_text = _format_ttl(target_ttl)
    lines = [
        "TTL renewal plan (%s, renew to %s)." % (source, target_text),
        "",
        "Total keys scanned: %d" % total,
        "Plan covers %d key(s); %d more need renewal but are outside "
        "the cap of %d." % (
            len(plan_renew) + len(plan_no_expiry), not_covered, max_keys
        ),
    ]
    lines.extend([
        "",
        "Renew (%d) — expiring sooner than %s, soonest first:" % (
            len(plan_renew), target_text
        ),
    ])
    if plan_renew:
        for ttl, key in plan_renew:
            lines.append(
                "- %s (expires in %s, renew to %s with kv_expire %r %d)"
                % (key, _format_ttl(ttl), target_text, key, target_ttl)
            )
    else:
        lines.append("(none)")
    if len(renew) > len(plan_renew):
        lines.append(
            "... and %d more expiring keys not covered by the cap"
            % (len(renew) - len(plan_renew))
        )
    lines.extend([
        "",
        "Give a first expiry (%d) — no expiry set, proposed expiry "
        "is %s:" % (len(plan_no_expiry), target_text),
    ])
    if plan_no_expiry:
        for key in plan_no_expiry:
            lines.append(
                "- %s (no expiry, set to %s with kv_expire %r %d)"
                % (key, target_text, key, target_ttl)
            )
    else:
        lines.append("(none)")
    if no_expiry_count > len(plan_no_expiry):
        lines.append(
            "... and %d more no-expiry keys not covered by the cap"
            % (no_expiry_count - len(plan_no_expiry))
        )
    lines.extend(["", "Already fine (%d) — living at least %s:" % (
        already_ok_count, target_text
    )])
    if already_ok:
        for ttl, key in already_ok:
            lines.append("- %s (expires in %s)" % (key, _format_ttl(ttl)))
        if already_ok_count > MAX_RENEWAL_LISTED:
            lines.append(
                "... and %d more" % (already_ok_count - MAX_RENEWAL_LISTED)
            )
    else:
        lines.append("(none)")
    lines.extend(["", "Missing or expired (%d) — do not renew these:" % missing_count])
    if missing:
        for key in missing:
            lines.append("- %s" % key)
        if missing_count > MAX_RENEWAL_LISTED:
            lines.append(
                "... and %d more" % (missing_count - MAX_RENEWAL_LISTED)
            )
    else:
        lines.append("(none)")
    lines.extend([
        "",
        "Produce the renewal plan as exact kv_expire calls, in the "
        "order listed above, or as one kv_batch call with one "
        "kv_expire op per key. For each no-expiry key, say first "
        "whether it looks like it should expire at all — a key "
        "that is permanent by design must not get an expiry just "
        "because it has none — and leave out any key you would not "
        "renew. Do not renew the missing or expired keys: they are "
        "gone, and kv_expire on them would be a no-op. Renewals "
        "run as kv_expire (EXPIRE, whole seconds); kv_pexpire "
        "exists for sub-second precision when a key needs it, but "
        "this plan stays in whole seconds. "
        "Do not run anything yourself: nothing in this plan has "
        "changed the keyspace yet.",
    ])
    return {
        "description": _prompt_def("ttl-renewal")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }


def _literal_prefix(pattern):
    """The literal text of a glob pattern before its first wildcard:
    "old:*" -> "old:", "*" -> "". Every key matching the pattern
    starts with it, so it is the part the target prefix replaces
    when a migrated key's target name is computed."""
    for index, char in enumerate(pattern):
        if char in "*?":
            return pattern[:index]
    return pattern


def _key_migration(client, arguments):
    """Plan migrating keys matching a pattern to a new prefix. Each
    source key is audited live — type, size, TTL — and its target
    name is the target prefix plus the part of the key after the
    pattern's literal prefix, so "old:user:1" under pattern "old:*"
    migrates to "v2:user:1" for target prefix "v2:". The target name
    is probed too: a free target means the key is ready, a target
    holding the same type would be overwritten, and a target
    holding a different type is a conflict that must be resolved
    first. A key whose target name is itself (the pattern and the
    target prefix agree, e.g. pattern "old:*" with prefix "old:")
    is flagged rather than migrated. Keys that expire while
    scanning are counted as missing, not migrated. The plan covers
    at most max_keys ready keys, in key order; overwrite, conflict,
    self-mapping, and missing keys are warnings, so each of those
    sections lists only its first 10 plus a count of the rest.
    Values are never read and never printed: only TTLs, types, and
    sizes are probed. List keys move atomically one element at a
    time: kv_lmove from 'left' to 'right', once per element, so the
    elements arrive in order and each move is atomic; the last move
    empties the source and cinder deletes an emptied list, so no
    kv_del is needed for a list key, and the TTL is re-applied with
    kv_expire afterwards because LMOVE creates the target with no
    expiry. A list key whose target name is itself needs no move at
    all — kv_lmove with source and destination the same key would
    rotate the list instead of moving it. One honest limit: cinder
    has no RENAME or COPY command, so migrating a non-list key is a
    read plus a write, not one atomic move — the plan's copy step is
    read the value, write it under the target name, re-apply the
    TTL, verify, then delete the source, and a key can change
    between the read and the write, so the source is only deleted
    after the target is verified. The TTL printed for a key is the
    one observed during the audit and it ticks down, so the plan
    says to re-check it with kv_ttl just before copying and use the
    fresh value in kv_expire."""
    pattern = arguments.get("pattern", "*")
    target_prefix = arguments.get("target_prefix")
    if not target_prefix or not isinstance(target_prefix, str):
        raise ValueError("key-migration requires a target_prefix argument")
    if "*" in target_prefix or "?" in target_prefix:
        raise ValueError(
            "key-migration target_prefix must be a literal prefix, "
            "got: %r" % (target_prefix,)
        )
    max_keys = _parse_positive_int(
        arguments.get("max_keys"), "max_keys", DEFAULT_MIGRATION_MAX_KEYS
    )
    if max_keys > MAX_MIGRATION_MAX_KEYS:
        raise ValueError(
            "max_keys must be at most %d, got: %d"
            % (MAX_MIGRATION_MAX_KEYS, max_keys)
        )
    literal = _literal_prefix(pattern)
    ready = []  # (key, line), sorted by key at render time
    overwrite = []  # bounded (key, line)
    overwrite_count = 0
    conflict = []  # bounded (key, line)
    conflict_count = 0
    self_mapped = []  # bounded (key, line)
    self_count = 0
    missing = []  # bounded sorted keys
    missing_count = 0
    total = 0
    for batch in iter_keys(client, pattern, PROMPT_SCAN_BATCH_SIZE):
        for key in batch:
            total += 1
            ttl = client.command("TTL", key)
            if ttl == -2:
                missing_count += 1
                _bounded_insert(
                    missing, key, MAX_MIGRATION_FLAGGED_LISTED
                )
                continue
            try:
                kind, size_value, size, _sample = _inspect_key(client, key)
            except ValueError:
                # The key vanished between the TTL probe and the type probe.
                missing_count += 1
                _bounded_insert(
                    missing, key, MAX_MIGRATION_FLAGGED_LISTED
                )
                continue
            target = target_prefix + key[len(literal):]
            if ttl == -1:
                ttl_text = "no expiry"
            else:
                ttl_text = "expires in %s" % _format_ttl(ttl)
            large = (
                (kind == "string" and size_value >= HEALTH_BIG_STRING_BYTES)
                or (kind != "string"
                    and size_value >= HEALTH_BIG_CONTAINER_ELEMENTS)
            )
            source_text = "%s, %s, %s" % (kind, size, ttl_text)
            if large:
                source_text += ", large — copy one at a time"
            if target == key:
                self_count += 1
                self_note = ""
                if kind == "list":
                    # LMOVE with source and destination the same key
                    # rotates the list instead of moving it, so a
                    # self-mapped list key must never be moved.
                    self_note = (
                        " — already in place, do not call kv_lmove "
                        "with source and destination the same key, "
                        "that would rotate the list"
                    )
                _bounded_insert(
                    self_mapped,
                    (key, "- %s → %s (%s; the target is the key "
                     "itself%s)"
                     % (key, target, source_text, self_note)),
                    MAX_MIGRATION_FLAGGED_LISTED,
                )
                continue
            if kind == "list":
                # A list moves with LMOVE, one element per call,
                # from 'left' to 'right' so the elements arrive in
                # order; each move is atomic, the last move empties
                # the source and cinder deletes an emptied list, so
                # no kv_del is needed, and the TTL is re-applied
                # afterwards because LMOVE creates the target with
                # no expiry.
                ready_line = (
                    "- %s → %s (%s; move it with %d kv_lmove calls — "
                    "source %r, destination %r, from 'left' to "
                    "'right' — each move is atomic and moves one "
                    "element in order; the last move deletes the "
                    "source, so no kv_del is needed; then re-apply "
                    "the TTL with kv_expire)"
                    % (key, target, source_text, size_value, key,
                       target)
                )
            else:
                ready_line = (
                    "- %s → %s (%s; delete the source with kv_del %r "
                    "after verifying the copy)"
                    % (key, target, source_text, key)
                )
            if client.command("EXISTS", target) == 0:
                ready.append((key, ready_line))
                continue
            target_ttl = client.command("TTL", target)
            if target_ttl == -2:
                # The target expired between EXISTS and TTL: it is
                # effectively free now.
                ready.append((key, ready_line))
                continue
            try:
                target_kind, _t_size, target_size, _s = _inspect_key(
                    client, target
                )
            except ValueError:
                # The target vanished between EXISTS and the type probe.
                ready.append((key, ready_line))
                continue
            if target_ttl == -1:
                target_ttl_text = "no expiry"
            else:
                target_ttl_text = (
                    "expires in %s" % _format_ttl(target_ttl)
                )
            target_text = "%s, %s, %s" % (
                target_kind, target_size, target_ttl_text
            )
            flagged_line = (
                "- %s → %s (source: %s; target exists: %s)"
                % (key, target, source_text, target_text)
            )
            if target_kind == kind:
                overwrite_count += 1
                _bounded_insert(
                    overwrite, (key, flagged_line),
                    MAX_MIGRATION_FLAGGED_LISTED,
                )
            else:
                conflict_count += 1
                _bounded_insert(
                    conflict, (key, flagged_line),
                    MAX_MIGRATION_FLAGGED_LISTED,
                )
    ready.sort()
    plan_ready = ready[:max_keys]
    not_covered = len(ready) - len(plan_ready)
    lines = [
        "Key migration plan (pattern %r → prefix %r)."
        % (pattern, target_prefix),
        "",
        "Total keys scanned: %d" % total,
        "Plan covers %d ready key(s); %d more ready keys are outside "
        "the cap of %d." % (len(plan_ready), not_covered, max_keys),
    ]
    lines.extend([
        "",
        "Ready (%d) — the target name is free, safe to migrate:"
        % len(plan_ready),
    ])
    if plan_ready:
        lines.extend(line for _key, line in plan_ready)
        if not_covered:
            lines.append(
                "... and %d more ready keys not covered by the cap"
                % not_covered
            )
    else:
        lines.append("(none)")
    flagged_sections = [
        (
            overwrite, overwrite_count,
            "Overwrite (%d) — the target exists with the same type; "
            "migrating would destroy its current contents:",
            "overwrite",
        ),
        (
            conflict, conflict_count,
            "Conflict (%d) — the target exists with a different type; "
            "do not migrate until resolved:",
            "conflict",
        ),
        (
            self_mapped, self_count,
            "Maps onto itself (%d) — the target name equals the source "
            "key; check the pattern and target prefix:",
            "self-mapping",
        ),
    ]
    for members, count, header, label in flagged_sections:
        lines.extend(["", header % count])
        if members:
            lines.extend(line for _key, line in members)
            if count > MAX_MIGRATION_FLAGGED_LISTED:
                lines.append(
                    "... and %d more %s keys" % (
                        count - MAX_MIGRATION_FLAGGED_LISTED, label
                    )
                )
        else:
            lines.append("(none)")
    lines.extend([
        "",
        "Missing or expired (%d) — gone while scanning, skip:"
        % missing_count,
    ])
    if missing:
        lines.extend("- %s" % key for key in missing)
        if missing_count > MAX_MIGRATION_FLAGGED_LISTED:
            lines.append(
                "... and %d more" % (
                    missing_count - MAX_MIGRATION_FLAGGED_LISTED
                )
            )
    else:
        lines.append("(none)")
    lines.extend([
        "",
        "Produce the migration steps for the ready keys, in the "
        "order listed above, one key at a time. For a ready list "
        "key, move it with kv_lmove, not by reading and re-writing "
        "it: call kv_lmove once per element — source the key, "
        "destination the target name, from 'left' to 'right' — so "
        "the elements arrive in order, one at a time, each move "
        "atomic; the audited element count above is how many calls "
        "to make. The last move empties the source, and cinder "
        "deletes an emptied list, so there is no kv_del step for a "
        "list key — verify instead with kv_llen on the target (it "
        "must equal the audited element count) and kv_exists on "
        "the source (it must be 0). A move interrupted halfway is "
        "safe to resume: the elements already moved are in the "
        "target in order and the rest are still in the source, so "
        "keep calling kv_lmove until the source is empty; never "
        "read the elements out and re-write them. LMOVE creates "
        "the target with no expiry, so re-check the source TTL "
        "with kv_ttl just before moving and re-apply the fresh "
        "value on the target with kv_expire after the last move. "
        "For a ready key of any other type, first read the value "
        "— kv_get or cinder://key/<key> for a string, "
        "cinder://key/<key> for a container — and write it under "
        "the target name; then re-check the source TTL with kv_ttl "
        "and re-apply the fresh value on the target with kv_expire, "
        "since the TTL printed above has ticked down since the "
        "audit; then verify the target with kv_exists and kv_ttl; "
        "only then delete the source with the kv_del call listed "
        "above. The kv_expire and kv_del steps for already-verified "
        "copies can run as one kv_batch call. For each overwrite "
        "key, say what to check before migrating it — read the "
        "target's value, decide which copy wins, and back the loser "
        "up — and for an overwrite list key, kv_lmove would append "
        "the source's elements onto the target's existing list, so "
        "if the source wins delete the target with kv_del first "
        "and only then move it with kv_lmove; for each conflict "
        "key, say what has to change before it can migrate at all. "
        "A self-mapped key is already at its target name and needs "
        "no move at all — and for a self-mapped list key never "
        "call kv_lmove with source and destination the same key, "
        "that rotates the list instead of moving it. Copy large "
        "keys one at a time, in a quiet window. Do not print any "
        "value anywhere. Cinder has no RENAME or COPY command, so "
        "a migration of a non-list key is a read plus a write, not "
        "one atomic move: a key can change between the read and "
        "the write, so verify the target before deleting the "
        "source, and do not migrate keys that are being written "
        "concurrently. A list key is the exception: each kv_lmove "
        "is atomic, though the whole list still moves one element "
        "at a time. This plan renames keys within this cinder "
        "instance; moving keys to another server needs the same "
        "steps run against that server, and this server cannot "
        "check whether the target names exist there. "
        "Do not run anything yourself: nothing in this plan has "
        "changed the keyspace yet.",
    ])
    return {
        "description": _prompt_def("key-migration")["description"],
        "messages": [
            {"role": "user", "content": {"type": "text", "text": "\n".join(lines)}},
        ],
    }
