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
on a non-float field or a container, and EXPIREs with a bad timeout,
then asks the model for a go/no-go per risky op. SETNX never
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

from .resp import RespError
from .scan import DEFAULT_SCAN_BATCH_SIZE, iter_keys

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
    "kv_append", "kv_decr", "kv_decrby", "kv_getex",
    "kv_hsetnx", "kv_hincrby", "kv_hincrbyfloat",
    "kv_zpopmin", "kv_zpopmax",
    "kv_lset", "kv_linsert",
    "kv_lpushx", "kv_rpushx", "kv_ltrim", "kv_lmove",
)
WRITE_SAFETY_READ_OPS = ("kv_get", "kv_keys", "kv_ttl", "kv_exists",
                         "kv_strlen", "kv_hscan", "kv_hkeys", "kv_hvals",
                         "kv_zrandmember", "kv_zscan", "kv_lindex")

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
            "would fail, GETEXes that would change or remove a TTL, "
            "ZPOPs that would drain a sorted set, LPUSHXes and "
            "RPUSHXes that would fail on a container, LTRIMs that "
            "would delete a list outright, LMOVEs that would fail "
            "on a container or drain a source list, and EXPIREs with "
            "a bad timeout, and give a go/no-go per risky op."
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
    SCARD / HLEN / ZCARD are tried in turn and the first one that
    does not answer WRONGTYPE names it."""
    try:
        value = client.command("GET", key)
    except RespError:
        # Not a string: probe the container types.
        for probe, name in (("LLEN", "list"), ("SCARD", "set"),
                            ("HLEN", "hash"), ("ZCARD", "zset")):
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
    container, a HSETNX on a container, an APPEND on a
    container, a GETEX or ZPOP on a container, an LSET or LINSERT
    on a container, an LSET on a missing key or with an index out
    of range, an LPUSHX or RPUSHX on a container, an LTRIM that
    would delete a never-expiring or large list outright, an
    LMOVE out of a container, into a container, or that would
    delete a never-expiring source by taking its only element,
    a ZPOP that would drain a never-expiring or large
    sorted set, or an EXPIRE,
    SETEX or GETEX with a bad timeout. "caution" changes
    something but the damage is bounded — an overwrite or delete
    of a key that expires soon anyway, a SET, MSET, SETNX, APPEND
    or GETSET that creates a key with no expiry, a HSETNX that
    creates a hash with no expiry or adds a field to a hash that
    never expires, a GETEX that gives a never-expiring key an
    expiry or removes one, a ZPOP that takes some but not all
    members, an LSET that replaces one element of a list, or an
    LINSERT that adds one element to a list, an LPUSHX or RPUSHX
    that adds elements to a list that never expires, an LTRIM
    that shortens a list that never expires or deletes a list
    that expires soon, or an LMOVE that moves one element out of
    a list with more to spare or empties a source that expires
    soon. SETNX on a key that
    already exists writes nothing, so it is safe, and so is HSETNX
    on a field that already exists, an LSET that writes the value
    the element already holds, and an LINSERT whose pivot is not
    in the list. Everything else is "safe": creating an expiring key,
    INCR or DECR on a missing key, HINCRBY on a missing key or a
    missing field, HINCRBYFLOAT on a missing key or a missing
    field, an EXPIRE on an existing key, a GETEX that
    only reads a value, an LPUSHX, RPUSHX, or LTRIM on a missing
    key, an LMOVE out of a missing key or within one key, or a
    no-op on a missing key.
    kv_mset has no single key — it writes several at once — so it
    is audited by _audit_mset instead of the single-key flow below.
    kv_lmove has two keys — a source and a destination — so it is
    audited by _audit_lmove instead."""
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
