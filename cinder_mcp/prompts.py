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
calls.
"""

import bisect

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
    Returns (kind, size_text, sample) where sample is the string value
    for string keys and None for containers. Cinder has no TYPE
    command, so the type is probed the same way the per-key resource
    does: GET succeeds for strings, otherwise LLEN / SCARD / HLEN are
    tried in turn and the first one that does not answer WRONGTYPE
    names it."""
    try:
        value = client.command("GET", key)
    except RespError:
        # Not a string: probe the container types.
        for probe, name in (("LLEN", "list"), ("SCARD", "set"), ("HLEN", "hash")):
            try:
                length = client.command(probe, key)
            except RespError:
                continue
            return name, "%d elements" % length, None
        raise ValueError("key has an unreadable type: %s" % key)
    if value is None:
        # The key expired between EXISTS and GET, or was deleted.
        raise ValueError("key not found: %s" % key)
    return "string", "%d bytes" % len(value.encode("utf-8")), value


def _key_deep_dive(client, arguments):
    """One key in detail: type, TTL, size, a sample of its value, and
    the keys that share its namespace."""
    key = arguments.get("key")
    if not key:
        raise ValueError("key-deep-dive requires a key argument")
    if client.command("EXISTS", key) == 0:
        raise ValueError("key not found: %s" % key)
    ttl = client.command("TTL", key)
    kind, size, sample = _inspect_key(client, key)
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
    between the KEYS scan and the TTL probe and is counted
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
    plan. Keys that expire between the KEYS scan and the TTL probe
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
                kind, size, _sample = _inspect_key(client, key)
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
