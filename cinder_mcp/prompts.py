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
keys with no expiry that the operator should act on.
"""

from .resp import RespError

# A string sample longer than this is truncated in the prompt text.
MAX_SAMPLE_CHARS = 200

# At most this many related keys are listed in the prompt text.
MAX_RELATED_KEYS = 20

# At most this many soonest-expiring keys are listed in the ttl-audit.
MAX_SOON_KEYS = 10

# At most this many no-expiry keys are listed in the ttl-audit.
MAX_NO_EXPIRY_KEYS = 20

# TTL bucket boundaries, in seconds: under 1 hour, under 1 day,
# under 1 week, over 1 week. Keys with TTL -1 have no expiry.
BUCKET_BOUNDS = (3600, 86400, 604800)

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


def _key_deep_dive(client, arguments):
    """One key in detail: type, TTL, size, a sample of its value, and
    the keys that share its namespace. Cinder has no TYPE command, so
    the type is probed the same way the per-key resource does: GET
    succeeds for strings, otherwise LLEN / SCARD / HLEN are tried in
    turn and the first one that does not answer WRONGTYPE names it."""
    key = arguments.get("key")
    if not key:
        raise ValueError("key-deep-dive requires a key argument")
    if client.command("EXISTS", key) == 0:
        raise ValueError("key not found: %s" % key)
    ttl = client.command("TTL", key)
    try:
        value = client.command("GET", key)
    except RespError:
        # Not a string: probe the container types.
        kind = None
        length = None
        for probe, name in (("LLEN", "list"), ("SCARD", "set"), ("HLEN", "hash")):
            try:
                length = client.command(probe, key)
            except RespError:
                continue
            kind = name
            break
        if kind is None:
            raise ValueError("key has an unreadable type: %s" % key)
        size = "%d elements" % length
        sample = None
    else:
        if value is None:
            # The key expired between EXISTS and GET.
            raise ValueError("key not found: %s" % key)
        kind = "string"
        size = "%d bytes" % len(value.encode("utf-8"))
        sample = value
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
    """Scan the keyspace, group every key by how soon it expires, and
    list the soonest-expiring keys and the keys with no expiry so the
    operator can act on them. TTL is probed per key with TTL: -1 means
    no expiry, -2 means the key expired between the KEYS scan and the
    TTL probe and is counted separately rather than bucketed."""
    pattern = arguments.get("pattern", "*")
    keys = client.command("KEYS", pattern)
    if keys is None:
        keys = []
    buckets = {
        "no expiry": [],
        "expiring in under 1 hour": [],
        "expiring in under 1 day": [],
        "expiring in under 1 week": [],
        "expiring in over 1 week": [],
    }
    expired = 0
    soonest = []  # (ttl, key), sorted ascending at the end
    for key in keys:
        ttl = client.command("TTL", key)
        if ttl == -2:
            expired += 1
        elif ttl == -1:
            buckets["no expiry"].append(key)
        elif ttl < BUCKET_BOUNDS[0]:
            buckets["expiring in under 1 hour"].append(key)
            soonest.append((ttl, key))
        elif ttl < BUCKET_BOUNDS[1]:
            buckets["expiring in under 1 day"].append(key)
            soonest.append((ttl, key))
        elif ttl < BUCKET_BOUNDS[2]:
            buckets["expiring in under 1 week"].append(key)
            soonest.append((ttl, key))
        else:
            buckets["expiring in over 1 week"].append(key)
            soonest.append((ttl, key))
    soonest.sort()
    no_expiry = sorted(buckets["no expiry"])
    lines = [
        "TTL audit of the cinder keyspace (pattern %r)." % pattern,
        "",
        "Total keys scanned: %d" % len(keys),
    ]
    if expired:
        lines.append(
            "%d key(s) expired while scanning and were not bucketed."
            % expired
        )
    lines.extend(["", "TTL buckets:"])
    for label, members in buckets.items():
        lines.append("- %s: %d" % (label, len(members)))
    lines.extend(["", "Soonest expiring keys (%d):" % len(soonest)])
    if soonest:
        for ttl, key in soonest[:MAX_SOON_KEYS]:
            lines.append("- %s (in %s)" % (key, _format_ttl(ttl)))
        if len(soonest) > MAX_SOON_KEYS:
            lines.append("... and %d more" % (len(soonest) - MAX_SOON_KEYS))
    else:
        lines.append("(none expiring)")
    lines.extend(["", "Keys with no expiry (%d):" % len(no_expiry)])
    if no_expiry:
        for key in no_expiry[:MAX_NO_EXPIRY_KEYS]:
            lines.append("- %s" % key)
        if len(no_expiry) > MAX_NO_EXPIRY_KEYS:
            lines.append("... and %d more" % (len(no_expiry) - MAX_NO_EXPIRY_KEYS))
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
