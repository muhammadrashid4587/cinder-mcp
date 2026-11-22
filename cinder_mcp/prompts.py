"""Prompt definitions for cinder-mcp.

Prompts are reusable starting points an MCP client can fetch: the
server fills them with live data from cinder and hands the client a
ready-to-send message. keyspace-summary samples cinder's INFO output
and lists the keys matching a pattern, then asks the model to check
what looks off: keys with no expiry, keys that should not be there,
and keys worth reading in full. key-deep-dive inspects one key in
detail — its type, TTL, size, a sample of its value, and the keys
related to it — and asks the model to judge whether that one key
looks healthy.
"""

from .resp import RespError

# A string sample longer than this is truncated in the prompt text.
MAX_SAMPLE_CHARS = 200

# At most this many related keys are listed in the prompt text.
MAX_RELATED_KEYS = 20

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
