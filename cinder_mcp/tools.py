"""Tool definitions for cinder-mcp.

Each tool maps to one cinder command. The schemas are plain JSON Schema
fragments, as the MCP spec requires for tools/list.
"""

TOOLS = [
    {
        "name": "kv_get",
        "description": "Get the string value of a key. Returns null when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_set",
        "description": "Set a key to a string value, optionally with a TTL in seconds (ex) or milliseconds (px).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
                "ex": {"type": "integer"},
                "px": {"type": "integer"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "kv_del",
        "description": "Delete a key. Returns 1 if the key existed, 0 otherwise.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_keys",
        "description": "List keys matching a glob pattern (* and ?). Defaults to all keys.",
        "inputSchema": {
            "type": "object",
            "properties": {"pattern": {"type": "string"}},
        },
    },
    {
        "name": "kv_incr",
        "description": "Increment the integer stored at a key by a given amount (default 1).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "by": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_ttl",
        "description": "Seconds until a key expires. -1 means no expiry, -2 means the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_exists",
        "description": "Check whether a key exists. Returns 1 if the key exists, 0 otherwise.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_expire",
        "description": "Set a key to expire after a number of seconds. Returns 1 if the timeout was set, 0 if the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "seconds": {"type": "integer"},
            },
            "required": ["key", "seconds"],
        },
    },
    {
        "name": "kv_batch",
        "description": "Run several kv operations in one call, in order, and get one summary back. Each op is an object with an \"op\" naming one of kv_get, kv_set, kv_del, kv_keys, kv_incr, kv_ttl, kv_exists or kv_expire plus that tool's arguments. Ops run sequentially and the batch keeps going past a failed op; each op's result or error is reported. Not atomic: cinder has no MULTI yet, so a batch is a convenience round-trip saver, not a transaction. At most 100 ops per call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "ops": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "op": {"type": "string"},
                            "key": {"type": "string"},
                            "value": {"type": "string"},
                            "ex": {"type": "integer"},
                            "px": {"type": "integer"},
                            "by": {"type": "integer"},
                            "seconds": {"type": "integer"},
                            "pattern": {"type": "string"},
                        },
                        "required": ["op"],
                    },
                },
            },
            "required": ["ops"],
        },
    },
]


def _format_ms(ms):
    """A budget threshold as short text: 100, not 100.0; 0.002 as-is."""
    return str(int(ms)) if float(ms).is_integer() else "%.3f" % ms


def tools_with_budgets(metrics):
    """The tool list for tools/list, with each tool's latency budget
    advertised in its description, so a client sees the budget before
    calling instead of discovering it from a warning. Budgets come
    from the given metrics object, so per-tool env overrides are
    honoured. The TOOLS definitions themselves are not mutated."""
    listed = []
    for tool in TOOLS:
        warn_ms, slow_ms = metrics.budget_for(tool["name"])
        advertised = dict(tool)
        advertised["description"] = (
            "%s Latency budget: warn >%sms, slow >%sms."
            % (
                tool["description"],
                _format_ms(warn_ms),
                _format_ms(slow_ms),
            )
        )
        listed.append(advertised)
    return listed


def _require(args, field):
    if field not in args or args[field] is None:
        raise ValueError("missing required argument: %s" % field)
    return args[field]


def call_tool(client, name, args):
    """Run one tool against cinder. Returns a plain value for the result text."""
    args = args or {}
    if name == "kv_batch":
        return _call_batch(client, args)
    return _call_single(client, name, args)


# Ops a batch may contain: the single-key tools, not kv_batch itself
# (no nesting — a batch inside a batch buys nothing and complicates
# the summary).
BATCHABLE_TOOLS = {
    "kv_get", "kv_set", "kv_del", "kv_keys",
    "kv_incr", "kv_ttl", "kv_exists", "kv_expire",
}

MAX_BATCH_OPS = 100


def _call_batch(client, args):
    """Run several kv ops in order and return one summary.

    Ops run sequentially against cinder; a failed op is recorded in
    place and the batch keeps going, so one bad op never discards
    the rest. The summary is {"results": [...], "ok": n, "failed": m}
    where each result is {"op": ..., "ok": true, "result": ...} or
    {"op": ..., "ok": false, "error": ...}. Not atomic: cinder has
    no MULTI yet, so this is a round-trip saver, not a transaction.
    Batch-level problems (ops missing, not a list, empty, over the
    cap) raise ValueError and fail the whole call."""
    ops = args.get("ops")
    if not isinstance(ops, list):
        raise ValueError("kv_batch requires ops to be a list")
    if not ops:
        raise ValueError("kv_batch requires at least one op")
    if len(ops) > MAX_BATCH_OPS:
        raise ValueError(
            "kv_batch accepts at most %d ops, got %d" % (MAX_BATCH_OPS, len(ops))
        )
    results = []
    ok_count = 0
    for op in ops:
        if not isinstance(op, dict) or not isinstance(op.get("op"), str):
            results.append(
                {"op": None, "ok": False, "error": "each op needs an op name"}
            )
            continue
        op_name = op["op"]
        if op_name not in BATCHABLE_TOOLS:
            results.append(
                {"op": op_name, "ok": False,
                 "error": "unknown or unbatchable op: %s" % op_name}
            )
            continue
        try:
            value = _call_single(client, op_name, op)
        except Exception as exc:
            results.append({"op": op_name, "ok": False, "error": str(exc)})
            continue
        results.append({"op": op_name, "ok": True, "result": value})
        ok_count += 1
    return {
        "results": results,
        "ok": ok_count,
        "failed": len(results) - ok_count,
    }


def _call_single(client, name, args):
    if name == "kv_get":
        return client.command("GET", _require(args, "key"))
    if name == "kv_set":
        cmd = ["SET", _require(args, "key"), _require(args, "value")]
        if args.get("ex") is not None:
            cmd += ["EX", args["ex"]]
        if args.get("px") is not None:
            cmd += ["PX", args["px"]]
        return client.command(*cmd)
    if name == "kv_del":
        return client.command("DEL", _require(args, "key"))
    if name == "kv_keys":
        return client.command("KEYS", args.get("pattern", "*"))
    if name == "kv_incr":
        by = args.get("by", 1)
        if by == 1:
            return client.command("INCR", _require(args, "key"))
        return client.command("INCRBY", _require(args, "key"), by)
    if name == "kv_ttl":
        return client.command("TTL", _require(args, "key"))
    if name == "kv_exists":
        return client.command("EXISTS", _require(args, "key"))
    if name == "kv_expire":
        return client.command(
            "EXPIRE", _require(args, "key"), _require(args, "seconds")
        )
    raise ValueError("unknown tool: %s" % name)
