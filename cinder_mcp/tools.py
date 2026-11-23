"""Tool definitions for cinder-mcp.

Each tool maps to one cinder command. The schemas are plain JSON Schema
fragments, as the MCP spec requires for tools/list.
"""

import hashlib

from .resp import RespError
from .scan import (
    DEFAULT_SCAN_BATCH_SIZE,
    scan_batch,
)

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
        "description": "List keys matching a glob pattern (* and ?). Defaults to all keys. Returns {\"keys\": [...], \"total\": n, \"returned\": m, \"sampled\": bool}: at most `limit` keys (default 100) are returned, and when the keyspace is larger than that the returned keys are a deterministic sample seeded by `seed`, so the same call always returns the same sample. Pass full=true to get the whole list instead.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "limit": {"type": "integer"},
                "full": {"type": "boolean"},
                "seed": {"type": "string"},
            },
        },
    },
    {
        "name": "kv_keys_scan",
        "description": "Walk the keys matching a glob pattern (* and ?) one bounded page at a time, SCAN-style. Returns {\"keys\": [...], \"cursor\": str, \"done\": bool, \"batch_size\": n}: at most `batch_size` keys per page (default 100). Pass the returned `cursor` back to fetch the next page; pass \"\" (or omit it) to start. When `done` is true the cursor is \"\" and the walk is finished. Pages are in sorted key order; keys added after the cursor are picked up later, keys deleted or renamed between pages can shift the window, the same caveats real SCAN has.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string"},
                "batch_size": {"type": "integer"},
                "cursor": {"type": "string"},
            },
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
        "description": "Run several kv operations in one call, in order, and get one summary back. Each op is an object with an \"op\" naming one of kv_get, kv_set, kv_del, kv_keys, kv_incr, kv_ttl, kv_exists or kv_expire plus that tool's arguments. Ops run sequentially and the batch keeps going past a failed op; each op's result or error is reported. At most 100 ops per call. Pass atomic=true to run the ops as one MULTI/EXEC transaction instead: they execute together with no other client interleaved, and an op that fails at EXEC time is recorded in place while the rest still run. An atomic batch only takes the single-command ops (kv_keys_scan cannot run inside a transaction); an op that cannot be queued fails the whole call before anything runs, so check the ops first.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "atomic": {"type": "boolean"},
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
                            "limit": {"type": "integer"},
                            "full": {"type": "boolean"},
                            "seed": {"type": "string"},
                            "batch_size": {"type": "integer"},
                            "cursor": {"type": "string"},
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
    "kv_get", "kv_set", "kv_del", "kv_keys", "kv_keys_scan",
    "kv_incr", "kv_ttl", "kv_exists", "kv_expire",
}

MAX_BATCH_OPS = 100


def _call_batch(client, args):
    """Run several kv ops in order and return one summary.

    Ops run sequentially against cinder; a failed op is recorded in
    place and the batch keeps going, so one bad op never discards
    the rest. The summary is {"results": [...], "ok": n, "failed": m,
    "atomic": bool} where each result is {"op": ..., "ok": true,
    "result": ...} or {"op": ..., "ok": false, "error": ...}.
    Batch-level problems (ops missing, not a list, empty, over the
    cap) raise ValueError and fail the whole call. With
    atomic=true the ops run as one MULTI/EXEC transaction instead;
    see _call_batch_atomic."""
    ops = args.get("ops")
    if not isinstance(ops, list):
        raise ValueError("kv_batch requires ops to be a list")
    if not ops:
        raise ValueError("kv_batch requires at least one op")
    if len(ops) > MAX_BATCH_OPS:
        raise ValueError(
            "kv_batch accepts at most %d ops, got %d" % (MAX_BATCH_OPS, len(ops))
        )
    atomic = args.get("atomic", False)
    if not isinstance(atomic, bool):
        raise ValueError("kv_batch atomic must be true or false")
    if atomic:
        return _call_batch_atomic(client, ops)
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
        "atomic": False,
    }


# Ops an atomic batch may contain: the single-command tools, not
# kv_keys_scan — its cursor walk re-runs KEYS between pages, which
# cannot happen inside a transaction — and not kv_batch itself.
ATOMIC_BATCHABLE_TOOLS = {
    "kv_get", "kv_set", "kv_del", "kv_keys",
    "kv_incr", "kv_ttl", "kv_exists", "kv_expire",
}


def _call_batch_atomic(client, ops):
    """Run the ops as one MULTI/EXEC transaction and return the same
    summary shape as the plain batch, with "atomic": true.

    Every op is turned into its argv and validated before anything
    is sent, so an op that cannot be queued (unknown name,
    kv_keys_scan, a missing required argument) fails the whole call
    up front and nothing runs. Once queued, the ops execute together
    with no other client interleaved; an op that fails at EXEC time
    (INCR on a non-integer, EXPIRE with a bad time) is recorded in
    place as an error while the rest still run, exactly as cinder's
    EXEC reports it."""
    argv_list = []
    for op in ops:
        if not isinstance(op, dict) or not isinstance(op.get("op"), str):
            raise ValueError(
                "atomic kv_batch: each op needs an op name")
        op_name = op["op"]
        if op_name not in ATOMIC_BATCHABLE_TOOLS:
            raise ValueError(
                "atomic kv_batch: op cannot run in a transaction: %s"
                % op_name
            )
        argv_list.append(_op_argv(op_name, op))
    replies = client.transaction(argv_list)
    results = []
    ok_count = 0
    for op, reply in zip(ops, replies):
        op_name = op["op"]
        if isinstance(reply, RespError):
            results.append(
                {"op": op_name, "ok": False, "error": str(reply)})
            continue
        if op_name == "kv_keys":
            # KEYS came back as a raw list inside the transaction;
            # apply the same sampling the standalone tool does.
            value = _keys_result(reply or [], op)
        else:
            value = reply
        results.append({"op": op_name, "ok": True, "result": value})
        ok_count += 1
    return {
        "results": results,
        "ok": ok_count,
        "failed": len(results) - ok_count,
        "atomic": True,
    }


# The default cap on keys kv_keys returns; larger keyspaces are sampled.
DEFAULT_KEY_LIMIT = 100

# The largest limit a caller may ask for; above this, ask for the full
# list explicitly with full=true instead of pretending a sample is one.
MAX_KEY_LIMIT = 10000


def sample_keys(keys, limit, seed=""):
    """A deterministic sample of `keys`: order them by the SHA-256 of
    "seed:key" and take the first `limit`, then sort the sample
    alphabetically so it reads in key order. The same keyspace and seed
    always yield the same sample; a different seed yields a different
    one. Nothing is random here — no RNG, no wall clock — so the sample
    is stable across calls, restarts, and machines."""
    ranked = sorted(
        keys,
        key=lambda k: hashlib.sha256(("%s:%s" % (seed, k)).encode()).hexdigest(),
    )
    return sorted(ranked[:limit])


def _keys_result(keys, args):
    """The kv_keys return shape for a fetched key list: {"keys": [...],
    "total": n, "returned": m, "sampled": bool}. Small keyspaces come
    back whole (sampled false); a keyspace larger than `limit`
    (default 100) comes back as a deterministic seeded sample;
    full=true returns the whole list whatever its size. Bad limit/full/
    seed values fail the call instead of silently ignoring the caller."""
    full = args.get("full", False)
    if not isinstance(full, bool):
        raise ValueError("kv_keys full must be true or false")
    limit = args.get("limit", DEFAULT_KEY_LIMIT)
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise ValueError("kv_keys limit must be an integer")
    if limit < 1 or limit > MAX_KEY_LIMIT:
        raise ValueError(
            "kv_keys limit must be between 1 and %d" % MAX_KEY_LIMIT
        )
    seed = args.get("seed", "")
    if not isinstance(seed, str):
        raise ValueError("kv_keys seed must be a string")
    total = len(keys)
    if full or total <= limit:
        return {
            "keys": sorted(keys),
            "total": total,
            "returned": total,
            "sampled": False,
        }
    sampled = sample_keys(keys, limit, seed)
    return {
        "keys": sampled,
        "total": total,
        "returned": len(sampled),
        "sampled": True,
    }


def _call_keys(client, args):
    """kv_keys: KEYS, then bound the listing (see _keys_result)."""
    keys = client.command("KEYS", args.get("pattern", "*")) or []
    return _keys_result(keys, args)


def _call_keys_scan(client, args):
    """kv_keys_scan: one bounded page of the keyspace. Returns
    {"keys": [...], "cursor": str, "done": bool, "batch_size": n}.
    Bad batch_size/cursor values fail the call instead of silently
    ignoring the caller."""
    return scan_batch(
        client,
        args.get("pattern", "*"),
        args.get("cursor", ""),
        args.get("batch_size", DEFAULT_SCAN_BATCH_SIZE),
    )


def _op_argv(name, args):
    """One batchable op as a RESP argv list, for queuing inside a
    transaction. Raises ValueError on a missing required argument,
    and on kv_keys_scan, whose cursor walk cannot run inside MULTI.
    kv_keys validates its limit/full/seed here too, so a bad sampling
    argument fails an atomic batch up front instead of after EXEC."""
    if name == "kv_get":
        return ["GET", _require(args, "key")]
    if name == "kv_set":
        cmd = ["SET", _require(args, "key"), _require(args, "value")]
        if args.get("ex") is not None:
            cmd += ["EX", args["ex"]]
        if args.get("px") is not None:
            cmd += ["PX", args["px"]]
        return cmd
    if name == "kv_del":
        return ["DEL", _require(args, "key")]
    if name == "kv_keys":
        # Validate the sampling arguments now; the list itself is
        # sampled from the EXEC reply by _keys_result.
        _keys_result([], args)
        return ["KEYS", args.get("pattern", "*")]
    if name == "kv_incr":
        by = args.get("by", 1)
        if by == 1:
            return ["INCR", _require(args, "key")]
        return ["INCRBY", _require(args, "key"), by]
    if name == "kv_ttl":
        return ["TTL", _require(args, "key")]
    if name == "kv_exists":
        return ["EXISTS", _require(args, "key")]
    if name == "kv_expire":
        return ["EXPIRE", _require(args, "key"), _require(args, "seconds")]
    raise ValueError("unknown or unbatchable op: %s" % name)


def _call_single(client, name, args):
    if name == "kv_keys":
        return _call_keys(client, args)
    if name == "kv_keys_scan":
        return _call_keys_scan(client, args)
    return client.command(*_op_argv(name, args))
