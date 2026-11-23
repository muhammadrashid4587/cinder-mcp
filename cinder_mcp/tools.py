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
        "name": "kv_hset",
        "description": "Set fields on a hash: HSET key field value [field value ...]. Takes `fields` as an object mapping field names to values. Returns the number of fields that were newly added (updating an existing field returns 0 for it).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "fields": {"type": "object"},
            },
            "required": ["key", "fields"],
        },
    },
    {
        "name": "kv_hget",
        "description": "Get one field of a hash. Returns null when the key or the field does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "field": {"type": "string"},
            },
            "required": ["key", "field"],
        },
    },
    {
        "name": "kv_hgetall",
        "description": "Get every field of a hash as an object mapping field names to values. Returns an empty object when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_zadd",
        "description": "Add members with scores to a sorted set: ZADD key [NX | XX | GT | LT | CH | INCR] score member [score member ...]. Takes `members` as an object mapping member names to scores. Returns the number of members that were newly added (updating an existing member's score returns 0 for it), or with ch=true the number of members added or updated. With nx=true only members not already present are added, with xx=true only members already present are updated, with gt=true an existing member's score only moves up, with lt=true it only moves down; nx cannot combine with xx, gt or lt, and gt cannot combine with lt. With incr=true exactly one member is given and the call returns that member's new score as a number (or null when the conditions rejected the update), like ZINCRBY.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "members": {"type": "object"},
                "nx": {"type": "boolean"},
                "xx": {"type": "boolean"},
                "gt": {"type": "boolean"},
                "lt": {"type": "boolean"},
                "ch": {"type": "boolean"},
                "incr": {"type": "boolean"},
            },
            "required": ["key", "members"],
        },
    },
    {
        "name": "kv_zrange",
        "description": "Members of a sorted set in an index range, lowest score first: ZRANGE key start stop [WITHSCORES]. Negative indices count from the end, as in Redis. Pass withscores=true for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names, and rev=true to read highest score first (ZREVRANGE). At most 1000 members per call; narrow the range for a larger set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "start": {"type": "integer"},
                "stop": {"type": "integer"},
                "withscores": {"type": "boolean"},
                "rev": {"type": "boolean"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zcard",
        "description": "The number of members in a sorted set: ZCARD key. Returns 0 when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_zscore",
        "description": "The score of one member of a sorted set: ZSCORE key member. Returns null when the key or the member does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "member": {"type": "string"},
            },
            "required": ["key", "member"],
        },
    },
    {
        "name": "kv_zrank",
        "description": "The rank of one member of a sorted set, lowest score first: ZRANK key member. Returns null when the key or the member does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "member": {"type": "string"},
            },
            "required": ["key", "member"],
        },
    },
    {
        "name": "kv_zrem",
        "description": "Remove members from a sorted set: ZREM key member [member ...]. Takes `members` as a list of member names. Returns the number of members actually removed.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "members": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["key", "members"],
        },
    },
    {
        "name": "kv_zincrby",
        "description": "Add to the score of one member of a sorted set: ZINCRBY key increment member. Creates the member with the increment as its score when it is not already present. Returns the member's new score as a number.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "increment": {"type": "number"},
                "member": {"type": "string"},
            },
            "required": ["key", "increment", "member"],
        },
    },
    {
        "name": "kv_batch",
        "description": "Run several kv operations in one call, in order, and get one summary back. Each op is an object with an \"op\" naming one of kv_get, kv_set, kv_del, kv_keys, kv_incr, kv_ttl, kv_exists, kv_expire, kv_hset, kv_hget, kv_hgetall, kv_zadd, kv_zrange, kv_zcard, kv_zscore, kv_zrank, kv_zrem or kv_zincrby plus that tool's arguments. Ops run sequentially and the batch keeps going past a failed op; each op's result or error is reported. At most 100 ops per call. Pass atomic=true to run the ops as one MULTI/EXEC transaction instead: they execute together with no other client interleaved, and an op that fails at EXEC time is recorded in place while the rest still run. An atomic batch only takes the single-command ops (kv_keys_scan cannot run inside a transaction); an op that cannot be queued fails the whole call before anything runs, so check the ops first.",
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
                            "field": {"type": "string"},
                            "fields": {"type": "object"},
                            "members": {"type": ["object", "array"]},
                            "member": {"type": "string"},
                            "increment": {"type": "number"},
                            "nx": {"type": "boolean"},
                            "xx": {"type": "boolean"},
                            "gt": {"type": "boolean"},
                            "lt": {"type": "boolean"},
                            "ch": {"type": "boolean"},
                            "incr": {"type": "boolean"},
                            "start": {"type": "integer"},
                            "stop": {"type": "integer"},
                            "withscores": {"type": "boolean"},
                            "rev": {"type": "boolean"},
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
    "kv_hset", "kv_hget", "kv_hgetall",
    "kv_zadd", "kv_zrange", "kv_zcard", "kv_zscore", "kv_zrank",
    "kv_zrem", "kv_zincrby",
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
    "kv_hset", "kv_hget", "kv_hgetall",
    "kv_zadd", "kv_zrange", "kv_zcard", "kv_zscore", "kv_zrank",
    "kv_zrem", "kv_zincrby",
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
        if op_name == "kv_zrange":
            # A range with a negative bound needs the set's size to
            # know how wide it is; check the bound before anything
            # is queued, like the standalone tool does.
            _check_zrange_window(client, op)
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
        elif op_name == "kv_hgetall":
            # HGETALL came back as a flat [field, value, ...] list
            # inside the transaction; shape it into a dict like the
            # standalone tool does.
            value = _hgetall_result(reply or [])
        elif op_name == "kv_zrange":
            # ZRANGE came back as a flat list inside the transaction;
            # shape it like the standalone tool does, including the
            # withscores member/score objects.
            value = _zrange_result(reply or [], _zrange_args(op)[3])
        elif op_name == "kv_zscore":
            # ZSCORE came back as a bulk score string (or nil) inside
            # the transaction; parse it like the standalone tool does.
            value = None if reply is None else float(reply)
        elif op_name == "kv_zincrby":
            # ZINCRBY came back as a bulk score string inside the
            # transaction; parse it like the standalone tool does.
            value = float(reply)
        elif op_name == "kv_zadd" and op.get("incr", False):
            # ZADD with INCR came back as a bulk score string (or
            # nil when the conditions rejected the update) instead
            # of an added count; parse it like the standalone tool.
            value = None if reply is None else float(reply)
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
    if name == "kv_hset":
        return ["HSET", _require(args, "key")] + _hset_field_args(args)
    if name == "kv_hget":
        return ["HGET", _require(args, "key"), _require(args, "field")]
    if name == "kv_hgetall":
        return ["HGETALL", _require(args, "key")]
    if name == "kv_zadd":
        return (["ZADD", _require(args, "key")] + _zadd_options(args)
                + _zadd_member_args(args))
    if name == "kv_zcard":
        return ["ZCARD", _require(args, "key")]
    if name == "kv_zscore":
        return ["ZSCORE", _require(args, "key"), _require(args, "member")]
    if name == "kv_zrank":
        return ["ZRANK", _require(args, "key"), _require(args, "member")]
    if name == "kv_zrem":
        return ["ZREM", _require(args, "key")] + _zrem_member_args(args)
    if name == "kv_zincrby":
        key, increment, member = _zincrby_args(args)
        return ["ZINCRBY", key, increment, member]
    if name == "kv_zrange":
        key, start, stop, withscores, rev = _zrange_args(args)
        # A range both ends of which are non-negative has a known
        # width; check the bound here. A negative bound needs the
        # set's size, which the caller checks with _check_zrange_window.
        if start >= 0 and stop >= 0 and stop - start + 1 > MAX_ZRANGE_MEMBERS:
            raise ValueError(
                "kv_zrange returns at most %d members; narrow the range"
                % MAX_ZRANGE_MEMBERS
            )
        cmd = ["ZREVRANGE" if rev else "ZRANGE", key, start, stop]
        if withscores:
            cmd.append("WITHSCORES")
        return cmd
    raise ValueError("unknown or unbatchable op: %s" % name)


def _hset_field_args(args):
    """The field/value pairs for an HSET, as a flat argv list.
    `fields` must be a non-empty object of string field names to
    string values; anything else fails the call instead of sending
    a half-formed HSET. Pairs are sent in sorted field order so the
    argv is deterministic."""
    fields = args.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise ValueError("kv_hset fields must be a non-empty object")
    argv = []
    for field in sorted(fields):
        value = fields[field]
        if not isinstance(field, str) or not isinstance(value, str):
            raise ValueError(
                "kv_hset fields must map string field names to string values"
            )
        argv += [field, value]
    return argv


def _hgetall_result(flat):
    """Shape a flat HGETALL reply [field, value, ...] into a dict.
    A missing key replies as an empty list, which becomes {}."""
    return {flat[i]: flat[i + 1] for i in range(0, len(flat), 2)}


# The most members one kv_zrange call returns; a wider range fails
# instead of dumping a huge sorted set into one tool result.
MAX_ZRANGE_MEMBERS = 1000


def _format_score(score):
    """One ZADD score as a RESP argument. Ints and floats both go
    through; repr round-trips a float exactly, and prints "inf" /
    "-inf" for infinities, which cinder's score parser accepts.
    NaN is rejected — cinder rejects it too — as is anything that
    is not a number."""
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError("kv_zadd scores must be numbers")
    if isinstance(score, float) and score != score:
        raise ValueError("kv_zadd scores must not be NaN")
    return repr(score)


def _zadd_options(args):
    """The ZADD option flags for a kv_zadd call, as argv tokens in
    cinder's order (NX | XX | GT | LT | CH | INCR, after the key and
    before the first score). Each flag must be a boolean when
    present. The combinations cinder rejects — NX with XX, GT or LT
    with NX, GT with LT — fail here as invalid params instead of as
    a server error, and INCR needs exactly one member, as in Redis.
    CH is ignored when INCR is set: cinder's INCR reply is the new
    score either way."""
    flags = {}
    opts = []
    for name in ("nx", "xx", "gt", "lt", "ch", "incr"):
        value = args.get(name, False)
        if not isinstance(value, bool):
            raise ValueError("kv_zadd %s must be true or false" % name)
        flags[name] = value
        if value:
            opts.append(name.upper())
    if flags["nx"] and flags["xx"]:
        raise ValueError("kv_zadd nx and xx cannot be used together")
    if flags["gt"] and flags["lt"]:
        raise ValueError("kv_zadd gt and lt cannot be used together")
    if flags["nx"] and (flags["gt"] or flags["lt"]):
        raise ValueError("kv_zadd nx cannot be used with gt or lt")
    if flags["incr"]:
        members = args.get("members")
        if isinstance(members, dict) and len(members) != 1:
            raise ValueError("kv_zadd incr takes exactly one member")
    return opts


def _zadd_member_args(args):
    """The score/member pairs for a ZADD, as a flat argv list.
    `members` must be a non-empty object of string member names to
    numeric scores; anything else fails the call instead of sending
    a half-formed ZADD. Pairs are sent in sorted member order so the
    argv is deterministic."""
    members = args.get("members")
    if not isinstance(members, dict) or not members:
        raise ValueError("kv_zadd members must be a non-empty object")
    argv = []
    for member in sorted(members):
        if not isinstance(member, str):
            raise ValueError(
                "kv_zadd members must map string member names to scores"
            )
        argv += [_format_score(members[member]), member]
    return argv


def _zrem_member_args(args):
    """The member names for a ZREM, as an argv list. `members` must
    be a non-empty list of strings; anything else fails the call
    instead of sending a half-formed ZREM."""
    members = args.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("kv_zrem members must be a non-empty list")
    for member in members:
        if not isinstance(member, str):
            raise ValueError("kv_zrem members must be strings")
    return list(members)


def _zincrby_args(args):
    """Validate a kv_zincrby call: (key, increment, member). The
    increment must be a number (NaN is rejected — cinder rejects
    it too); it is formatted with repr so a float round-trips
    exactly, like a ZADD score."""
    key = _require(args, "key")
    increment = _require(args, "increment")
    member = _require(args, "member")
    if isinstance(increment, bool) or not isinstance(increment, (int, float)):
        raise ValueError("kv_zincrby increment must be a number")
    if isinstance(increment, float) and increment != increment:
        raise ValueError("kv_zincrby increment must not be NaN")
    return key, repr(increment), member


def _zrange_args(args):
    """Validate a kv_zrange call: (key, start, stop, withscores, rev).
    start defaults to 0 and stop to -1, as in Redis; withscores and
    rev default to false. Bad types fail the call instead of sending
    a half-formed ZRANGE."""
    key = _require(args, "key")
    start = args.get("start", 0)
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("kv_zrange start must be an integer")
    stop = args.get("stop", -1)
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError("kv_zrange stop must be an integer")
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zrange withscores must be true or false")
    rev = args.get("rev", False)
    if not isinstance(rev, bool):
        raise ValueError("kv_zrange rev must be true or false")
    return key, start, stop, withscores, rev


def _zrange_window(start, stop, length):
    """How many members a [start, stop] range covers in a sorted set
    of `length` members, resolving negative indices the way Redis
    does: -1 is the last member. Returns 0 for an empty range."""
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


def _check_zrange_window(client, args):
    """Fail a kv_zrange call whose range would return more than
    MAX_ZRANGE_MEMBERS members. A range with a negative bound needs
    the set's size first, so it reads ZCARD; a range both ends of
    which are non-negative is checked without a round trip. A missing
    key has size 0, so the check passes and the range returns []."""
    key, start, stop, _, _ = _zrange_args(args)
    if start >= 0 and stop >= 0:
        window = stop - start + 1
    else:
        window = _zrange_window(start, stop, client.command("ZCARD", key) or 0)
    if window > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zrange returns at most %d members; narrow the range"
            % MAX_ZRANGE_MEMBERS
        )


def _zrange_result(flat, withscores):
    """Shape a flat ZRANGE reply into the tool's return value: a list
    of member names, or with withscores a list of {"member": ...,
    "score": ...} objects, the scores parsed as numbers. A missing
    key replies as an empty list, which becomes []."""
    flat = flat or []
    if not withscores:
        return list(flat)
    return [
        {"member": flat[i], "score": float(flat[i + 1])}
        for i in range(0, len(flat), 2)
    ]


def _call_zadd(client, args):
    """kv_zadd: plain form returns the number of newly added members
    (or added+updated with ch); with incr=true it returns the new
    score of the single member as a number, or null when the
    conditions rejected the update."""
    reply = client.command(*_op_argv("kv_zadd", args))
    if args.get("incr", False):
        return None if reply is None else float(reply)
    return reply


def _call_zscore(client, args):
    """kv_zscore: the member's score as a number, or null when the
    key or the member does not exist (cinder replies nil)."""
    reply = client.command(*_op_argv("kv_zscore", args))
    return None if reply is None else float(reply)


def _call_zincrby(client, args):
    """kv_zincrby: the member's new score as a number. Cinder
    replies with the score as a bulk string."""
    return float(client.command(*_op_argv("kv_zincrby", args)))


def _call_zrange(client, args):
    """kv_zrange: bound the range first (see _check_zrange_window),
    then run ZRANGE or ZREVRANGE and shape the reply."""
    _check_zrange_window(client, args)
    return _zrange_result(
        client.command(*_op_argv("kv_zrange", args)) or [],
        _zrange_args(args)[3],
    )


def _call_single(client, name, args):
    if name == "kv_keys":
        return _call_keys(client, args)
    if name == "kv_keys_scan":
        return _call_keys_scan(client, args)
    if name == "kv_hgetall":
        return _hgetall_result(
            client.command("HGETALL", _require(args, "key")) or []
        )
    if name == "kv_zadd":
        return _call_zadd(client, args)
    if name == "kv_zscore":
        return _call_zscore(client, args)
    if name == "kv_zincrby":
        return _call_zincrby(client, args)
    if name == "kv_zrange":
        return _call_zrange(client, args)
    return client.command(*_op_argv(name, args))
