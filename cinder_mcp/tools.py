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
        "description": "Walk the keys matching a glob pattern (* and ?) one bounded page at a time with cinder's real SCAN. Returns {\"keys\": [...], \"cursor\": str, \"done\": bool, \"batch_size\": n}: about `batch_size` keys per page (default 100) — COUNT is a hint to cinder, so a page can run a few keys over when several matches share one hash bucket. Pass the returned `cursor` back to fetch the next page; pass \"\" (or omit it) to start. When `done` is true the cursor is \"\" and the walk is finished. The cursor is opaque: pass it back verbatim, do not read meaning into it. Pages are in SCAN order, not sorted; keys added after the cursor are picked up later, keys deleted or renamed between pages can shift the window, and a key can come back twice if the table resizes mid-walk, the same caveats real SCAN has.",
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
        "name": "kv_pttl",
        "description": "Milliseconds until a key expires. -1 means no expiry, -2 means the key does not exist.",
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
        "name": "kv_pexpire",
        "description": "Set a key to expire after a number of milliseconds. Returns 1 if the timeout was set, 0 if the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "milliseconds": {"type": "integer"},
            },
            "required": ["key", "milliseconds"],
        },
    },
    {
        "name": "kv_mget",
        "description": "Get the string values of several keys at once: MGET key [key ...]. Takes `keys` as a list of key names. Returns the values in the same order, with null for a key that does not exist — and for a key holding a non-string, which is real Redis behaviour: unlike kv_get, MGET does not fail on a wrong type. At most 1000 keys per call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["keys"],
        },
    },
    {
        "name": "kv_mset",
        "description": "Set several keys to string values at once: MSET key value [key value ...]. Takes `values` as an object mapping key names to values. Returns \"OK\". Overwrites any type, as in Redis, and a key given twice takes the last value.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "values": {"type": "object"},
            },
            "required": ["values"],
        },
    },
    {
        "name": "kv_getdel",
        "description": "Get the string value of a key and delete it: GETDEL key. Returns the old value, or null when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_setnx",
        "description": "Set a key to a string value only if it does not already exist: SETNX key value. Returns 1 if the key was set, 0 if it already existed — whatever it holds, a list or hash counts as existing too.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
        },
    },
    {
        "name": "kv_setex",
        "description": "Set a key to a string value with a TTL in seconds: SETEX key seconds value. Returns \"OK\". The seconds must be more than 0; overwrites any type, like a plain SET.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "seconds": {"type": "integer"},
                "value": {"type": "string"},
            },
            "required": ["key", "seconds", "value"],
        },
    },
    {
        "name": "kv_getset",
        "description": "Set a key to a string value and return its old value: GETSET key value. Returns the old value, or null when the key did not exist. Clears the key's TTL, like a plain SET.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key", "value"],
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
        "name": "kv_hdel",
        "description": "Remove fields from a hash: HDEL key field [field ...]. Takes `fields` as a list of field names. Returns the number of fields actually removed (removing a field that is not present counts 0). Removing the last field deletes the key, as in Redis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "fields": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["key", "fields"],
        },
    },
    {
        "name": "kv_hexists",
        "description": "Test whether a field exists in a hash: HEXISTS key field. Returns 1 if the field is present, 0 if it is not or the key does not exist.",
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
        "name": "kv_hlen",
        "description": "The number of fields in a hash: HLEN key. Returns 0 when the key does not exist.",
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
        "name": "kv_zrangebyscore",
        "description": "Members of a sorted set whose scores fall in a range, lowest score first: ZRANGEBYSCORE key min max [WITHSCORES] [LIMIT offset count]. `min` and `max` default to -inf and +inf; pass a number or a string like \"5\", \"(5\" for an exclusive bound, \"-inf\" or \"+inf\". Pass withscores=true for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names, and rev=true to read highest score first (ZREVRANGEBYSCORE, bounds still given min then max). Pass offset/count to page through the matches (count defaults to all); at most 1000 members per call, so narrow the range or pass a smaller count for a larger set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "min": {"type": ["number", "string"]},
                "max": {"type": ["number", "string"]},
                "withscores": {"type": "boolean"},
                "rev": {"type": "boolean"},
                "offset": {"type": "integer"},
                "count": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zcount",
        "description": "The number of members of a sorted set whose scores fall in a range: cinder has no ZCOUNT, so this counts by fetching the range with ZRANGEBYSCORE key min max and counting the members it returns. `min` and `max` default to -inf and +inf; pass a number or a string like \"5\", \"(5\" for an exclusive bound, \"-inf\" or \"+inf\". At most 1000 members per call, so a range holding more than that fails instead of returning a silently truncated count — narrow the range for a larger set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "min": {"type": ["number", "string"]},
                "max": {"type": ["number", "string"]},
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
        "name": "kv_zrevrank",
        "description": "The rank of one member of a sorted set, highest score first: cinder has no ZREVRANK, so this reads ZRANK key member and ZCARD key and returns ZCARD - 1 - ZRANK. Returns null when the key or the member does not exist.",
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
        "name": "kv_lpush",
        "description": "Push elements onto the head of a list: LPUSH key element [element ...]. Takes `elements` as a list of strings. Returns the length of the list after the push; several elements at once are pushed left one at a time, so the last element ends up at the head. Creates the list when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "elements": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["key", "elements"],
        },
    },
    {
        "name": "kv_rpush",
        "description": "Push elements onto the tail of a list: RPUSH key element [element ...]. Takes `elements` as a list of strings. Returns the length of the list after the push; several elements at once are appended in order. Creates the list when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "elements": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["key", "elements"],
        },
    },
    {
        "name": "kv_lrange",
        "description": "Elements of a list in an index range: LRANGE key start stop. Negative indices count from the end, as in Redis. start defaults to 0 and stop to -1. At most 1000 elements per call; narrow the range for a longer list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "start": {"type": "integer"},
                "stop": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_llen",
        "description": "The length of a list: LLEN key. Returns 0 when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_lpop",
        "description": "Remove and return the first element of a list: LPOP key. Returns null when the key does not exist or the list is empty; popping the last element deletes the key, as in Redis. Cinder has no LPOP count argument — one element at a time.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_rpop",
        "description": "Remove and return the last element of a list: RPOP key. Returns null when the key does not exist or the list is empty; popping the last element deletes the key, as in Redis. Cinder has no RPOP count argument — one element at a time.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_sadd",
        "description": "Add members to a set: SADD key member [member ...]. Takes `members` as a list of member names. Returns the number of members that were newly added (adding a member already present returns 0 for it). Creates the set when the key does not exist.",
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
        "name": "kv_smembers",
        "description": "The members of a set: SMEMBERS key. Returns the members in cinder's order. At most 1000 members per call; a larger set fails instead of returning a silently truncated list.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_scard",
        "description": "The number of members in a set: SCARD key. Returns 0 when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_srem",
        "description": "Remove members from a set: SREM key member [member ...]. Takes `members` as a list of member names. Returns the number of members actually removed (removing a member that is not present counts 0). Removing the last member deletes the key, as in Redis.",
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
        "name": "kv_sismember",
        "description": "Test whether a value is a member of a set: SISMEMBER key member. Returns 1 if the member is present, 0 if it is not or the key does not exist.",
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
        "name": "kv_batch",
        "description": "Run several kv operations in one call, in order, and get one summary back. Each op is an object with an \"op\" naming one of kv_get, kv_set, kv_del, kv_keys, kv_incr, kv_ttl, kv_pttl, kv_exists, kv_expire, kv_pexpire, kv_mget, kv_mset, kv_getdel, kv_setnx, kv_setex, kv_getset, kv_hset, kv_hget, kv_hgetall, kv_hdel, kv_hexists, kv_hlen, kv_zadd, kv_zrange, kv_zrangebyscore, kv_zcount, kv_zcard, kv_zscore, kv_zrank, kv_zrevrank, kv_zrem, kv_zincrby, kv_lpush, kv_rpush, kv_lrange, kv_llen, kv_lpop, kv_rpop, kv_sadd, kv_smembers, kv_scard, kv_srem or kv_sismember plus that tool's arguments. Ops run sequentially and the batch keeps going past a failed op; each op's result or error is reported. At most 100 ops per call. Pass atomic=true to run the ops as one MULTI/EXEC transaction instead: they execute together with no other client interleaved, and an op that fails at EXEC time is recorded in place while the rest still run. An atomic batch only takes the single-command ops (kv_keys_scan cannot run inside a transaction); an op that cannot be queued fails the whole call before anything runs, so check the ops first.",
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
                            "milliseconds": {"type": "integer"},
                            "keys": {"type": "array", "items": {"type": "string"}},
                            "values": {"type": "object"},
                            "field": {"type": "string"},
                            # `fields` is an object for kv_hset and a list
                            # of field names for kv_hdel.
                            "fields": {"type": ["object", "array"]},
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
                            "min": {"type": ["number", "string"]},
                            "max": {"type": ["number", "string"]},
                            "offset": {"type": "integer"},
                            "count": {"type": "integer"},
                            "withscores": {"type": "boolean"},
                            "rev": {"type": "boolean"},
                            "pattern": {"type": "string"},
                            "limit": {"type": "integer"},
                            "full": {"type": "boolean"},
                            "seed": {"type": "string"},
                            "elements": {"type": "array", "items": {"type": "string"}},
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
    "kv_incr", "kv_ttl", "kv_pttl", "kv_exists", "kv_expire", "kv_pexpire",
    "kv_mget", "kv_mset", "kv_getdel", "kv_setnx", "kv_setex", "kv_getset",
    "kv_hset", "kv_hget", "kv_hgetall", "kv_hdel", "kv_hexists", "kv_hlen",
    "kv_zadd", "kv_zrange", "kv_zrangebyscore", "kv_zcount", "kv_zcard",
    "kv_zscore", "kv_zrank", "kv_zrevrank", "kv_zrem", "kv_zincrby",
    "kv_lpush", "kv_rpush", "kv_lrange", "kv_llen", "kv_lpop", "kv_rpop",
    "kv_sadd", "kv_smembers", "kv_scard", "kv_srem", "kv_sismember",
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
# kv_keys_scan — its cursor walk needs several round trips, one
# SCAN per page, which cannot happen inside a transaction — and
# not kv_batch itself.
ATOMIC_BATCHABLE_TOOLS = {
    "kv_get", "kv_set", "kv_del", "kv_keys",
    "kv_incr", "kv_ttl", "kv_pttl", "kv_exists", "kv_expire", "kv_pexpire",
    "kv_mget", "kv_mset", "kv_getdel", "kv_setnx", "kv_setex", "kv_getset",
    "kv_hset", "kv_hget", "kv_hgetall", "kv_hdel", "kv_hexists", "kv_hlen",
    "kv_zadd", "kv_zrange", "kv_zrangebyscore", "kv_zcount", "kv_zcard",
    "kv_zscore", "kv_zrank", "kv_zrevrank", "kv_zrem", "kv_zincrby",
    "kv_lpush", "kv_rpush", "kv_lrange", "kv_llen", "kv_lpop", "kv_rpop",
    "kv_sadd", "kv_smembers", "kv_scard", "kv_srem", "kv_sismember",
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
        if op_name == "kv_lrange":
            # A range with a negative bound needs the list's length
            # to know how wide it is; check the bound before anything
            # is queued, like the standalone tool does.
            _check_lrange_window(client, op)
        # Most ops queue one command; kv_zrevrank queues two (ZRANK
        # then ZCARD), combined from their two EXEC replies below.
        argv_list.extend(_op_argvs(op_name, op))
    replies = client.transaction(argv_list)
    results = []
    ok_count = 0
    # Replies are consumed in order; most ops take one reply, but
    # kv_zrevrank takes two (its ZRANK, then its ZCARD).
    ri = 0
    for op in ops:
        op_name = op["op"]
        if op_name == "kv_zrevrank":
            rank_reply, card_reply = replies[ri], replies[ri + 1]
            ri += 2
            if isinstance(rank_reply, RespError):
                results.append(
                    {"op": op_name, "ok": False,
                     "error": str(rank_reply)})
                continue
            if isinstance(card_reply, RespError):
                results.append(
                    {"op": op_name, "ok": False,
                     "error": str(card_reply)})
                continue
            value = None if rank_reply is None \
                else card_reply - 1 - rank_reply
            results.append({"op": op_name, "ok": True, "result": value})
            ok_count += 1
            continue
        reply = replies[ri]
        ri += 1
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
        elif op_name == "kv_lrange":
            # LRANGE came back as a flat list inside the transaction;
            # a range wider than the cap is recorded as this op's
            # error, in place, like an EXEC-time failure — the rest
            # still run.
            members = list(reply or [])
            if len(members) > MAX_LRANGE_ELEMENTS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_lrange returns at most %d elements; "
                              "narrow the range" % MAX_LRANGE_ELEMENTS})
                continue
            value = members
        elif op_name == "kv_smembers":
            # SMEMBERS came back as a flat list inside the
            # transaction; a set wider than the cap is recorded as
            # this op's error, in place, like an EXEC-time failure —
            # the rest still run.
            members = list(reply or [])
            if len(members) > MAX_SMEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_smembers returns at most %d members; "
                              "the set is larger" % MAX_SMEMBERS})
                continue
            value = members
        elif op_name == "kv_zrangebyscore":
            # ZRANGEBYSCORE came back as a flat list inside the
            # transaction; shape it like the standalone tool does,
            # including the withscores member/score objects. A range
            # wider than the cap is recorded as this op's error, in
            # place, like an EXEC-time failure — the rest still run.
            members = _zrange_result(reply or [], _zrangebyscore_args(op)[3])
            if len(members) > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_zrangebyscore returns at most %d "
                              "members; narrow the range or pass a limit"
                              % MAX_ZRANGE_MEMBERS})
                continue
            value = members
        elif op_name == "kv_zcount":
            # ZRANGEBYSCORE came back as a flat list inside the
            # transaction; the count is its length. A range wider
            # than the cap is recorded as this op's error, in place,
            # like an EXEC-time failure — the rest still run.
            count = len(reply or [])
            if count > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_zcount counts at most %d members; "
                              "narrow the range" % MAX_ZRANGE_MEMBERS})
                continue
            value = count
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
    """kv_keys_scan: one bounded page of the keyspace from one real
    SCAN call. Returns {"keys": [...], "cursor": str, "done": bool,
    "batch_size": n}. Bad batch_size/cursor values fail the call
    instead of silently ignoring the caller."""
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
    if name == "kv_pttl":
        return ["PTTL", _require(args, "key")]
    if name == "kv_exists":
        return ["EXISTS", _require(args, "key")]
    if name == "kv_expire":
        return ["EXPIRE", _require(args, "key"), _require(args, "seconds")]
    if name == "kv_pexpire":
        milliseconds = _require(args, "milliseconds")
        if isinstance(milliseconds, bool) or not isinstance(milliseconds, int):
            raise ValueError("kv_pexpire milliseconds must be an integer")
        if milliseconds < 0:
            raise ValueError(
                "kv_pexpire milliseconds must be 0 or more, got %d"
                % milliseconds
            )
        return ["PEXPIRE", _require(args, "key"), milliseconds]
    if name == "kv_mget":
        return ["MGET"] + _mget_keys_args(args)
    if name == "kv_mset":
        return ["MSET"] + _mset_values_args(args)
    if name == "kv_getdel":
        return ["GETDEL", _require(args, "key")]
    if name == "kv_setnx":
        return ["SETNX", _require(args, "key"), _require(args, "value")]
    if name == "kv_setex":
        key, seconds, value = _setex_args(args)
        return ["SETEX", key, seconds, value]
    if name == "kv_getset":
        return ["GETSET", _require(args, "key"), _require(args, "value")]
    if name == "kv_hset":
        return ["HSET", _require(args, "key")] + _hset_field_args(args)
    if name == "kv_hget":
        return ["HGET", _require(args, "key"), _require(args, "field")]
    if name == "kv_hgetall":
        return ["HGETALL", _require(args, "key")]
    if name == "kv_hdel":
        return ["HDEL", _require(args, "key")] + _hash_fields_args(args, name)
    if name == "kv_hexists":
        return ["HEXISTS", _require(args, "key"), _require(args, "field")]
    if name == "kv_hlen":
        return ["HLEN", _require(args, "key")]
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
    if name == "kv_lpush":
        return ["LPUSH", _require(args, "key")] + _list_elements_args(args, name)
    if name == "kv_rpush":
        return ["RPUSH", _require(args, "key")] + _list_elements_args(args, name)
    if name == "kv_lrange":
        key, start, stop = _lrange_args(args)
        # A range both ends of which are non-negative has a known
        # width; check the bound here. A negative bound needs the
        # list's length, which the caller checks with
        # _check_lrange_window.
        if start >= 0 and stop >= 0 and stop - start + 1 > MAX_LRANGE_ELEMENTS:
            raise ValueError(
                "kv_lrange returns at most %d elements; narrow the range"
                % MAX_LRANGE_ELEMENTS
            )
        return ["LRANGE", key, start, stop]
    if name == "kv_llen":
        return ["LLEN", _require(args, "key")]
    if name == "kv_lpop":
        return ["LPOP", _require(args, "key")]
    if name == "kv_rpop":
        return ["RPOP", _require(args, "key")]
    if name == "kv_sadd":
        return ["SADD", _require(args, "key")] + _set_members_args(args, name)
    if name == "kv_smembers":
        return ["SMEMBERS", _require(args, "key")]
    if name == "kv_scard":
        return ["SCARD", _require(args, "key")]
    if name == "kv_srem":
        return ["SREM", _require(args, "key")] + _set_members_args(args, name)
    if name == "kv_sismember":
        return ["SISMEMBER", _require(args, "key"), _require(args, "member")]
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
    if name == "kv_zrangebyscore":
        key, min_b, max_b, withscores, rev, offset, count = \
            _zrangebyscore_args(args)
        # The reply is capped at MAX_ZRANGE_MEMBERS members: an
        # explicit count is sent as given (already checked against
        # the cap); without one, ask for one extra member so the
        # caller can tell the range was too wide instead of getting
        # a silently truncated list.
        probe = count if count >= 0 else MAX_ZRANGE_MEMBERS + 1
        cmd = ["ZREVRANGEBYSCORE" if rev else "ZRANGEBYSCORE", key]
        cmd += [max_b, min_b] if rev else [min_b, max_b]
        if withscores:
            cmd.append("WITHSCORES")
        cmd += ["LIMIT", offset, probe]
        return cmd
    if name == "kv_zcount":
        key, min_b, max_b = _zcount_args(args)
        # Ask for one extra member so the caller can tell the range
        # was too wide instead of getting a silently truncated count.
        return ["ZRANGEBYSCORE", key, min_b, max_b,
                "LIMIT", 0, MAX_ZRANGE_MEMBERS + 1]
    raise ValueError("unknown or unbatchable op: %s" % name)


def _op_argvs(name, args):
    """One batchable op as a list of argv lists, for queuing inside a
    transaction. Most ops are one command; kv_zrevrank is two (ZRANK
    then ZCARD), combined from their two EXEC replies by the caller."""
    if name == "kv_zrevrank":
        key, member = _zrevrank_args(args)
        return [["ZRANK", key, member], ["ZCARD", key]]
    return [_op_argv(name, args)]


# The most keys one kv_mget call reads; a wider call fails instead of
# dumping a huge slice of the keyspace into one tool result.
MAX_MGET_KEYS = 1000


def _mget_keys_args(args):
    """The key names for an MGET, as an argv list. `keys` must be a
    non-empty list of strings, at most MAX_MGET_KEYS; anything else
    fails the call instead of sending a half-formed MGET."""
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("kv_mget keys must be a non-empty list")
    if len(keys) > MAX_MGET_KEYS:
        raise ValueError(
            "kv_mget reads at most %d keys; narrow the list"
            % MAX_MGET_KEYS
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError("kv_mget keys must be strings")
    return list(keys)


def _mset_values_args(args):
    """The key/value pairs for an MSET, as a flat argv list.
    `values` must be a non-empty object of string key names to
    string values; anything else fails the call instead of sending
    a half-formed MSET. Pairs are sent in sorted key order so the
    argv is deterministic."""
    values = args.get("values")
    if not isinstance(values, dict) or not values:
        raise ValueError("kv_mset values must be a non-empty object")
    argv = []
    for key in sorted(values):
        value = values[key]
        if not isinstance(key, str) or not isinstance(value, str):
            raise ValueError(
                "kv_mset values must map string key names to string values"
            )
        argv += [key, value]
    return argv


def _setex_args(args):
    """Validate a kv_setex call: (key, seconds, value). The seconds
    must be an integer greater than 0 — cinder rejects 0 or a
    negative time as a server error, so fail here as invalid params
    instead."""
    key = _require(args, "key")
    seconds = _require(args, "seconds")
    value = _require(args, "value")
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise ValueError("kv_setex seconds must be an integer")
    if seconds <= 0:
        raise ValueError(
            "kv_setex seconds must be more than 0, got %d" % seconds
        )
    return key, seconds, value


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


def _hash_fields_args(args, name):
    """The field names for an HDEL, as an argv list. `fields` must
    be a non-empty list of strings; anything else fails the call
    instead of sending a half-formed HDEL."""
    fields = args.get("fields")
    if not isinstance(fields, list) or not fields:
        raise ValueError("%s fields must be a non-empty list" % name)
    for field in fields:
        if not isinstance(field, str):
            raise ValueError("%s fields must be strings" % name)
    return list(fields)


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


def _format_score_bound(value, tool="kv_zrangebyscore"):
    """One ZRANGEBYSCORE bound as a RESP argument. A number goes
    through repr — infinities print as "inf" / "-inf", which
    cinder's bound parser accepts. A string is passed through after
    checking it is a plain number or infinity with an optional
    leading '(' for an exclusive bound: "5", "(5", "-inf", "+inf".
    NaN is rejected — cinder rejects it too — as is anything that
    is not a number or a numeric string."""
    if isinstance(value, bool):
        raise ValueError("%s bounds must be numbers or strings" % tool)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and value != value:
            raise ValueError("%s bounds must not be NaN" % tool)
        return repr(value)
    if isinstance(value, str):
        text = value[1:] if value.startswith("(") else value
        if not text:
            raise ValueError(
                "%s bound %r is not a valid score" % (tool, value)
            )
        try:
            parsed = float(text)
        except ValueError:
            raise ValueError(
                "%s bound %r is not a valid score" % (tool, value)
            )
        if parsed != parsed:
            raise ValueError("%s bounds must not be NaN" % tool)
        return value
    raise ValueError("%s bounds must be numbers or strings" % tool)


def _zrangebyscore_args(args):
    """Validate a kv_zrangebyscore call: (key, min, max, withscores,
    rev, offset, count). min defaults to -inf and max to +inf, as in
    Redis; offset defaults to 0 and count to -1, meaning all matches
    from the offset. count is at most MAX_ZRANGE_MEMBERS, and an
    offset below 0 or a count below -1 fails the call instead of
    sending a half-formed ZRANGEBYSCORE."""
    key = _require(args, "key")
    min_b = _format_score_bound(args.get("min", "-inf"))
    max_b = _format_score_bound(args.get("max", "+inf"))
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zrangebyscore withscores must be true or false")
    rev = args.get("rev", False)
    if not isinstance(rev, bool):
        raise ValueError("kv_zrangebyscore rev must be true or false")
    offset = args.get("offset", 0)
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("kv_zrangebyscore offset must be an integer")
    if offset < 0:
        raise ValueError("kv_zrangebyscore offset must be 0 or more")
    count = args.get("count", -1)
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("kv_zrangebyscore count must be an integer")
    if count < -1:
        raise ValueError("kv_zrangebyscore count must be -1 or more")
    if count > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zrangebyscore returns at most %d members; narrow the "
            "range or pass a smaller count" % MAX_ZRANGE_MEMBERS
        )
    return key, min_b, max_b, withscores, rev, offset, count


def _zrangebyscore_result(flat, withscores):
    """Shape a flat ZRANGEBYSCORE reply into the tool's return value,
    like _zrange_result, and fail when the probe asked for one extra
    member and got it — the range holds more than MAX_ZRANGE_MEMBERS
    members, so the caller must narrow it or pass a limit instead of
    getting a silently truncated list."""
    members = _zrange_result(flat, withscores)
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zrangebyscore returns at most %d members; narrow the "
            "range or pass a limit" % MAX_ZRANGE_MEMBERS
        )
    return members


def _call_zrangebyscore(client, args):
    """kv_zrangebyscore: run ZRANGEBYSCORE or ZREVRANGEBYSCORE and
    shape the reply. The argv always carries a LIMIT (see _op_argv),
    so a range wider than the cap is caught from the reply."""
    return _zrangebyscore_result(
        client.command(*_op_argv("kv_zrangebyscore", args)) or [],
        _zrangebyscore_args(args)[3],
    )


def _zcount_args(args):
    """Validate a kv_zcount call: (key, min, max). The bounds parse
    exactly like kv_zrangebyscore's: numbers or strings with an
    optional leading '(' for exclusivity, -inf/+inf by default."""
    key = _require(args, "key")
    min_b = _format_score_bound(args.get("min", "-inf"), "kv_zcount")
    max_b = _format_score_bound(args.get("max", "+inf"), "kv_zcount")
    return key, min_b, max_b


def _call_zcount(client, args):
    """kv_zcount: count the members in a score range. Cinder has no
    ZCOUNT, so this fetches the range with ZRANGEBYSCORE and counts
    what comes back — the count is honest, not a server-side count.
    The argv asks for one extra member (see _op_argv), so a range
    wider than the cap fails instead of returning a truncated count."""
    members = client.command(*_op_argv("kv_zcount", args)) or []
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zcount counts at most %d members; narrow the range"
            % MAX_ZRANGE_MEMBERS
        )
    return len(members)


def _zrevrank_args(args):
    """Validate a kv_zrevrank call: (key, member)."""
    return _require(args, "key"), _require(args, "member")


def _call_zrevrank(client, args):
    """kv_zrevrank: the member's rank, highest score first. Cinder
    has no ZREVRANK, so this reads ZRANK and ZCARD and returns
    ZCARD - 1 - ZRANK — null when the key or the member does not
    exist (cinder replies nil for the rank)."""
    key, member = _zrevrank_args(args)
    rank = client.command("ZRANK", key, member)
    if rank is None:
        return None
    return (client.command("ZCARD", key) or 0) - 1 - rank


# The most elements one kv_lrange call returns; a wider range fails
# instead of dumping a huge list into one tool result.
MAX_LRANGE_ELEMENTS = 1000


def _list_elements_args(args, name):
    """The element names for an LPUSH/RPUSH, as an argv list.
    `elements` must be a non-empty list of strings; anything else
    fails the call instead of sending a half-formed push."""
    elements = args.get("elements")
    if not isinstance(elements, list) or not elements:
        raise ValueError("%s elements must be a non-empty list" % name)
    for element in elements:
        if not isinstance(element, str):
            raise ValueError("%s elements must be strings" % name)
    return list(elements)


def _lrange_args(args):
    """Validate a kv_lrange call: (key, start, stop). start defaults
    to 0 and stop to -1, as in Redis. Bad types fail the call instead
    of sending a half-formed LRANGE."""
    key = _require(args, "key")
    start = args.get("start", 0)
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("kv_lrange start must be an integer")
    stop = args.get("stop", -1)
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError("kv_lrange stop must be an integer")
    return key, start, stop


def _check_lrange_window(client, args):
    """Fail a kv_lrange call whose range would return more than
    MAX_LRANGE_ELEMENTS elements. A range with a negative bound needs
    the list's length first, so it reads LLEN; a range both ends of
    which are non-negative is checked without a round trip. A missing
    key has length 0, so the check passes and the range returns []."""
    key, start, stop = _lrange_args(args)
    if start >= 0 and stop >= 0:
        window = stop - start + 1
    else:
        window = _zrange_window(start, stop, client.command("LLEN", key) or 0)
    if window > MAX_LRANGE_ELEMENTS:
        raise ValueError(
            "kv_lrange returns at most %d elements; narrow the range"
            % MAX_LRANGE_ELEMENTS
        )


def _call_lrange(client, args):
    """kv_lrange: bound the range first (see _check_lrange_window),
    then run LRANGE. A missing key replies as an empty list, which
    becomes []."""
    _check_lrange_window(client, args)
    return list(client.command(*_op_argv("kv_lrange", args)) or [])


# The most members one kv_smembers call returns; a larger set fails
# instead of dumping a huge set into one tool result.
MAX_SMEMBERS = 1000


def _set_members_args(args, name):
    """The member names for an SADD or SREM, as an argv list.
    `members` must be a non-empty list of strings; anything else
    fails the call instead of sending a half-formed command."""
    members = args.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("%s members must be a non-empty list" % name)
    for member in members:
        if not isinstance(member, str):
            raise ValueError("%s members must be strings" % name)
    return list(members)


def _call_smembers(client, args):
    """kv_smembers: bound the set first with SCARD, then run
    SMEMBERS. A missing key replies as an empty list, which becomes
    []. The SCARD check runs outside a transaction, so an atomic
    batch checks the reply length instead (see _call_batch_atomic)."""
    key = _require(args, "key")
    if (client.command("SCARD", key) or 0) > MAX_SMEMBERS:
        raise ValueError(
            "kv_smembers returns at most %d members; the set is larger"
            % MAX_SMEMBERS
        )
    return list(client.command("SMEMBERS", key) or [])


def _call_single(client, name, args):
    if name == "kv_keys":
        return _call_keys(client, args)
    if name == "kv_keys_scan":
        return _call_keys_scan(client, args)
    if name == "kv_smembers":
        return _call_smembers(client, args)
    if name == "kv_hgetall":
        return _hgetall_result(
            client.command("HGETALL", _require(args, "key")) or []
        )
    if name == "kv_lrange":
        return _call_lrange(client, args)
    if name == "kv_zadd":
        return _call_zadd(client, args)
    if name == "kv_zscore":
        return _call_zscore(client, args)
    if name == "kv_zincrby":
        return _call_zincrby(client, args)
    if name == "kv_zrange":
        return _call_zrange(client, args)
    if name == "kv_zrangebyscore":
        return _call_zrangebyscore(client, args)
    if name == "kv_zcount":
        return _call_zcount(client, args)
    if name == "kv_zrevrank":
        return _call_zrevrank(client, args)
    return client.command(*_op_argv(name, args))
