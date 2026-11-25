"""Tool definitions for cinder-mcp.

Each tool maps to one cinder command. The schemas are plain JSON Schema
fragments, as the MCP spec requires for tools/list.
"""

import hashlib

from .resp import RespError
from .scan import (
    DEFAULT_SCAN_BATCH_SIZE,
    hscan_batch,
    hscan_result,
    scan_batch,
    sscan_batch,
    sscan_result,
    validate_batch_size,
    zscan_batch,
    zscan_result,
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
        "name": "kv_dbsize",
        "description": "The number of keys in the database: DBSIZE. Takes no arguments. Returns 0 on an empty database.",
        "inputSchema": {
            "type": "object",
            "properties": {},
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
        "name": "kv_append",
        "description": "Append a value to the string stored at a key: APPEND key value. Creates the key when it does not exist. Returns the length of the string after the append. Preserves the key's TTL.",
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
        "name": "kv_strlen",
        "description": "The length of the string stored at a key: STRLEN key. Returns 0 when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_decr",
        "description": "Decrement the integer stored at a key by a given amount (default 1).",
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
        "name": "kv_decrby",
        "description": "Decrement the integer stored at a key by a given amount: DECRBY key n. Creates the key holding -n when it does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "by": {"type": "integer"},
            },
            "required": ["key", "by"],
        },
    },
    {
        "name": "kv_getex",
        "description": "Get the string value of a key and set, refresh, or remove its TTL: GETEX key [EX seconds | PX milliseconds | PERSIST]. Returns the value, or null when the key does not exist. With no option the TTL is left alone; ex sets it in seconds, px in milliseconds, persist removes it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "ex": {"type": "integer"},
                "px": {"type": "integer"},
                "persist": {"type": "boolean"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_getrange",
        "description": "A substring of the string stored at a key: GETRANGE key start stop. Negative indices count from the end, as in Redis; out-of-range ends are clamped, so GETRANGE key 0 -1 returns the whole value. Returns \"\" when the key does not exist or the range is empty — including a range past the end of a SETRANGE zero-pad, whose zero bytes come back intact. start defaults to 0 and stop to -1.",
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
        "name": "kv_setrange",
        "description": "Overwrite the string stored at a key starting at an offset: SETRANGE key offset value. Creates the key zero-padded to the offset when it does not exist, and extends it when the write runs past the end. Returns the length of the string after the write. Preserves the key's TTL. An empty value changes nothing and creates nothing: it returns the current length, or 0 when the key does not exist. The offset must be 0 or more.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "offset": {"type": "integer"},
                "value": {"type": "string"},
            },
            "required": ["key", "offset", "value"],
        },
    },
    {
        "name": "kv_setbit",
        "description": "Set one bit of the string stored at a key: SETBIT key offset bit. The offset must be 0 or more (at most 4294967295) and the bit 0 or 1. Returns the bit's old value (0 or 1). Creates the key zero-padded to the byte holding the offset when it does not exist — even when the bit being set is 0, the key comes into being — and preserves the key's TTL. Setting a bit that already holds the requested value changes nothing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "offset": {"type": "integer"},
                "bit": {"type": "integer"},
            },
            "required": ["key", "offset", "bit"],
        },
    },
    {
        "name": "kv_getbit",
        "description": "The bit of the string stored at a key: GETBIT key offset. The offset must be 0 or more (at most 4294967295). Returns 0 or 1; 0 when the key does not exist or the offset is past the end of the string.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "offset": {"type": "integer"},
            },
            "required": ["key", "offset"],
        },
    },
    {
        "name": "kv_bitcount",
        "description": "The number of bits set to 1 in the string stored at a key: BITCOUNT key [start end]. `start` and `end` are byte indexes, both or neither; negative indexes count from the end and out-of-range ends are clamped, as in Redis. Returns 0 when the key does not exist. Cinder has no BYTE|BIT mode: the range is always in bytes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "start": {"type": "integer"},
                "end": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_bitop",
        "description": "Combine the strings stored at several keys bitwise and store the result: BITOP AND|OR|XOR|NOT destination key [key ...]. `operation` is \"and\", \"or\", \"xor\" or \"not\"; `sources` is the list of source keys. NOT takes exactly one source, the rest take at least two. Returns the length of the destination string in bytes — the length of the longest source. A missing source counts as empty, so when every source is missing or empty the destination is deleted and 0 is returned. Overwrites the destination wholesale and clears its TTL; the destination may also be one of the sources.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "operation": {"type": "string"},
                "destination": {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["operation", "destination", "sources"],
        },
    },
    {
        "name": "kv_bitfield",
        "description": "Read and write packed integer fields of the string stored at a key: BITFIELD key [GET type offset | SET type offset value | INCRBY type offset increment | OVERFLOW WRAP|SAT|FAIL ...]. `ops` is a list of subcommands in order: {\"op\": \"get\", \"type\": \"i8\", \"offset\": 0}, {\"op\": \"set\", ...} with a \"value\", {\"op\": \"incrby\", ...} with a \"value\" to add, and {\"op\": \"overflow\", \"policy\": \"wrap\"|\"sat\"|\"fail\"} which sets the overflow policy for the SET / INCRBY ops that follow it (default WRAP). Types are i1..i64 and u1..u63 (u64 is not supported: a u64 field cannot come back as a signed 64-bit integer); offsets are bit offsets, or \"#n\" for the n-th field of that width; a field must end within 2^32 bits. Returns one result per GET / SET / INCRBY, in order: GET returns the field's current value (0 when the key does not exist or the field is past the end), SET returns the old value, INCRBY returns the new value; a SET or INCRBY that overflows under OVERFLOW FAIL answers null and writes nothing. A syntax error anywhere in the ops fails the whole call before anything runs. A write creates the key zero-padded when it does not exist and preserves the TTL — even a write that answers null under OVERFLOW FAIL leaves the grown string behind, as in Redis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "ops": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["key", "ops"],
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
        "name": "kv_hmget",
        "description": "Get several fields of a hash at once: HMGET key field [field ...]. Takes `fields` as a list of field names. Returns the values in the same order, with null for a field that does not exist — and null for every field when the key does not exist.",
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
        "name": "kv_hsetnx",
        "description": "Set one field of a hash only when the field does not already exist: HSETNX key field value. Returns 1 if the field was set, 0 if it already existed (the old value is left alone).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "field": {"type": "string"},
                "value": {"type": "string"},
            },
            "required": ["key", "field", "value"],
        },
    },
    {
        "name": "kv_hincrby",
        "description": "Increment the integer stored in one field of a hash: HINCRBY key field increment. Creates the field holding the increment when it does not exist, and the key when it does not exist. Returns the new value as a number. A negative increment counts down, as in Redis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "field": {"type": "string"},
                "increment": {"type": "integer"},
            },
            "required": ["key", "field", "increment"],
        },
    },
    {
        "name": "kv_hscan",
        "description": "Walk the fields of a hash one bounded page at a time with cinder's real HSCAN. Returns {\"fields\": {...}, \"cursor\": str, \"done\": bool, \"batch_size\": n}: at most `batch_size` fields per page (default 100) — COUNT is exact here, cinder stops the page at that many matching fields. Pass the returned `cursor` back to fetch the next page; pass \"\" (or omit it) to start. When `done` is true the cursor is \"\" and the walk is finished. The cursor is opaque: pass it back verbatim, do not read meaning into it. Pass `pattern` to match field names only, with the same glob (* and ?). A missing key is done at once, with no fields. Fields come back in hash order, not sorted; fields added or deleted between pages can shift the window, the same caveats real HSCAN has.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "pattern": {"type": "string"},
                "batch_size": {"type": "integer"},
                "cursor": {"type": "string"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_hkeys",
        "description": "The field names of a hash: HKEYS key. Returns the field names in cinder's order. At most 1000 fields per call; a larger hash fails instead of returning a silently truncated list — page it with kv_hscan instead. Returns an empty list when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_hvals",
        "description": "The values of a hash: HVALS key. Returns the field values in cinder's order, matching kv_hkeys field for field. At most 1000 values per call; a larger hash fails instead of returning a silently truncated list — page it with kv_hscan instead. Returns an empty list when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_hincrbyfloat",
        "description": "Increment the float stored in one field of a hash: HINCRBYFLOAT key field increment. Creates the field holding the increment when it does not exist, and the key when it does not exist. Returns the new value as a number. A negative increment counts down, as in Redis. The increment may be an integer or a float, but not NaN or an infinity; a field holding a non-float fails.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "field": {"type": "string"},
                "increment": {"type": "number"},
            },
            "required": ["key", "field", "increment"],
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
        "name": "kv_zrangebylex",
        "description": "Members of a sorted set whose names fall in a lex range, in lex order: ZRANGEBYLEX key min max [LIMIT offset count] [REV]. `min` and `max` default to \"-\" and \"+\"; pass \"[a\" for an inclusive bound, \"(a\" for an exclusive one, \"-\" for no lower bound and \"+\" for no upper bound — a bare member name is a syntax error in cinder, as is the wrong infinity on a side. Members come back in lex order regardless of their scores, and cinder has no WITHSCORES for this command. Pass rev=true to read highest lex order first (bounds still given min then max). Pass offset/count to page through the matches (count defaults to all); at most 1000 members per call, so narrow the range or pass a smaller count for a larger set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "min": {"type": "string"},
                "max": {"type": "string"},
                "rev": {"type": "boolean"},
                "offset": {"type": "integer"},
                "count": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zlexcount",
        "description": "The number of members of a sorted set whose names fall in a lex range: ZLEXCOUNT key min max. `min` and `max` default to \"-\" and \"+\"; pass \"[a\" for an inclusive bound, \"(a\" for an exclusive one, \"-\" for no lower bound and \"+\" for no upper bound — a bare member name is a syntax error in cinder, as is the wrong infinity on a side. There is no REV and no LIMIT: the count does not depend on order, and cinder counts server-side, so unlike kv_zcount there is no 1000-member cap and a range holding any number of members counts honestly. Returns 0 when the key does not exist or the range is empty, including a finite min above the max.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "min": {"type": "string"},
                "max": {"type": "string"},
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
        "name": "kv_zmscore",
        "description": "The scores of several members of a sorted set at once: ZMSCORE key member [member ...]. Takes `members` as a list of member names. Returns the scores in the same order, as numbers, with null for a member that is not in the set — and null for every member when the key does not exist. At most 1000 members per call.",
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
        "name": "kv_zremrangebyscore",
        "description": "Remove the members of a sorted set whose scores fall in a range: ZREMRANGEBYSCORE key min max. `min` and `max` default to -inf and +inf; pass a number or a string like \"5\", \"(5\" for an exclusive bound, \"-inf\" or \"+inf\". Returns the number of members removed; 0 when the key does not exist or the range is empty, including a finite min above the max. Removing the last member deletes the key, as in Redis.",
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
        "name": "kv_zremrangebyrank",
        "description": "Remove the members of a sorted set ranked in a range: ZREMRANGEBYRANK key start stop. `start` defaults to 0 and `stop` to -1; negative indices count from the end, as in ZRANGE, and out-of-range ends are clamped. Returns the number of members removed; 0 when the key does not exist or the range is empty, including a start past the end. Removing the last member deletes the key, as in Redis.",
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
        "name": "kv_zremrangebylex",
        "description": "Remove the members of a sorted set whose names fall in a lex range: ZREMRANGEBYLEX key min max. `min` and `max` default to \"-\" and \"+\"; pass \"[a\" for an inclusive bound, \"(a\" for an exclusive one, \"-\" for no lower bound and \"+\" for no upper bound — a bare member name is a syntax error in cinder, as is the wrong infinity on a side. There is no REV: the removed set does not depend on order. Returns the number of members removed; 0 when the key does not exist or the range is empty, including a finite min above the max. Removing the last member deletes the key, as in Redis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "min": {"type": "string"},
                "max": {"type": "string"},
            },
            "required": ["key"],
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
        "name": "kv_zpopmin",
        "description": "Remove and return the lowest-scoring member(s) of a sorted set: ZPOPMIN key [count]. Returns a list of {\"member\": ..., \"score\": ...} objects, lowest score first; count defaults to 1. A count past the end pops the whole set, and a missing key returns an empty list. Popping the last member deletes the key, as in Redis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zpopmax",
        "description": "Remove and return the highest-scoring member(s) of a sorted set: ZPOPMAX key [count]. Returns a list of {\"member\": ..., \"score\": ...} objects, highest score first; count defaults to 1. A count past the end pops the whole set, and a missing key returns an empty list. Popping the last member deletes the key, as in Redis.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zrandmember",
        "description": "A random member (or members) of a sorted set: ZRANDMEMBER key [count [WITHSCORES]]. Without a count returns one member as a string, or null when the key does not exist. With a count returns a list of member names: a positive count returns distinct members (at most the whole set), a negative count samples with replacement so members may repeat, and 0 returns an empty list. Pass withscores=true with a count for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The set is not changed. At most 1000 members per call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "count": {"type": "integer"},
                "withscores": {"type": "boolean"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zscan",
        "description": "Walk the members of a sorted set one bounded page at a time with cinder's real ZSCAN. Returns {\"members\": [...], \"cursor\": str, \"done\": bool, \"batch_size\": n}: at most `batch_size` members per page (default 100) — COUNT is exact here, cinder stops the page at that many matching members. Pass the returned `cursor` back to fetch the next page; pass \"\" (or omit it) to start. When `done` is true the cursor is \"\" and the walk is finished. The cursor is opaque: pass it back verbatim, do not read meaning into it. Pass `pattern` to match member names only, with the same glob (* and ?), and `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. A missing key is done at once, with no members. Members come back in score order, lowest first, not sorted by name; members added or deleted between pages can shift the window, the same caveats real ZSCAN has.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "pattern": {"type": "string"},
                "batch_size": {"type": "integer"},
                "cursor": {"type": "string"},
                "withscores": {"type": "boolean"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_zunion",
        "description": "The union of several sorted sets: ZUNION numkeys key [key ...] [WITHSCORES]. Takes `keys` as a list of key names, at most 1000. A member in several sets appears once, with the sum of its scores, lowest score first, member name breaking ties. A missing key counts as an empty set. Pass `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The union holds at most 1000 members; a wider union fails instead of returning a truncated list. Cinder has no WEIGHTS, AGGREGATE, or STORE variants, so the tool does not offer them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "array", "items": {"type": "string"}},
                "withscores": {"type": "boolean"},
            },
            "required": ["keys"],
        },
    },
    {
        "name": "kv_zinter",
        "description": "The intersection of several sorted sets: ZINTER numkeys key [key ...] [WEIGHTS weight ...] [AGGREGATE SUM|MIN|MAX] [WITHSCORES]. Takes `keys` as a list of key names, at most 1000. A member must be in every set to appear, once, lowest score first, member name breaking ties. Pass `weights` as a list of numbers, one per key, to multiply each set's scores before aggregating (defaults to 1 per key); pass `aggregate` as \"sum\", \"min\" or \"max\" to combine a member's weighted scores (defaults to \"sum\"). A missing key counts as an empty set, so an intersection with one is empty. Pass `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The intersection holds at most 1000 members; a wider intersection fails instead of returning a truncated list. Cinder's `ZINTERSTORE` stores the intersection instead of returning it; like `kv_zunion` with `ZUNIONSTORE`, this tool does not offer it — it returns the intersection.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "array", "items": {"type": "string"}},
                "weights": {"type": "array", "items": {"type": "number"}},
                "aggregate": {"type": "string"},
                "withscores": {"type": "boolean"},
            },
            "required": ["keys"],
        },
    },
    {
        "name": "kv_zdiff",
        "description": "The difference of several sorted sets: ZDIFF numkeys key [key ...] [WITHSCORES]. Takes `keys` as a list of key names, at most 1000. The members of the first set that are in none of the other sets, once each, in the first set's score order, member name breaking ties, with the first set's scores. A missing key counts as an empty set, so a difference against only missing keys is the whole first set, and a missing first key diffs to nothing. Pass `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The difference holds at most 1000 members; a wider difference fails instead of returning a truncated list. Cinder's `ZDIFFSTORE` stores the difference instead of returning it; like `kv_zunion` with `ZUNIONSTORE`, this tool does not offer it — it returns the difference.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "array", "items": {"type": "string"}},
                "withscores": {"type": "boolean"},
            },
            "required": ["keys"],
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
        "name": "kv_lindex",
        "description": "The element of a list at an index: LINDEX key index. Negative indices count from the end, as in Redis. Returns null when the key does not exist or the index is out of range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "index": {"type": "integer"},
            },
            "required": ["key", "index"],
        },
    },
    {
        "name": "kv_lset",
        "description": "Set the element of a list at an index: LSET key index value. Negative indices count from the end, as in Redis. Returns OK. Fails when the key does not exist or the index is out of range.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "index": {"type": "integer"},
                "value": {"type": "string"},
            },
            "required": ["key", "index", "value"],
        },
    },
    {
        "name": "kv_linsert",
        "description": "Insert an element into a list before or after a pivot: LINSERT key BEFORE|AFTER pivot element. Takes `where` as \"before\" or \"after\" and `pivot` as the element to insert beside. Returns the length of the list after the insert, 0 when the pivot is not found, -1 when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "where": {"type": "string"},
                "pivot": {"type": "string"},
                "element": {"type": "string"},
            },
            "required": ["key", "where", "pivot", "element"],
        },
    },
    {
        "name": "kv_lpushx",
        "description": "Push elements onto the head of an existing list: LPUSHX key element [element ...]. Takes `elements` as a list of strings. Returns the length of the list after the push, or 0 when the key does not exist — unlike kv_lpush it never creates the list. Several elements at once are pushed left one at a time, so the last element ends up at the head.",
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
        "name": "kv_rpushx",
        "description": "Push elements onto the tail of an existing list: RPUSHX key element [element ...]. Takes `elements` as a list of strings. Returns the length of the list after the push, or 0 when the key does not exist — unlike kv_rpush it never creates the list. Several elements at once are appended in order.",
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
        "name": "kv_ltrim",
        "description": "Trim a list to an index range: LTRIM key start stop. Negative indices count from the end, as in Redis. Returns OK. A range that keeps nothing deletes the key, as in Redis; a missing key is a no-op that still returns OK.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "start": {"type": "integer"},
                "stop": {"type": "integer"},
            },
            "required": ["key", "start", "stop"],
        },
    },
    {
        "name": "kv_lmove",
        "description": "Move one element between lists: LMOVE source destination LEFT|RIGHT LEFT|RIGHT. Takes `source` and `destination` as key names and `from` / `to` as \"left\" or \"right\". Removes the element from one end of the source and puts it at one end of the destination, creating the destination when it does not exist, and returns the moved element. Returns null when the source does not exist or is empty; moving the last element out deletes the source key, as in Redis. When source and destination are the same key the element is rotated within the list.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "source": {"type": "string"},
                "destination": {"type": "string"},
                "from": {"type": "string"},
                "to": {"type": "string"},
            },
            "required": ["source", "destination", "from", "to"],
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
        "name": "kv_sscan",
        "description": "Walk the members of a set one bounded page at a time with cinder's real SSCAN. Returns {\"members\": [...], \"cursor\": str, \"done\": bool, \"batch_size\": n}: at most `batch_size` members per page (default 100) — COUNT is exact here, cinder stops the page at that many matching members. Pass the returned `cursor` back to fetch the next page; pass \"\" (or omit it) to start. When `done` is true the cursor is \"\" and the walk is finished. The cursor is opaque: pass it back verbatim, do not read meaning into it. Pass `pattern` to match member names only, with the same glob (* and ?). A missing key is done at once, with no members. Members come back in the set's storage order, which is insertion order; members added or deleted between pages can shift the window, the same caveats real SSCAN has.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "pattern": {"type": "string"},
                "batch_size": {"type": "integer"},
                "cursor": {"type": "string"},
            },
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
        "description": "Run several kv operations in one call, in order, and get one summary back. Each op is an object with an \"op\" naming one of kv_get, kv_set, kv_del, kv_keys, kv_dbsize, kv_incr, kv_ttl, kv_pttl, kv_exists, kv_expire, kv_pexpire, kv_mget, kv_mset, kv_getdel, kv_setnx, kv_setex, kv_getset, kv_append, kv_strlen, kv_decr, kv_decrby, kv_getex, kv_getrange, kv_setrange, kv_setbit, kv_getbit, kv_bitcount, kv_bitop, kv_bitfield, kv_hset, kv_hget, kv_hgetall, kv_hdel, kv_hexists, kv_hlen, kv_hmget, kv_hsetnx, kv_hincrby, kv_hscan, kv_hkeys, kv_hvals, kv_hincrbyfloat, kv_zadd, kv_zrange, kv_zrangebyscore, kv_zrangebylex, kv_zlexcount, kv_zcount, kv_zcard, kv_zscore, kv_zmscore, kv_zrank, kv_zrevrank, kv_zrem, kv_zremrangebyscore, kv_zremrangebyrank, kv_zremrangebylex, kv_zincrby, kv_zpopmin, kv_zpopmax, kv_zrandmember, kv_zscan, kv_zunion, kv_zinter, kv_zdiff, kv_lpush, kv_rpush, kv_lrange, kv_llen, kv_lpop, kv_rpop, kv_lindex, kv_lset, kv_linsert, kv_lpushx, kv_rpushx, kv_ltrim, kv_lmove, kv_sadd, kv_smembers, kv_sscan, kv_scard, kv_srem or kv_sismember plus that tool's arguments. Ops run sequentially and the batch keeps going past a failed op; each op's result or error is reported. At most 100 ops per call. Pass atomic=true to run the ops as one MULTI/EXEC transaction instead: they execute together with no other client interleaved, and an op that fails at EXEC time is recorded in place while the rest still run. An atomic batch only takes the single-command ops (kv_keys_scan cannot run inside a transaction); an op that cannot be queued fails the whole call before anything runs, so check the ops first.",
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
                            "bit": {"type": "integer"},
                            "seconds": {"type": "integer"},
                            "milliseconds": {"type": "integer"},
                            "persist": {"type": "boolean"},
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
                            "operation": {"type": "string"},
                            "sources": {"type": "array", "items": {"type": "string"}},
                            "count": {"type": "integer"},
                            "withscores": {"type": "boolean"},
                            "weights": {"type": "array",
                                        "items": {"type": "number"}},
                            "aggregate": {"type": "string"},
                            "rev": {"type": "boolean"},
                            "pattern": {"type": "string"},
                            "limit": {"type": "integer"},
                            "full": {"type": "boolean"},
                            "seed": {"type": "string"},
                            "elements": {"type": "array", "items": {"type": "string"}},
                            "index": {"type": "integer"},
                            "where": {"type": "string"},
                            "pivot": {"type": "string"},
                            "element": {"type": "string"},
                            "source": {"type": "string"},
                            "destination": {"type": "string"},
                            "from": {"type": "string"},
                            "to": {"type": "string"},
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
    "kv_dbsize",
    "kv_incr", "kv_ttl", "kv_pttl", "kv_exists", "kv_expire", "kv_pexpire",
    "kv_mget", "kv_mset", "kv_getdel", "kv_setnx", "kv_setex", "kv_getset",
    "kv_append", "kv_strlen", "kv_decr", "kv_decrby", "kv_getex",
    "kv_getrange", "kv_setrange",
    "kv_setbit", "kv_getbit", "kv_bitcount", "kv_bitop", "kv_bitfield",
    "kv_hset", "kv_hget", "kv_hgetall", "kv_hdel", "kv_hexists", "kv_hlen",
    "kv_hmget", "kv_hsetnx", "kv_hincrby", "kv_hscan",
    "kv_hkeys", "kv_hvals", "kv_hincrbyfloat",
    "kv_zadd", "kv_zrange", "kv_zrangebyscore", "kv_zrangebylex",
    "kv_zlexcount", "kv_zcount", "kv_zcard",
    "kv_zscore", "kv_zmscore", "kv_zrank", "kv_zrevrank", "kv_zrem",
    "kv_zremrangebyscore", "kv_zremrangebyrank", "kv_zremrangebylex",
    "kv_zincrby",
    "kv_zpopmin", "kv_zpopmax",
    "kv_zrandmember", "kv_zscan", "kv_zunion", "kv_zinter", "kv_zdiff",
    "kv_lpush", "kv_rpush", "kv_lrange", "kv_llen", "kv_lpop", "kv_rpop",
    "kv_lindex", "kv_lset", "kv_linsert",
    "kv_lpushx", "kv_rpushx", "kv_ltrim", "kv_lmove",
    "kv_sadd", "kv_smembers", "kv_sscan", "kv_scard", "kv_srem", "kv_sismember",
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
    "kv_dbsize",
    "kv_incr", "kv_ttl", "kv_pttl", "kv_exists", "kv_expire", "kv_pexpire",
    "kv_mget", "kv_mset", "kv_getdel", "kv_setnx", "kv_setex", "kv_getset",
    "kv_append", "kv_strlen", "kv_decr", "kv_decrby", "kv_getex",
    "kv_getrange", "kv_setrange",
    "kv_setbit", "kv_getbit", "kv_bitcount", "kv_bitop", "kv_bitfield",
    "kv_hset", "kv_hget", "kv_hgetall", "kv_hdel", "kv_hexists", "kv_hlen",
    "kv_hmget", "kv_hsetnx", "kv_hincrby", "kv_hscan",
    "kv_hkeys", "kv_hvals", "kv_hincrbyfloat",
    "kv_zadd", "kv_zrange", "kv_zrangebyscore", "kv_zrangebylex",
    "kv_zlexcount", "kv_zcount", "kv_zcard",
    "kv_zscore", "kv_zmscore", "kv_zrank", "kv_zrevrank", "kv_zrem",
    "kv_zremrangebyscore", "kv_zremrangebyrank", "kv_zremrangebylex",
    "kv_zincrby",
    "kv_zpopmin", "kv_zpopmax",
    "kv_zrandmember", "kv_zscan", "kv_zunion", "kv_zinter", "kv_zdiff",
    "kv_lpush", "kv_rpush", "kv_lrange", "kv_llen", "kv_lpop", "kv_rpop",
    "kv_lindex", "kv_lset", "kv_linsert",
    "kv_lpushx", "kv_rpushx", "kv_ltrim", "kv_lmove",
    "kv_sadd", "kv_smembers", "kv_sscan", "kv_scard", "kv_srem", "kv_sismember",
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
        elif op_name == "kv_hscan":
            # HSCAN came back as [cursor, [field, value, ...]]
            # inside the transaction; shape it like the standalone
            # tool does, into one page with its resume cursor.
            value = hscan_result(
                reply, op.get("batch_size", DEFAULT_SCAN_BATCH_SIZE)
            )
        elif op_name == "kv_zscan":
            # ZSCAN came back as [cursor, [member, ...]] (or with
            # WITHSCORES, [member, score, ...]) inside the
            # transaction; shape it like the standalone tool does,
            # into one page with its resume cursor.
            value = zscan_result(
                reply, op.get("batch_size", DEFAULT_SCAN_BATCH_SIZE),
                op.get("withscores", False),
            )
        elif op_name == "kv_sscan":
            # SSCAN came back as [cursor, [member, ...]] inside the
            # transaction; shape it like the standalone tool does,
            # into one page with its resume cursor.
            value = sscan_result(
                reply, op.get("batch_size", DEFAULT_SCAN_BATCH_SIZE)
            )
        elif op_name in ("kv_hkeys", "kv_hvals"):
            # HKEYS/HVALS came back as a flat list inside the
            # transaction; a hash wider than the cap is recorded as
            # this op's error, in place, like an EXEC-time failure
            # — the rest still run.
            fields = list(reply or [])
            if len(fields) > MAX_HASH_FIELDS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "%s returns at most %d fields; "
                              "the hash is larger"
                              % (op_name, MAX_HASH_FIELDS)})
                continue
            value = fields
        elif op_name == "kv_hincrbyfloat":
            # HINCRBYFLOAT came back as a bulk string inside the
            # transaction; parse it like the standalone tool does.
            value = float(reply)
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
        elif op_name == "kv_zrangebylex":
            # ZRANGEBYLEX came back as a flat list inside the
            # transaction; shape it like the standalone tool does.
            # A range wider than the cap is recorded as this op's
            # error, in place, like an EXEC-time failure — the rest
            # still run.
            members = _zrange_result(reply or [], False)
            if len(members) > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_zrangebylex returns at most %d "
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
        elif op_name in ("kv_zpopmin", "kv_zpopmax"):
            # ZPOPMIN/ZPOPMAX came back as a flat list inside the
            # transaction; shape it like the standalone tool does,
            # into member/score objects.
            value = _zpop_result(reply or [])
        elif op_name == "kv_zrandmember":
            # ZRANDMEMBER came back as one bulk string (or nil) for
            # a bare call, or a flat list for a count call; shape
            # the count form like the standalone tool does,
            # including the withscores member/score objects.
            _key, count, withscores = _zrandmember_args(op)
            value = _zrandmember_result(reply, count, withscores)
        elif op_name == "kv_zscore":
            # ZSCORE came back as a bulk score string (or nil) inside
            # the transaction; parse it like the standalone tool does.
            value = None if reply is None else float(reply)
        elif op_name == "kv_zmscore":
            # ZMSCORE came back as a list of bulk score strings (or
            # nils) inside the transaction; shape it like the
            # standalone tool does.
            value = _zmscore_result(reply)
        elif op_name == "kv_zunion":
            # ZUNION came back as a flat list inside the
            # transaction; shape it like the standalone tool does,
            # including the withscores member/score objects. A union
            # wider than the cap is recorded as this op's error, in
            # place, like an EXEC-time failure — the rest still run.
            members = _zrange_result(reply or [],
                                     _zunion_args(op)[1])
            if len(members) > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_zunion returns at most %d members; "
                              "the union is larger"
                              % MAX_ZRANGE_MEMBERS})
                continue
            value = members
        elif op_name == "kv_zinter":
            # ZINTER came back as a flat list inside the
            # transaction; shape it like the standalone tool does,
            # including the withscores member/score objects. An
            # intersection wider than the cap is recorded as this
            # op's error, in place, like an EXEC-time failure —
            # the rest still run.
            members = _zrange_result(reply or [],
                                     _zinter_args(op)[1])
            if len(members) > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_zinter returns at most %d members; "
                              "the intersection is larger"
                              % MAX_ZRANGE_MEMBERS})
                continue
            value = members
        elif op_name == "kv_zdiff":
            # ZDIFF came back as a flat list inside the
            # transaction; shape it like the standalone tool does,
            # including the withscores member/score objects. A
            # difference wider than the cap is recorded as this
            # op's error, in place, like an EXEC-time failure —
            # the rest still run.
            members = _zrange_result(reply or [],
                                     _zdiff_args(op)[1])
            if len(members) > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_zdiff returns at most %d members; "
                              "the difference is larger"
                              % MAX_ZRANGE_MEMBERS})
                continue
            value = members
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


def _hscan_args(args, tool="kv_hscan"):
    """The validated (key, pattern, batch_size, cursor) for a
    kv_hscan call. Bad values fail up front instead of sending a
    half-formed HSCAN, in the standalone tool and in a batch.
    kv_zscan and kv_sscan share the same shape, so they pass
    tool="kv_zscan" / "kv_sscan" and get their own name in the
    errors."""
    key = _require(args, "key")
    pattern = args.get("pattern", "*")
    if not isinstance(pattern, str):
        raise ValueError("%s pattern must be a string" % tool)
    batch_size = validate_batch_size(
        args.get("batch_size", DEFAULT_SCAN_BATCH_SIZE)
    )
    cursor = args.get("cursor", "")
    if not isinstance(cursor, str):
        raise ValueError("%s cursor must be a string" % tool)
    if cursor and not cursor.isdigit():
        raise ValueError(
            "%s cursor must be a decimal %s cursor string"
            % (tool, {"kv_hscan": "HSCAN", "kv_zscan": "ZSCAN",
                      "kv_sscan": "SSCAN"}[tool])
        )
    return key, pattern, batch_size, cursor


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


def _call_hscan(client, args):
    """kv_hscan: one bounded page of a hash from one real HSCAN
    call. Returns {"fields": {...}, "cursor": str, "done": bool,
    "batch_size": n}. Bad key/batch_size/cursor values fail the call
    instead of silently ignoring the caller."""
    key, pattern, batch_size, cursor = _hscan_args(args)
    return hscan_batch(client, key, pattern, cursor, batch_size)


def _zscan_args(args):
    """The validated (key, pattern, batch_size, cursor, withscores)
    for a kv_zscan call. Bad values fail up front instead of
    sending a half-formed ZSCAN, in the standalone tool and in a
    batch."""
    key, pattern, batch_size, cursor = _hscan_args(args, "kv_zscan")
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zscan withscores must be true or false")
    return key, pattern, batch_size, cursor, withscores


def _call_zscan(client, args):
    """kv_zscan: one bounded page of a sorted set from one real
    ZSCAN call. Returns {"members": [...], "cursor": str, "done":
    bool, "batch_size": n}, with member/score objects when
    withscores is true. Bad key/batch_size/cursor values fail the
    call instead of silently ignoring the caller."""
    key, pattern, batch_size, cursor, withscores = _zscan_args(args)
    return zscan_batch(client, key, pattern, cursor, batch_size,
                       withscores)


def _call_sscan(client, args):
    """kv_sscan: one bounded page of a set from one real SSCAN
    call. Returns {"members": [...], "cursor": str, "done": bool,
    "batch_size": n}. Bad key/batch_size/cursor values fail the
    call instead of silently ignoring the caller."""
    key, pattern, batch_size, cursor = _hscan_args(args, "kv_sscan")
    return sscan_batch(client, key, pattern, cursor, batch_size)


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
    if name == "kv_dbsize":
        # DBSIZE takes no arguments; cinder replies with the key
        # count as an integer.
        return ["DBSIZE"]
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
    if name == "kv_append":
        return ["APPEND", _require(args, "key"), _require(args, "value")]
    if name == "kv_strlen":
        return ["STRLEN", _require(args, "key")]
    if name == "kv_decr":
        # Like kv_incr: DECR for the default step of 1, DECRBY
        # otherwise, so a plain kv_decr sends the plain command.
        by = args.get("by", 1)
        if by == 1:
            return ["DECR", _require(args, "key")]
        return ["DECRBY", _require(args, "key"), by]
    if name == "kv_decrby":
        key, by = _decrby_args(args)
        return ["DECRBY", key, by]
    if name == "kv_getex":
        key, ex, px, persist = _getex_args(args)
        if ex is not None:
            return ["GETEX", key, "EX", ex]
        if px is not None:
            return ["GETEX", key, "PX", px]
        if persist:
            return ["GETEX", key, "PERSIST"]
        return ["GETEX", key]
    if name == "kv_getrange":
        key, start, stop = _getrange_args(args)
        return ["GETRANGE", key, start, stop]
    if name == "kv_setrange":
        key, offset, value = _setrange_args(args)
        return ["SETRANGE", key, offset, value]
    if name == "kv_setbit":
        key, offset, bit = _setbit_args(args)
        return ["SETBIT", key, offset, bit]
    if name == "kv_getbit":
        key, offset = _bit_offset_args(args, "kv_getbit")
        return ["GETBIT", key, offset]
    if name == "kv_bitcount":
        key, start, end = _bitcount_args(args)
        if start is None:
            return ["BITCOUNT", key]
        return ["BITCOUNT", key, start, end]
    if name == "kv_bitop":
        operation, destination, sources = _bitop_args(args)
        return ["BITOP", operation, destination] + list(sources)
    if name == "kv_bitfield":
        return _bitfield_argv(args)
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
    if name == "kv_hmget":
        return ["HMGET", _require(args, "key")] + _hash_fields_args(args, name)
    if name == "kv_hsetnx":
        return ["HSETNX", _require(args, "key"), _require(args, "field"),
                _require(args, "value")]
    if name == "kv_hincrby":
        key, field, increment = _hincrby_args(args)
        return ["HINCRBY", key, field, increment]
    if name == "kv_hscan":
        key, pattern, batch_size, cursor = _hscan_args(args)
        return ["HSCAN", key, cursor or "0", "MATCH", pattern,
                "COUNT", batch_size]
    if name == "kv_hkeys":
        return ["HKEYS", _require(args, "key")]
    if name == "kv_hvals":
        return ["HVALS", _require(args, "key")]
    if name == "kv_hincrbyfloat":
        key, field, increment = _hincrbyfloat_args(args)
        return ["HINCRBYFLOAT", key, field, increment]
    if name == "kv_zadd":
        return (["ZADD", _require(args, "key")] + _zadd_options(args)
                + _zadd_member_args(args))
    if name == "kv_zcard":
        return ["ZCARD", _require(args, "key")]
    if name == "kv_zscore":
        return ["ZSCORE", _require(args, "key"), _require(args, "member")]
    if name == "kv_zmscore":
        return ["ZMSCORE", _require(args, "key")] + _zmscore_members_args(args)
    if name == "kv_zrank":
        return ["ZRANK", _require(args, "key"), _require(args, "member")]
    if name == "kv_zrem":
        return ["ZREM", _require(args, "key")] + _zrem_member_args(args)
    if name == "kv_zremrangebyscore":
        key, min_b, max_b = _zremrangebyscore_args(args)
        return ["ZREMRANGEBYSCORE", key, min_b, max_b]
    if name == "kv_zremrangebyrank":
        key, start, stop = _zremrangebyrank_args(args)
        return ["ZREMRANGEBYRANK", key, start, stop]
    if name == "kv_zremrangebylex":
        key, min_b, max_b = _zremrangebylex_args(args)
        return ["ZREMRANGEBYLEX", key, min_b, max_b]
    if name == "kv_zincrby":
        key, increment, member = _zincrby_args(args)
        return ["ZINCRBY", key, increment, member]
    if name == "kv_zpopmin":
        key, count = _zpop_args(args, name)
        return ["ZPOPMIN", key] if count == 1 else ["ZPOPMIN", key, count]
    if name == "kv_zpopmax":
        key, count = _zpop_args(args, name)
        return ["ZPOPMAX", key] if count == 1 else ["ZPOPMAX", key, count]
    if name == "kv_zrandmember":
        key, count, withscores = _zrandmember_args(args)
        cmd = ["ZRANDMEMBER", key]
        if count is not None:
            cmd.append(count)
            if withscores:
                cmd.append("WITHSCORES")
        return cmd
    if name == "kv_zscan":
        key, pattern, batch_size, cursor, withscores = _zscan_args(args)
        cmd = ["ZSCAN", key, cursor or "0", "MATCH", pattern,
               "COUNT", batch_size]
        if withscores:
            cmd.append("WITHSCORES")
        return cmd
    if name == "kv_zunion":
        keys, withscores = _zunion_args(args)
        cmd = ["ZUNION", len(keys)] + list(keys)
        if withscores:
            cmd.append("WITHSCORES")
        return cmd
    if name == "kv_zinter":
        keys, weights, aggregate, withscores = _zinter_args(args)
        cmd = ["ZINTER", len(keys)] + list(keys)
        if weights is not None:
            cmd.append("WEIGHTS")
            cmd += [repr(weight) for weight in weights]
        if aggregate is not None:
            cmd += ["AGGREGATE", aggregate.upper()]
        if withscores:
            cmd.append("WITHSCORES")
        return cmd
    if name == "kv_zdiff":
        keys, withscores = _zdiff_args(args)
        cmd = ["ZDIFF", len(keys)] + list(keys)
        if withscores:
            cmd.append("WITHSCORES")
        return cmd
    if name == "kv_sscan":
        key, pattern, batch_size, cursor = _hscan_args(args, "kv_sscan")
        return ["SSCAN", key, cursor or "0", "MATCH", pattern,
                "COUNT", batch_size]
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
    if name == "kv_lindex":
        key, index = _list_index_args(args, name)
        return ["LINDEX", key, index]
    if name == "kv_lset":
        key, index, value = _lset_args(args)
        return ["LSET", key, index, value]
    if name == "kv_linsert":
        key, where, pivot, element = _linsert_args(args)
        return ["LINSERT", key, where, pivot, element]
    if name == "kv_lpushx":
        return ["LPUSHX", _require(args, "key")] + _list_elements_args(args, name)
    if name == "kv_rpushx":
        return ["RPUSHX", _require(args, "key")] + _list_elements_args(args, name)
    if name == "kv_ltrim":
        key, start, stop = _ltrim_args(args)
        return ["LTRIM", key, start, stop]
    if name == "kv_lmove":
        source, destination, from_side, to_side = _lmove_args(args)
        return ["LMOVE", source, destination, from_side, to_side]
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
    if name == "kv_zrangebylex":
        key, min_b, max_b, rev, offset, count = _zrangebylex_args(args)
        # The reply is capped at MAX_ZRANGE_MEMBERS members: an
        # explicit count is sent as given (already checked against
        # the cap); without one, ask for one extra member so the
        # caller can tell the range was too wide instead of getting
        # a silently truncated list. With REV the bounds go
        # max-first, as cinder reads them; without it, min first.
        probe = count if count >= 0 else MAX_ZRANGE_MEMBERS + 1
        cmd = ["ZRANGEBYLEX", key]
        cmd += [max_b, min_b] if rev else [min_b, max_b]
        cmd += ["LIMIT", offset, probe]
        if rev:
            cmd.append("REV")
        return cmd
    if name == "kv_zlexcount":
        key, min_b, max_b = _zlexcount_args(args)
        return ["ZLEXCOUNT", key, min_b, max_b]
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


# The most members one kv_zmscore call reads; a wider call fails
# instead of dumping a huge slice of the sorted set into one tool
# result.
MAX_ZMSCORE_MEMBERS = 1000


def _zmscore_members_args(args):
    """The member names for a ZMSCORE, as an argv list. `members`
    must be a non-empty list of strings, at most
    MAX_ZMSCORE_MEMBERS; anything else fails the call instead of
    sending a half-formed ZMSCORE."""
    members = args.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("kv_zmscore members must be a non-empty list")
    if len(members) > MAX_ZMSCORE_MEMBERS:
        raise ValueError(
            "kv_zmscore reads at most %d members; narrow the list"
            % MAX_ZMSCORE_MEMBERS
        )
    for member in members:
        if not isinstance(member, str):
            raise ValueError("kv_zmscore members must be strings")
    return list(members)


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


def _decrby_args(args):
    """Validate a kv_decrby call: (key, by). The step must be an
    integer — cinder rejects anything else as a server error, so
    fail here as invalid params instead. Any integer goes through,
    including a negative one (DECRBY with a negative step counts
    up, as in Redis)."""
    key = _require(args, "key")
    by = _require(args, "by")
    if isinstance(by, bool) or not isinstance(by, int):
        raise ValueError("kv_decrby by must be an integer")
    return key, by


def _getex_args(args):
    """Validate a kv_getex call: (key, ex, px, persist). At most
    one of ex / px / persist may be given — cinder rejects a
    second option as a syntax error, so fail here as invalid
    params instead. ex and px are seconds and milliseconds and
    must be integers greater than 0, like kv_setex's seconds;
    persist must be a boolean. No option leaves the TTL alone."""
    key = _require(args, "key")
    ex = args.get("ex")
    px = args.get("px")
    persist = args.get("persist", False)
    if not isinstance(persist, bool):
        raise ValueError("kv_getex persist must be true or false")
    given = [name for name, value in (("ex", ex), ("px", px))
             if value is not None]
    if persist:
        given.append("persist")
    if len(given) > 1:
        raise ValueError(
            "kv_getex takes at most one of ex, px, persist"
        )
    if ex is not None:
        if isinstance(ex, bool) or not isinstance(ex, int):
            raise ValueError("kv_getex ex must be an integer")
        if ex <= 0:
            raise ValueError(
                "kv_getex ex must be more than 0, got %d" % ex
            )
    if px is not None:
        if isinstance(px, bool) or not isinstance(px, int):
            raise ValueError("kv_getex px must be an integer")
        if px <= 0:
            raise ValueError(
                "kv_getex px must be more than 0, got %d" % px
            )
    return key, ex, px, persist


def _getrange_args(args):
    """Validate a kv_getrange call: (key, start, stop). start
    defaults to 0 and stop to -1, as in Redis; negative indices
    count from the end and out-of-range ends are clamped by
    cinder. Bad types fail the call instead of sending a
    half-formed GETRANGE."""
    key = _require(args, "key")
    start = args.get("start", 0)
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("kv_getrange start must be an integer")
    stop = args.get("stop", -1)
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError("kv_getrange stop must be an integer")
    return key, start, stop


def _setrange_args(args):
    """Validate a kv_setrange call: (key, offset, value). The
    offset must be an integer 0 or more — cinder rejects a
    negative offset as a server error, so fail here as invalid
    params instead — and the value must be a string. An empty
    value is allowed through: cinder answers with the current
    length (or 0 for a missing key) and changes nothing."""
    key = _require(args, "key")
    offset = _require(args, "offset")
    value = _require(args, "value")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("kv_setrange offset must be an integer")
    if offset < 0:
        raise ValueError(
            "kv_setrange offset must be 0 or more, got %d" % offset
        )
    if not isinstance(value, str):
        raise ValueError("kv_setrange value must be a string")
    return key, offset, value


# The largest bit offset cinder accepts: 2^32 - 1, as in Redis.
MAX_BIT_OFFSET = 4294967295


def _bit_offset_args(args, name):
    """Validate a kv_setbit / kv_getbit call: (key, offset). The
    offset must be an integer from 0 to MAX_BIT_OFFSET — cinder
    rejects anything else as a server error, so fail here as
    invalid params instead."""
    key = _require(args, "key")
    offset = _require(args, "offset")
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("%s offset must be an integer" % name)
    if offset < 0 or offset > MAX_BIT_OFFSET:
        raise ValueError(
            "%s offset must be between 0 and %d, got %d"
            % (name, MAX_BIT_OFFSET, offset)
        )
    return key, offset


def _setbit_args(args):
    """Validate a kv_setbit call: (key, offset, bit). The bit must
    be 0 or 1 — cinder rejects anything else as a server error,
    so fail here as invalid params instead."""
    key, offset = _bit_offset_args(args, "kv_setbit")
    bit = _require(args, "bit")
    if isinstance(bit, bool) or not isinstance(bit, int):
        raise ValueError("kv_setbit bit must be an integer")
    if bit not in (0, 1):
        raise ValueError("kv_setbit bit must be 0 or 1, got %d" % bit)
    return key, offset, bit


def _bitcount_args(args):
    """Validate a kv_bitcount call: (key, start, end). start and
    end are byte indexes, both or neither — cinder rejects a call
    with only one bound as a wrong number of arguments, so fail
    here as invalid params instead. Negative indexes count from
    the end and out-of-range ends are clamped by cinder. There is
    no BYTE|BIT mode in cinder: BITCOUNT key 0 -1 BIT is a wrong
    number of arguments there, so the tool does not offer it."""
    key = _require(args, "key")
    start = args.get("start")
    end = args.get("end")
    if (start is None) != (end is None):
        raise ValueError(
            "kv_bitcount takes start and end together, or neither"
        )
    if start is not None:
        if isinstance(start, bool) or not isinstance(start, int):
            raise ValueError("kv_bitcount start must be an integer")
        if isinstance(end, bool) or not isinstance(end, int):
            raise ValueError("kv_bitcount end must be an integer")
    return key, start, end


def _bitop_args(args):
    """Validate a kv_bitop call: (operation, destination, sources).
    `operation` is "and", "or", "xor" or "not" in any case, sent
    uppercase; `sources` is a non-empty list of key names. NOT
    takes exactly one source and the rest take at least two —
    cinder rejects the wrong count as a server error, so fail
    here as invalid params instead. An unknown operation is a
    syntax error in cinder, so fail here too. The argument is
    called `operation`, not `op`: inside kv_batch each op already
    carries an "op" naming the tool, so a bitop "op" would
    collide with it."""
    operation = _require(args, "operation")
    if not isinstance(operation, str) \
            or operation.lower() not in ("and", "or", "xor", "not"):
        raise ValueError(
            "kv_bitop operation must be \"and\", \"or\", \"xor\" or "
            "\"not\""
        )
    operation = operation.upper()
    destination = _require(args, "destination")
    if not isinstance(destination, str):
        raise ValueError("kv_bitop destination must be a string")
    sources = args.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("kv_bitop sources must be a non-empty list")
    for source in sources:
        if not isinstance(source, str):
            raise ValueError("kv_bitop sources must be strings")
    if operation == "NOT":
        if len(sources) != 1:
            raise ValueError(
                "kv_bitop NOT takes exactly one source key"
            )
    elif len(sources) < 2:
        raise ValueError(
            "kv_bitop %s takes at least two source keys" % operation
        )
    return operation, destination, sources


# BITFIELD field widths: signed i1..i64, unsigned u1..u63 — cinder
# rejects u64 because a u64 field cannot come back as a signed
# 64-bit RESP integer. A field must end inside a 512 MB string:
# offset + bits <= 2^32, as in Redis.
MAX_BITFIELD_END = 4294967296

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1


def _parse_bitfield_type(type_name):
    """Validate a BITFIELD encoding: i1..i64 or u1..u63, any case.
    Returns (is_signed, bits, canonical_type). cinder rejects
    anything else as a server error, so fail here as invalid
    params instead."""
    if not isinstance(type_name, str):
        raise ValueError(
            "kv_bitfield type must be a string like 'i8' or 'u8', "
            "got %r" % (type_name,)
        )
    text = type_name.lower()
    if len(text) < 2 or text[0] not in ("i", "u") \
            or not text[1:].isdigit():
        raise ValueError(
            "kv_bitfield type must be like 'i8' or 'u8', got %r"
            % (type_name,)
        )
    bits = int(text[1:])
    if bits < 1 or bits > 64:
        raise ValueError(
            "kv_bitfield type must be i1..i64 or u1..u63, got %r"
            % (type_name,)
        )
    if text[0] == "u" and bits == 64:
        raise ValueError(
            "kv_bitfield type 'u64' is not supported: a u64 field "
            "cannot come back as a signed 64-bit integer"
        )
    return text[0] == "i", bits, text


def _parse_bitfield_offset(offset, bits):
    """Validate a BITFIELD offset for a field of `bits` width: a
    plain integer is a bit offset; '#n' is the n-th field of that
    width, so its bit offset is n * bits. Returns (bit_offset,
    argv_text). The field must end inside 2^32 bits — cinder
    rejects anything else as a server error, so fail here as
    invalid params instead."""
    max_off = MAX_BITFIELD_END - bits
    if isinstance(offset, bool):
        raise ValueError(
            "kv_bitfield offset must be an integer or '#n', got %r"
            % (offset,)
        )
    if isinstance(offset, int):
        if offset < 0 or offset > max_off:
            raise ValueError(
                "kv_bitfield offset must be between 0 and %d for a "
                "%d-bit field, got %d" % (max_off, bits, offset)
            )
        return offset, str(offset)
    if isinstance(offset, str) and offset.startswith("#") \
            and offset[1:].isdigit():
        n = int(offset[1:])
        if n > max_off // bits:
            raise ValueError(
                "kv_bitfield offset '#%d' runs past 2^32 bits for a "
                "%d-bit field" % (n, bits)
            )
        return n * bits, "#%d" % n
    raise ValueError(
        "kv_bitfield offset must be an integer or '#n', got %r"
        % (offset,)
    )


def _bitfield_argv(args):
    """Validate a kv_bitfield call and build its BITFIELD argv: the
    key plus one argv chunk per op, in order. Each op is an object
    with "op" naming "get", "set", "incrby" or "overflow": get
    takes a type and an offset, set and incrby take a type, an
    offset and a value, overflow takes a "policy" ("wrap", "sat"
    or "fail") that applies to the SET / INCRBY ops that follow
    it. The value must fit a signed 64-bit integer, as cinder's
    integer parse rejects anything wider. At least one op is
    required: an empty call would only ever return []."""
    key = _require(args, "key")
    ops = args.get("ops")
    if not isinstance(ops, list) or not ops:
        raise ValueError("kv_bitfield requires a non-empty ops list")
    argv = ["BITFIELD", key]
    for op in ops:
        if not isinstance(op, dict):
            raise ValueError(
                "kv_bitfield ops must be objects, got %r" % (op,)
            )
        kind = op.get("op")
        if not isinstance(kind, str):
            raise ValueError(
                "kv_bitfield op needs an 'op': %r" % (op,)
            )
        kind = kind.lower()
        if kind == "overflow":
            policy = op.get("policy")
            if not isinstance(policy, str) \
                    or policy.lower() not in ("wrap", "sat", "fail"):
                raise ValueError(
                    "kv_bitfield overflow policy must be 'wrap', "
                    "'sat' or 'fail', got %r" % (policy,)
                )
            argv += ["OVERFLOW", policy.upper()]
            continue
        if kind not in ("get", "set", "incrby"):
            raise ValueError(
                "kv_bitfield op must be 'get', 'set', 'incrby' or "
                "'overflow', got %r" % (kind,)
            )
        _is_signed, bits, type_name = _parse_bitfield_type(op.get("type"))
        _offset, offset_text = _parse_bitfield_offset(
            op.get("offset"), bits)
        if kind == "get":
            argv += ["GET", type_name, offset_text]
            continue
        value = _require(op, "value")
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(
                "kv_bitfield %s value must be an integer, got %r"
                % (kind, value)
            )
        if value < INT64_MIN or value > INT64_MAX:
            raise ValueError(
                "kv_bitfield %s value is not an integer or out of "
                "range: %d" % (kind, value)
            )
        argv += [kind.upper(), type_name, offset_text, value]
    return argv


def _hincrby_args(args):
    """Validate a kv_hincrby call: (key, field, increment). The
    increment must be an integer — cinder rejects anything else as
    a server error, so fail here as invalid params instead. Any
    integer goes through, including a negative one (HINCRBY with a
    negative increment counts down, as in Redis)."""
    key = _require(args, "key")
    field = _require(args, "field")
    increment = _require(args, "increment")
    if isinstance(increment, bool) or not isinstance(increment, int):
        raise ValueError("kv_hincrby increment must be an integer")
    return key, field, increment


def _hincrbyfloat_args(args):
    """Validate a kv_hincrbyfloat call: (key, field, increment).
    The increment must be a finite number — an int or a float, as
    in Redis. cinder rejects a non-float argument as a server
    error and an increment that would overflow as one too, so both
    fail here as invalid params instead: NaN and infinities never
    reach the server. repr round-trips a float exactly, and prints
    an int plainly, so either form parses back in cinder."""
    key = _require(args, "key")
    field = _require(args, "field")
    increment = _require(args, "increment")
    if isinstance(increment, bool) or not isinstance(increment, (int, float)):
        raise ValueError("kv_hincrbyfloat increment must be a number")
    if isinstance(increment, float) and (
        increment != increment
        or increment in (float("inf"), float("-inf"))
    ):
        raise ValueError(
            "kv_hincrbyfloat increment must be a finite number"
        )
    return key, field, repr(increment)


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


def _zmscore_result(reply):
    """Shape a ZMSCORE reply into the tool's return value: one score
    per member, in request order, as a number, or null for a member
    that is not in the set (cinder replies nil for those, and for
    every member when the key does not exist)."""
    return [None if score is None else float(score) for score in (reply or [])]


def _call_zmscore(client, args):
    """kv_zmscore: the scores of several members at once, in request
    order, with null for a member that is not in the set."""
    return _zmscore_result(client.command(*_op_argv("kv_zmscore", args)))


# The most keys one kv_zunion call reads; a wider call fails
# instead of sending a half-formed ZUNION with a huge argv.
MAX_ZUNION_KEYS = 1000


def _zunion_args(args):
    """Validate a kv_zunion call: (keys, withscores). `keys` must
    be a non-empty list of string key names, at most
    MAX_ZUNION_KEYS; `withscores` must be a boolean. Anything else
    fails the call instead of sending a half-formed ZUNION."""
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("kv_zunion keys must be a non-empty list")
    if len(keys) > MAX_ZUNION_KEYS:
        raise ValueError(
            "kv_zunion reads at most %d keys; narrow the list"
            % MAX_ZUNION_KEYS
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError("kv_zunion keys must be strings")
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zunion withscores must be true or false")
    return list(keys), withscores


def _zunion_result(flat, withscores):
    """Shape a flat ZUNION reply into the tool's return value, a
    list of member names in score order, or with withscores a list
    of {"member": ..., "score": ...} objects, and fail when the
    union holds more than MAX_ZRANGE_MEMBERS members — cinder has
    no LIMIT for ZUNION, so the reply is checked after the fact
    instead of asking for one member too many, as kv_zrangebyscore
    does. The caller must union fewer or smaller sets instead of
    getting a silently truncated list."""
    members = _zrange_result(flat, withscores)
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zunion returns at most %d members; the union is larger"
            % MAX_ZRANGE_MEMBERS
        )
    return members


def _call_zunion(client, args):
    """kv_zunion: the union of several sorted sets, a member in
    several sets appearing once with the sum of its scores, lowest
    score first. A missing key counts as an empty set, as in
    cinder. The call is read-only: the sets are untouched, so the
    audit treats it as a read op."""
    return _zunion_result(
        client.command(*_op_argv("kv_zunion", args)) or [],
        _zunion_args(args)[1],
    )


# The most keys one kv_zinter call reads; a wider call fails
# instead of sending a half-formed ZINTER with a huge argv.
MAX_ZINTER_KEYS = 1000

# How a member's scores combine across the sets: the default,
# "sum", adds the weighted scores; "min" and "max" take the
# smallest and largest. Cinder spells them uppercase on the wire.
ZINTER_AGGREGATES = ("sum", "min", "max")


def _zinter_args(args):
    """Validate a kv_zinter call: (keys, weights, aggregate,
    withscores). `keys` must be a non-empty list of string key
    names, at most MAX_ZINTER_KEYS; `weights`, when given, must be
    a list of numbers, one per key (NaN is rejected — cinder
    rejects it too); `aggregate`, when given, must be "sum", "min"
    or "max" (any case); `withscores` must be a boolean. Anything
    else fails the call instead of sending a half-formed ZINTER.
    Weights and aggregate default to None, meaning the tool sends
    neither option and cinder weights every set by 1 and sums."""
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("kv_zinter keys must be a non-empty list")
    if len(keys) > MAX_ZINTER_KEYS:
        raise ValueError(
            "kv_zinter reads at most %d keys; narrow the list"
            % MAX_ZINTER_KEYS
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError("kv_zinter keys must be strings")
    weights = args.get("weights")
    if weights is not None:
        if not isinstance(weights, list):
            raise ValueError("kv_zinter weights must be a list")
        if len(weights) != len(keys):
            raise ValueError(
                "kv_zinter weights must have one weight per key"
            )
        for weight in weights:
            if isinstance(weight, bool) or not isinstance(
                    weight, (int, float)):
                raise ValueError(
                    "kv_zinter weights must be numbers")
            if isinstance(weight, float) and weight != weight:
                raise ValueError(
                    "kv_zinter weights must not be NaN")
    aggregate = args.get("aggregate")
    if aggregate is not None:
        if not isinstance(aggregate, str):
            raise ValueError("kv_zinter aggregate must be a string")
        if aggregate.lower() not in ZINTER_AGGREGATES:
            raise ValueError(
                "kv_zinter aggregate must be sum, min or max")
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zinter withscores must be true or false")
    return list(keys), weights, aggregate, withscores


def _zinter_result(flat, withscores):
    """Shape a flat ZINTER reply into the tool's return value, a
    list of member names in score order, or with withscores a list
    of {"member": ..., "score": ...} objects, and fail when the
    intersection holds more than MAX_ZRANGE_MEMBERS members —
    cinder has no LIMIT for ZINTER, so the reply is checked after
    the fact instead of asking for one member too many, as
    kv_zrangebyscore does. The caller must intersect fewer or
    smaller sets instead of getting a silently truncated list."""
    members = _zrange_result(flat, withscores)
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zinter returns at most %d members; the intersection "
            "is larger" % MAX_ZRANGE_MEMBERS
        )
    return members


def _call_zinter(client, args):
    """kv_zinter: the intersection of several sorted sets, a
    member appearing once only when it is in every set, with its
    weighted scores combined by the aggregate, lowest score first.
    A missing key counts as an empty set, so an intersection with
    one is empty, as in cinder. The call is read-only: the sets
    are untouched, so the audit treats it as a read op."""
    return _zinter_result(
        client.command(*_op_argv("kv_zinter", args)) or [],
        _zinter_args(args)[3],
    )


# The most keys one kv_zdiff call reads; a wider call fails
# instead of sending a half-formed ZDIFF with a huge argv.
MAX_ZDIFF_KEYS = 1000


def _zdiff_args(args):
    """Validate a kv_zdiff call: (keys, withscores). `keys` must
    be a non-empty list of string key names, at most
    MAX_ZDIFF_KEYS; `withscores` must be a boolean. Anything else
    fails the call instead of sending a half-formed ZDIFF."""
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("kv_zdiff keys must be a non-empty list")
    if len(keys) > MAX_ZDIFF_KEYS:
        raise ValueError(
            "kv_zdiff reads at most %d keys; narrow the list"
            % MAX_ZDIFF_KEYS
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError("kv_zdiff keys must be strings")
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zdiff withscores must be true or false")
    return list(keys), withscores


def _zdiff_result(flat, withscores):
    """Shape a flat ZDIFF reply into the tool's return value, a
    list of member names in the first set's score order, or with
    withscores a list of {"member": ..., "score": ...} objects,
    and fail when the difference holds more than
    MAX_ZRANGE_MEMBERS members — cinder has no LIMIT for ZDIFF,
    so the reply is checked after the fact instead of asking for
    one member too many, as kv_zrangebyscore does. The caller
    must diff fewer or smaller sets instead of getting a silently
    truncated list."""
    members = _zrange_result(flat, withscores)
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zdiff returns at most %d members; the difference "
            "is larger" % MAX_ZRANGE_MEMBERS
        )
    return members


def _call_zdiff(client, args):
    """kv_zdiff: the members of the first sorted set that are in
    none of the other sets, once each, in the first set's score
    order with the first set's scores. A missing key counts as an
    empty set, so a difference against only missing keys is the
    whole first set and a missing first key diffs to nothing, as
    in cinder. The call is read-only: the sets are untouched, so
    the audit treats it as a read op."""
    return _zdiff_result(
        client.command(*_op_argv("kv_zdiff", args)) or [],
        _zdiff_args(args)[1],
    )


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


def _format_lex_bound(value, side, tool="kv_zrangebylex"):
    """One ZRANGEBYLEX bound as a RESP argument: "-" is -inf (min
    only), "+" is +inf (max only), "[x" is inclusive and "(x"
    exclusive, exactly as cinder's lex-bound parser reads them. A
    bare member name is a syntax error in cinder, so fail here as
    invalid params instead; so is the wrong infinity on a side, an
    empty bracket, and anything that is not a string."""
    if not isinstance(value, str):
        raise ValueError(
            "%s %s bound must be a string, got %r" % (tool, side, value)
        )
    if value == "-":
        if side != "min":
            raise ValueError(
                "%s max bound must not be \"-\"" % tool
            )
        return value
    if value == "+":
        if side != "max":
            raise ValueError(
                "%s min bound must not be \"+\"" % tool
            )
        return value
    if value.startswith(("[", "(")) and len(value) > 1:
        return value
    raise ValueError(
        "%s %s bound %r is not a valid lex bound: use \"-\", \"+\", "
        "\"[member\" or \"(member\"" % (tool, side, value)
    )


def _zrangebylex_args(args):
    """Validate a kv_zrangebylex call: (key, min, max, rev, offset,
    count). min defaults to "-" and max to "+", as in Redis; offset
    defaults to 0 and count to -1, meaning all matches from the
    offset. count is at most MAX_ZRANGE_MEMBERS, and an offset below
    0 or a count below -1 fails the call instead of sending a
    half-formed ZRANGEBYLEX. There is no withscores: cinder reads
    WITHSCORES as a syntax error, so the tool does not offer it."""
    key = _require(args, "key")
    min_b = _format_lex_bound(args.get("min", "-"), "min")
    max_b = _format_lex_bound(args.get("max", "+"), "max")
    rev = args.get("rev", False)
    if not isinstance(rev, bool):
        raise ValueError("kv_zrangebylex rev must be true or false")
    offset = args.get("offset", 0)
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("kv_zrangebylex offset must be an integer")
    if offset < 0:
        raise ValueError("kv_zrangebylex offset must be 0 or more")
    count = args.get("count", -1)
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("kv_zrangebylex count must be an integer")
    if count < -1:
        raise ValueError("kv_zrangebylex count must be -1 or more")
    if count > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zrangebylex returns at most %d members; narrow the "
            "range or pass a smaller count" % MAX_ZRANGE_MEMBERS
        )
    return key, min_b, max_b, rev, offset, count


def _zrangebylex_result(flat):
    """Shape a flat ZRANGEBYLEX reply into the tool's return value,
    a list of member names in lex order, and fail when the probe
    asked for one extra member and got it — the range holds more
    than MAX_ZRANGE_MEMBERS members, so the caller must narrow it
    or pass a limit instead of getting a silently truncated list."""
    members = _zrange_result(flat, False)
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "kv_zrangebylex returns at most %d members; narrow the "
            "range or pass a limit" % MAX_ZRANGE_MEMBERS
        )
    return members


def _call_zrangebylex(client, args):
    """kv_zrangebylex: run ZRANGEBYLEX and shape the reply. The
    argv always carries a LIMIT (see _op_argv), so a range wider
    than the cap is caught from the reply. The call is read-only:
    the set is untouched, so the audit treats it as a read op."""
    return _zrangebylex_result(
        client.command(*_op_argv("kv_zrangebylex", args)) or []
    )


def _zremrangebyscore_args(args):
    """Validate a kv_zremrangebyscore call: (key, min, max). The
    bounds parse exactly like kv_zrangebyscore's: numbers or
    strings with an optional leading '(' for exclusivity,
    -inf/+inf by default."""
    key = _require(args, "key")
    min_b = _format_score_bound(args.get("min", "-inf"),
                                "kv_zremrangebyscore")
    max_b = _format_score_bound(args.get("max", "+inf"),
                                "kv_zremrangebyscore")
    return key, min_b, max_b


def _zremrangebyrank_args(args):
    """Validate a kv_zremrangebyrank call: (key, start, stop).
    start defaults to 0 and stop to -1, as in ZRANGE; negative
    indices count from the end. Bad types fail the call instead
    of sending a half-formed ZREMRANGEBYRANK."""
    key = _require(args, "key")
    start = args.get("start", 0)
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("kv_zremrangebyrank start must be an integer")
    stop = args.get("stop", -1)
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError("kv_zremrangebyrank stop must be an integer")
    return key, start, stop


def _zremrangebylex_args(args):
    """Validate a kv_zremrangebylex call: (key, min, max). The
    bounds parse exactly like kv_zrangebylex's: "-" / "+" or "[x"
    / "(x", defaulting to "-" / "+". There is no REV: the removed
    set does not depend on order, so the bounds are always min
    first. A bare member, the wrong infinity, or a non-string
    bound fails the call as invalid params instead of as a
    server error."""
    key = _require(args, "key")
    min_b = _format_lex_bound(args.get("min", "-"), "min",
                              "kv_zremrangebylex")
    max_b = _format_lex_bound(args.get("max", "+"), "max",
                              "kv_zremrangebylex")
    return key, min_b, max_b


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


def _zlexcount_args(args):
    """Validate a kv_zlexcount call: (key, min, max). The bounds parse
    exactly like kv_zrangebylex's: "-" / "+" or "[x" / "(x",
    defaulting to "-" / "+". There is no REV and no LIMIT: the count
    does not depend on order, and cinder counts server-side, so no
    cap applies and no probe member is needed."""
    key = _require(args, "key")
    min_b = _format_lex_bound(args.get("min", "-"), "min", "kv_zlexcount")
    max_b = _format_lex_bound(args.get("max", "+"), "max", "kv_zlexcount")
    return key, min_b, max_b


def _zrevrank_args(args):
    """Validate a kv_zrevrank call: (key, member)."""
    return _require(args, "key"), _require(args, "member")


def _zpop_args(args, name):
    """Validate a kv_zpopmin / kv_zpopmax call: (key, count).
    count defaults to 1 and must be a positive integer — cinder
    rejects 0 or a negative count as out of range, so fail here
    as invalid params instead."""
    key = _require(args, "key")
    count = args.get("count", 1)
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("%s count must be an integer" % name)
    if count < 1:
        raise ValueError(
            "%s count must be 1 or more, got %d" % (name, count)
        )
    return key, count


def _zpop_result(flat):
    """Shape a flat ZPOPMIN/ZPOPMAX reply [member, score, ...] into
    a list of {"member": ..., "score": ...} objects, the scores
    parsed as numbers, lowest score first for ZPOPMIN and highest
    first for ZPOPMAX. A missing key replies as an empty list,
    which becomes []."""
    flat = flat or []
    return [
        {"member": flat[i], "score": float(flat[i + 1])}
        for i in range(0, len(flat), 2)
    ]


def _call_zpop(client, args, name):
    """kv_zpopmin / kv_zpopmax: pop the lowest- / highest-scoring
    member(s) and shape the reply into member/score objects."""
    return _zpop_result(client.command(*_op_argv(name, args)) or [])


# The most members one kv_zrandmember count call returns, in
# either direction: a positive count is naturally capped by the
# set's size, but a negative count samples with replacement and
# is unbounded in cinder, so a huge one would ask it to build a
# huge reply.
MAX_ZRANDMEMBER_COUNT = 1000


def _zrandmember_args(args):
    """Validate a kv_zrandmember call: (key, count, withscores).
    count is optional: without it the call returns one member (or
    null for a missing key); with it, that many members. A
    positive count returns distinct members, a negative count
    samples with replacement, 0 returns an empty list. count is
    at most MAX_ZRANDMEMBER_COUNT in either direction. withscores
    needs a count: cinder reads the second argument as the count,
    so ZRANDMEMBER key WITHSCORES is a syntax error there, not a
    bare call with scores."""
    key = _require(args, "key")
    count = args.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("kv_zrandmember count must be an integer")
        if abs(count) > MAX_ZRANDMEMBER_COUNT:
            raise ValueError(
                "kv_zrandmember count must be between -%d and %d"
                % (MAX_ZRANDMEMBER_COUNT, MAX_ZRANDMEMBER_COUNT)
            )
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("kv_zrandmember withscores must be true or false")
    if withscores and count is None:
        raise ValueError("kv_zrandmember withscores needs a count")
    return key, count, withscores


def _zrandmember_result(reply, count, withscores):
    """Shape a ZRANDMEMBER reply into the tool's return value: a
    bare call returns one member string, or null for a missing
    key; a count call returns a list of member names, or with
    withscores a list of {"member": ..., "score": ...} objects.
    A count of 0 returns an empty list."""
    if count is None:
        return reply
    return _zrange_result(reply or [], withscores)


def _call_zrandmember(client, args):
    """kv_zrandmember: one random member, or `count` of them. A
    positive count returns distinct members (at most the whole
    set), a negative count samples with replacement, 0 returns an
    empty list; withscores pairs each member with its score. The
    call is read-only: the set is untouched, so the audit treats
    it as a read op."""
    key, count, withscores = _zrandmember_args(args)
    return _zrandmember_result(
        client.command(*_op_argv("kv_zrandmember", args)),
        count, withscores,
    )


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


def _list_index_args(args, name):
    """Validate a kv_lindex / kv_lset index: (key, index). The index
    must be an integer; a negative one counts from the end, as in
    Redis. Bad types fail the call instead of sending a half-formed
    LINDEX or LSET."""
    key = _require(args, "key")
    index = _require(args, "index")
    if isinstance(index, bool) or not isinstance(index, int):
        raise ValueError("%s index must be an integer" % name)
    return key, index


def _lset_args(args):
    """Validate a kv_lset call: (key, index, value)."""
    key, index = _list_index_args(args, "kv_lset")
    value = _require(args, "value")
    if not isinstance(value, str):
        raise ValueError("kv_lset value must be a string")
    return key, index, value


def _linsert_args(args):
    """Validate a kv_linsert call: (key, where, pivot, element).
    `where` is \"before\" or \"after\", in any case — cinder compares
    it case-insensitively — and is sent as BEFORE or AFTER. Bad
    values fail the call instead of sending a half-formed LINSERT."""
    key = _require(args, "key")
    where = _require(args, "where")
    if not isinstance(where, str) or where.lower() not in ("before", "after"):
        raise ValueError("kv_linsert where must be \"before\" or \"after\"")
    pivot = _require(args, "pivot")
    if not isinstance(pivot, str):
        raise ValueError("kv_linsert pivot must be a string")
    element = _require(args, "element")
    if not isinstance(element, str):
        raise ValueError("kv_linsert element must be a string")
    return key, where.upper(), pivot, element


def _ltrim_args(args):
    """Validate a kv_ltrim call: (key, start, stop). Both bounds
    are required — cinder takes no defaults — and must be integers;
    negative ones count from the end, as in Redis. Bad types fail
    the call instead of sending a half-formed LTRIM."""
    key = _require(args, "key")
    start = _require(args, "start")
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("kv_ltrim start must be an integer")
    stop = _require(args, "stop")
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError("kv_ltrim stop must be an integer")
    return key, start, stop


def _lmove_args(args):
    """Validate a kv_lmove call: (source, destination, from, to).
    `from` and `to` are "left" or "right" in any case — cinder
    compares them case-insensitively — and are sent as LEFT or
    RIGHT. Bad values fail the call instead of sending a
    half-formed LMOVE."""
    source = _require(args, "source")
    if not isinstance(source, str):
        raise ValueError("kv_lmove source must be a string")
    destination = _require(args, "destination")
    if not isinstance(destination, str):
        raise ValueError("kv_lmove destination must be a string")
    from_side = _require(args, "from")
    if not isinstance(from_side, str) \
            or from_side.lower() not in ("left", "right"):
        raise ValueError("kv_lmove from must be \"left\" or \"right\"")
    to_side = _require(args, "to")
    if not isinstance(to_side, str) \
            or to_side.lower() not in ("left", "right"):
        raise ValueError("kv_lmove to must be \"left\" or \"right\"")
    return source, destination, from_side.upper(), to_side.upper()


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


# The most fields one kv_hkeys or kv_hvals call returns; a larger
# hash fails instead of dumping a huge hash into one tool result.
MAX_HASH_FIELDS = 1000


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


def _call_hkeys(client, args):
    """kv_hkeys: bound the hash first with HLEN, then run HKEYS. A
    missing key replies as an empty list, which becomes []. The
    HLEN check runs outside a transaction, so an atomic batch
    checks the reply length instead (see _call_batch_atomic)."""
    key = _require(args, "key")
    if (client.command("HLEN", key) or 0) > MAX_HASH_FIELDS:
        raise ValueError(
            "kv_hkeys returns at most %d fields; the hash is larger"
            % MAX_HASH_FIELDS
        )
    return list(client.command("HKEYS", key) or [])


def _call_hvals(client, args):
    """kv_hvals: bound the hash first with HLEN, then run HVALS. A
    missing key replies as an empty list, which becomes []. The
    HLEN check runs outside a transaction, so an atomic batch
    checks the reply length instead (see _call_batch_atomic)."""
    key = _require(args, "key")
    if (client.command("HLEN", key) or 0) > MAX_HASH_FIELDS:
        raise ValueError(
            "kv_hvals returns at most %d values; the hash is larger"
            % MAX_HASH_FIELDS
        )
    return list(client.command("HVALS", key) or [])


def _call_hincrbyfloat(client, args):
    """kv_hincrbyfloat: the field's new value as a number. Cinder
    replies with the value as a bulk string, formatted with %.17g,
    as it does for ZINCRBY scores."""
    return float(client.command(*_op_argv("kv_hincrbyfloat", args)))


def _call_single(client, name, args):
    if name == "kv_keys":
        return _call_keys(client, args)
    if name == "kv_keys_scan":
        return _call_keys_scan(client, args)
    if name == "kv_hscan":
        return _call_hscan(client, args)
    if name == "kv_zscan":
        return _call_zscan(client, args)
    if name == "kv_sscan":
        return _call_sscan(client, args)
    if name == "kv_hkeys":
        return _call_hkeys(client, args)
    if name == "kv_hvals":
        return _call_hvals(client, args)
    if name == "kv_hincrbyfloat":
        return _call_hincrbyfloat(client, args)
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
    if name == "kv_zmscore":
        return _call_zmscore(client, args)
    if name == "kv_zunion":
        return _call_zunion(client, args)
    if name == "kv_zinter":
        return _call_zinter(client, args)
    if name == "kv_zdiff":
        return _call_zdiff(client, args)
    if name == "kv_zincrby":
        return _call_zincrby(client, args)
    if name == "kv_zrange":
        return _call_zrange(client, args)
    if name == "kv_zrangebyscore":
        return _call_zrangebyscore(client, args)
    if name == "kv_zrangebylex":
        return _call_zrangebylex(client, args)
    if name == "kv_zcount":
        return _call_zcount(client, args)
    if name == "kv_zrevrank":
        return _call_zrevrank(client, args)
    if name in ("kv_zpopmin", "kv_zpopmax"):
        return _call_zpop(client, args, name)
    if name == "kv_zrandmember":
        return _call_zrandmember(client, args)
    return client.command(*_op_argv(name, args))
