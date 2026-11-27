"""Tool definitions for cinder-mcp.

Each tool maps to one cinder command. The schemas are plain JSON Schema
fragments, as the MCP spec requires for tools/list.
"""

import hashlib
import math

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
                "key": { "type": "string" },
                "field": { "type": "string" },
                "increment": { "type": "number" },
            },
            "required": ["key", "field", "increment"],
        },
    },
    {
        "name": "kv_hexpire",
        "description": "Set fields of a hash to expire after a number of seconds: HEXPIRE key seconds [NX | XX | GT | LT] FIELDS numfields field [field ...]. Takes `seconds` and `fields` as a list of field names (at most 1000). Returns one integer per field, in order: -2 the key or the field does not exist, 0 the condition was not met, 1 the expiry was set, 2 the field was deleted at once (a zero TTL). With condition \"nx\" only fields with no expiry are set, \"xx\" only fields that already have one, \"gt\" only when the new expiry is later than the current one, \"lt\" only when it is sooner — a field with no expiry counts as never expiring, so gt never applies to it and lt always does. Seconds must be 0 or more.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "seconds": {"type": "integer"},
                "fields": {"type": "array", "items": {"type": "string"}},
                "condition": {"type": "string"},
           },
            "required": ["key", "seconds", "fields"],
       },
   },
    {
        "name": "kv_hpexpire",
        "description": "Set fields of a hash to expire after a number of milliseconds: HPEXPIRE key milliseconds [NX | XX | GT | LT] FIELDS numfields field [field ...]. Takes `milliseconds` and `fields` as a list of field names (at most 1000). Returns one integer per field, in order: -2 the key or the field does not exist, 0 the condition was not met, 1 the expiry was set, 2 the field was deleted at once (a zero TTL). With condition \"nx\" only fields with no expiry are set, \"xx\" only fields that already have one, \"gt\" only when the new expiry is later than the current one, \"lt\" only when it is sooner — a field with no expiry counts as never expiring, so gt never applies to it and lt always does. Milliseconds must be 0 or more.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "milliseconds": {"type": "integer"},
                "fields": {"type": "array", "items": {"type": "string"}},
                "condition": {"type": "string"},
           },
            "required": ["key", "milliseconds", "fields"],
       },
   },
    {
        "name": "kv_hexpireat",
        "description": "Set fields of a hash to expire at an absolute Unix time in seconds: HEXPIREAT key seconds [NX | XX | GT | LT] FIELDS numfields field [field ...]. Takes `seconds` as a Unix timestamp and `fields` as a list of field names (at most 1000). Returns one integer per field, in order: -2 the key or the field does not exist, 0 the condition was not met, 1 the expiry was set, 2 the field was deleted at once (a time already past). With condition \"nx\" only fields with no expiry are set, \"xx\" only fields that already have one, \"gt\" only when the new expiry is later than the current one, \"lt\" only when it is sooner — a field with no expiry counts as never expiring, so gt never applies to it and lt always does.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "seconds": {"type": "integer"},
                "fields": {"type": "array", "items": {"type": "string"}},
                "condition": {"type": "string"},
           },
            "required": ["key", "seconds", "fields"],
       },
   },
    {
        "name": "kv_hpexpireat",
        "description": "Set fields of a hash to expire at an absolute Unix time in milliseconds: HPEXPIREAT key milliseconds [NX | XX | GT | LT] FIELDS numfields field [field ...]. Takes `milliseconds` as a Unix timestamp in milliseconds and `fields` as a list of field names (at most 1000). Returns one integer per field, in order: -2 the key or the field does not exist, 0 the condition was not met, 1 the expiry was set, 2 the field was deleted at once (a time already past). With condition \"nx\" only fields with no expiry are set, \"xx\" only fields that already have one, \"gt\" only when the new expiry is later than the current one, \"lt\" only when it is sooner — a field with no expiry counts as never expiring, so gt never applies to it and lt always does.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "milliseconds": {"type": "integer"},
                "fields": {"type": "array", "items": {"type": "string"}},
                "condition": {"type": "string"},
           },
            "required": ["key", "milliseconds", "fields"],
       },
   },
    {
        "name": "kv_httl",
        "description": "Seconds until fields of a hash expire: HTTL key FIELDS numfields field [field ...]. Takes `fields` as a list of field names (at most 1000). Returns one integer per field, in order: the remaining TTL in seconds, -1 when the field has no expiry, -2 when the key or the field does not exist.",
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
        "name": "kv_hpttl",
        "description": "Milliseconds until fields of a hash expire: HPTTL key FIELDS numfields field [field ...]. Takes `fields` as a list of field names (at most 1000). Returns one integer per field, in order: the remaining TTL in milliseconds, -1 when the field has no expiry, -2 when the key or the field does not exist.",
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
        "name": "kv_hpersist",
        "description": "Remove the expiry from fields of a hash: HPERSIST key FIELDS numfields field [field ...]. Takes `fields` as a list of field names (at most 1000). Returns one integer per field, in order: 1 an expiry was removed, -1 the field had no expiry, -2 the key or the field does not exist.",
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
        "name": "kv_xadd",
        "description": "Append one entry to a stream: XADD key [MAXLEN [~] threshold] id field value [field value ...]. Takes `fields` as an object of field names to values (at least one) and returns the new entry's ID as a string. The `id` defaults to \"*\" (auto: the current time in milliseconds, sequence 0, or the top ID's sequence plus one when the millisecond is not past it); \"ms-seq\" is explicit, and \"ms-*\" or \"ms-\" takes the millisecond and the next sequence in it — a bare millisecond is not an ID. An ID at or below the stream's top ID fails, and an explicit \"0-0\" fails, while a partial \"0-*\" on an empty stream resolves to \"0-0\", as in cinder. Pass `maxlen` to trim the oldest entries down to that many after the append (0 trims the entry just added, so the key is deleted at once); `approximate: true` sends MAXLEN ~, which cinder trims exactly like the plain form. Creates the stream when it does not exist, and preserves its TTL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "id": {"type": "string"},
                "fields": {"type": "object"},
                "maxlen": {"type": "integer"},
                "approximate": {"type": "boolean"},
            },
            "required": ["key", "fields"],
        },
    },
    {
        "name": "kv_xrange",
        "description": "Entries of a stream in an ID range, oldest first: XRANGE key start end [COUNT count]. Takes `start` and `end` as stream IDs (\"-\" for the first entry, \"+\" for the last, a bare millisecond for the whole millisecond, or \"ms-seq\"), defaulting to \"-\" and \"+\". Returns a list of {\"id\": ..., \"fields\": {...}} objects, in ID order, the bounds inclusive. Pass `count` to take at most that many entries (0 answers an empty list); without a count at most 1000 entries are returned, and a wider range fails instead of returning a truncated list. A missing key answers an empty list, and a start past the end does too. A field named twice in one entry keeps only its last value in the object.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "start": {"type": "string"},
                "end": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_xrevrange",
        "description": "Entries of a stream in an ID range, newest first: XREVRANGE key end start [COUNT count]. Takes `end` and `start` as stream IDs (\"+\" for the last entry, \"-\" for the first, a bare millisecond for the whole millisecond, or \"ms-seq\"), defaulting to \"+\" and \"-\" — the bounds are given end-first, as in Redis, and the entries come back in reverse ID order, the bounds inclusive. Pass `count` to take at most that many entries, highest first (0 answers an empty list); without a count at most 1000 entries are returned, and a wider range fails instead of returning a truncated list. A missing key answers an empty list, and an end below the start does too. A field named twice in one entry keeps only its last value in the object.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "end": {"type": "string"},
                "start": {"type": "string"},
                "count": {"type": "integer"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_xlen",
        "description": "The number of entries in a stream: XLEN key. Returns 0 when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {"key": {"type": "string"}},
            "required": ["key"],
        },
    },
    {
        "name": "kv_xread",
        "description": "Entries added to several streams after given IDs: XREAD [COUNT count] [BLOCK milliseconds] STREAMS key [key ...] id [id ...]. Takes `streams` as an object mapping stream keys to IDs (\"$\" for the top ID at read time, so only entries added after the read qualify, \"-\" for every entry, a bare millisecond for the entries after that whole millisecond, or \"ms-seq\"), and returns one {\"key\": ..., \"entries\": [{\"id\": ..., \"fields\": {...}}]} object per stream that has anything new, in stream order — streams with nothing new are left out, and a read with nothing new at all answers an empty list. Pass `count` for at most that many entries per stream (1 to 1000); without a count at most 1000 entries per stream are returned, and a wider stream fails instead of returning a truncated list. Pass `block` to wait up to that many milliseconds for new entries instead of answering at once (1 to 4000: BLOCK 0 would wait forever, and the socket to cinder times out after 5 seconds, so a longer block would die as a connection error instead of a clean timeout); a block that times out answers an empty list. \">\" is not an ID: use kv_xreadgroup for consumer-group reads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "streams": {"type": "object"},
                "count": {"type": "integer"},
                "block": {"type": "integer"},
            },
            "required": ["streams"],
        },
    },
    {
        "name": "kv_xreadgroup",
        "description": "Read a stream as a consumer of a consumer group: XREADGROUP GROUP group consumer [COUNT count] [BLOCK milliseconds] STREAMS key [key ...] id [id ...]. Takes `group` and `consumer` as strings and `streams` as an object mapping stream keys to IDs (\">\" for the entries after the group's cursor — the new entries, delivered to this consumer and recorded in the group's pending list — or an explicit ID like \"0\" or \"ms-seq\" to re-read this consumer's pending entries after that ID, without changing delivery state). Returns one {\"key\": ..., \"entries\": [{\"id\": ..., \"fields\": {...}}]} object per stream that has anything to deliver, in stream order — streams with nothing new are left out, and a read with nothing new at all answers an empty list. Pass `count` for at most that many entries per stream (1 to 1000); without a count at most 1000 entries per stream are returned, and a wider stream fails instead of returning a truncated list. Pass `block` to wait up to that many milliseconds for new entries instead of answering at once (1 to 4000: BLOCK 0 would wait forever, and the socket to cinder times out after 5 seconds, so a longer block would die as a connection error instead of a clean timeout); a block that times out answers an empty list. A blocked read with an explicit ID never wakes on new entries — only entries already pending for this consumer answer it — so it waits out the whole block and answers an empty list when nothing is pending. A read for a missing key or a group that does not exist fails with NOGROUP. Create the group first with kv_xgroup_create. At most 100 streams per call.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "group": {"type": "string"},
                "consumer": {"type": "string"},
                "streams": {"type": "object"},
                "count": {"type": "integer"},
                "block": {"type": "integer"},
            },
            "required": ["group", "consumer", "streams"],
        },
    },
    {
        "name": "kv_xpending",
        "description": "Pending entries of a consumer group: XPENDING key group [start end count [consumer]]. Takes `key` and `group` as strings. With no range arguments it returns the summary as {\"total\": ..., \"min_id\": ... or null, \"max_id\": ... or null, \"consumers\": [{\"consumer\": ..., \"count\": ...}]} — the number of pending entries, the lowest and highest pending IDs (null when nothing is pending), and one count per consumer that has anything pending, in the order the consumers first read. Pass `start`, `end` and `count` together for the extended form, which returns one {\"id\": ..., \"consumer\": ..., \"idle_ms\": ..., \"deliveries\": ...} object per pending entry in the ID range, in ID order — the consumer the entry was last delivered to, how many milliseconds since it was last delivered, and how many times it has been delivered; `count` takes at most that many entries (1 to 1000), and `consumer` narrows the list to the entries last delivered to one consumer. A read for a missing key or a group that does not exist fails with NOGROUP. A read, so it changes nothing.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "group": {"type": "string"},
                "start": {"type": "string"},
                "end": {"type": "string"},
                "count": {"type": "integer"},
                "consumer": {"type": "string"},
            },
            "required": ["key", "group"],
        },
    },
    {
        "name": "kv_xgroup_create",
        "description": "Create a consumer group on a stream: XGROUP CREATE key group id [MKSTREAM]. Takes `key` and `group` as strings and `id` as the ID the group starts at (\"$\" by default — only entries added after the group is created, \"0\" for every entry from the beginning, or an explicit ID like \"ms-seq\"), and returns \"OK\". Pass `mkstream: true` to create the stream empty when it does not exist; without it, creating a group on a missing key fails. Creating a group that already exists fails with BUSYGROUP, and a key that is not a stream fails with WRONGTYPE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "group": {"type": "string"},
                "id": {"type": "string"},
                "mkstream": {"type": "boolean"},
            },
            "required": ["key", "group"],
        },
    },
    {
        "name": "kv_xack",
        "description": "Acknowledge entries of a consumer group: XACK key group id [id ...]. Takes `key` and `group` as strings and `ids` as a list of entry IDs (\"ms-seq\", at least one, at most 1000) and returns how many were dropped from the group's pending list — an ID that is not pending counts 0, so acking the same entry twice answers 1 then 0. The entries stay in the stream; only their pending record is dropped. A missing key or a group that does not exist fails with NOGROUP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "group": {"type": "string"},
                "ids": {"type": "array"},
            },
            "required": ["key", "group", "ids"],
        },
    },
    {
        "name": "kv_xclaim",
        "description": "Claim pending entries of a consumer group for another consumer: XCLAIM key group consumer min-idle-time id [id ...] [IDLE ms] [TIME ms-unix-time] [RETRYCOUNT count] [FORCE] [JUSTID]. Takes `key`, `group` and `consumer` as strings, `min_idle_ms` as the milliseconds an entry must have been idle since its last delivery before it can be claimed (0 claims at once), and `ids` as a list of entry IDs (\"ms-seq\", or a bare millisecond for the first sequence of that millisecond; at least one, at most 1000). Returns the claimed entries as [{\"id\": ..., \"fields\": {...}}] in the order the IDs were given — an entry that is not in the stream, is not idle enough, or is not pending is left out, and a repeated ID is claimed once. Pass `force: true` to claim an entry even when it has not been idle long enough, and to claim an entry that is in the stream but not pending at all, creating a pending record for it. Pass `idle_ms` to set the claimed entries' delivery time that many milliseconds ago, or `time_ms` for an absolute Unix time in milliseconds — the two cannot be combined. Pass `retrycount` to set the delivery count instead of bumping it by one, and `justid: true` to answer only the claimed IDs instead of the entries. A claimed entry moves to this consumer, its delivery count bumps by one (or is set by `retrycount`), and it stays pending until XACK. A missing key or a group that does not exist fails with NOGROUP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "group": {"type": "string"},
                "consumer": {"type": "string"},
                "min_idle_ms": {"type": "integer"},
                "ids": {"type": "array"},
                "idle_ms": {"type": "integer"},
                "time_ms": {"type": "integer"},
                "retrycount": {"type": "integer"},
                "force": {"type": "boolean"},
                "justid": {"type": "boolean"},
            },
            "required": ["key", "group", "consumer", "min_idle_ms", "ids"],
        },
    },
    {
        "name": "kv_xgroup_setid",
        "description": "Move a consumer group's last-delivered ID: XGROUP SETID key group id. Takes `key` and `group` as strings and `id` as the ID the group moves to (\"$\" by default — the top ID at call time, so the next \">\" read delivers only entries added after it, \"0\" for every entry from the beginning, or an explicit ID like \"ms-seq\"). Returns \"OK\". The next \">\" read delivers the entries after the new ID, and entries already pending stay pending for their consumers — the pending list is untouched. Cinder has no ENTRIESREAD option for SETID, so the tool does not offer it. A missing key or a group that does not exist fails with NOGROUP, and a key that is not a stream fails with WRONGTYPE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "group": {"type": "string"},
                "id": {"type": "string"},
            },
            "required": ["key", "group"],
        },
    },
    {
        "name": "kv_xgroup_destroy",
        "description": "Destroy a consumer group on a stream: XGROUP DESTROY key group. Takes `key` and `group` as strings and returns 1 when the group was destroyed, 0 when there was no such group on the stream. Destroying a group drops its cursor, its consumers and its pending list — the stream and its entries survive, and so do the other groups. A missing key fails with NOGROUP, and a key that is not a stream fails with WRONGTYPE.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "group": {"type": "string"},
            },
            "required": ["key", "group"],
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
        "name": "kv_zrevrange",
        "description": "Members of a sorted set in an index range, highest score first: ZREVRANGE key start stop [WITHSCORES]. Negative indices count from the end, as in Redis. Pass withscores=true for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. At most 1000 members per call; narrow the range for a larger set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "start": {"type": "integer"},
                "stop": {"type": "integer"},
                "withscores": {"type": "boolean"},
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
        "name": "kv_zrevrangebyscore",
        "description": "Members of a sorted set whose scores fall in a range, highest score first: ZREVRANGEBYSCORE key max min [WITHSCORES] [LIMIT offset count]. `min` and `max` default to -inf and +inf; pass a number or a string like \"5\", \"(5\" for an exclusive bound, \"-inf\" or \"+inf\" — bounds are still given min then max, cinder reads them max-first. Pass withscores=true for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. Pass offset/count to page through the matches (count defaults to all); at most 1000 members per call, so narrow the range or pass a smaller count for a larger set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "min": {"type": ["number", "string"]},
                "max": {"type": ["number", "string"]},
                "withscores": {"type": "boolean"},
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
        "description": "The union of several sorted sets: ZUNION numkeys key [key ...] [WITHSCORES]. Takes `keys` as a list of key names, at most 1000. A member in several sets appears once, with the sum of its scores, lowest score first, member name breaking ties. A missing key counts as an empty set. Pass `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The union holds at most 1000 members; a wider union fails instead of returning a truncated list. Cinder has no WEIGHTS or AGGREGATE variants for ZUNION itself; `kv_zunionstore` stores the union at a destination key instead of returning it, and does take WEIGHTS and AGGREGATE.",
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
        "description": "The intersection of several sorted sets: ZINTER numkeys key [key ...] [WEIGHTS weight ...] [AGGREGATE SUM|MIN|MAX] [WITHSCORES]. Takes `keys` as a list of key names, at most 1000. A member must be in every set to appear, once, lowest score first, member name breaking ties. Pass `weights` as a list of numbers, one per key, to multiply each set's scores before aggregating (defaults to 1 per key); pass `aggregate` as \"sum\", \"min\" or \"max\" to combine a member's weighted scores (defaults to \"sum\"). A missing key counts as an empty set, so an intersection with one is empty. Pass `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The intersection holds at most 1000 members; a wider intersection fails instead of returning a truncated list. Use `kv_zinterstore` to store the intersection at a destination key instead of returning it.",
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
        "description": "The difference of several sorted sets: ZDIFF numkeys key [key ...] [WITHSCORES]. Takes `keys` as a list of key names, at most 1000. The members of the first set that are in none of the other sets, once each, in the first set's score order, member name breaking ties, with the first set's scores. A missing key counts as an empty set, so a difference against only missing keys is the whole first set, and a missing first key diffs to nothing. Pass `withscores: true` for a list of {\"member\": ..., \"score\": ...} objects instead of plain member names. The difference holds at most 1000 members; a wider difference fails instead of returning a truncated list. Use `kv_zdiffstore` to store the difference at a destination key instead of returning it.",
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
        "name": "kv_zunionstore",
        "description": "Store the union of several sorted sets at a destination key: ZUNIONSTORE destination numkeys key [key ...] [WEIGHTS weight ...] [AGGREGATE SUM|MIN|MAX]. Takes `destination` and `keys` as a list of key names, at most 1000, and returns the number of members stored. A member in several sets is stored once, with the sum of its scores by default; pass `weights` as a list of numbers, one per key, to multiply each set's scores before combining them (defaults to 1 per key), and `aggregate` as \"sum\", \"min\" or \"max\" to combine a member's weighted scores (defaults to \"sum\"). A missing key counts as an empty set. The destination is overwritten whatever it held — any type — and its TTL is cleared; an empty result deletes the destination instead of leaving an empty set, and the destination may itself be one of the input keys, since the union is computed before it is touched. When the destination already holds exactly the result, nothing is written and its TTL is kept. Fails with WRONGTYPE on an input key holding anything but a sorted set, and a failed store leaves the destination and its TTL untouched.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "keys": {"type": "array", "items": {"type": "string"}},
                "weights": {"type": "array", "items": {"type": "number"}},
                "aggregate": {"type": "string"},
            },
            "required": ["destination", "keys"],
        },
    },
    {
        "name": "kv_zinterstore",
        "description": "Store the intersection of several sorted sets at a destination key: ZINTERSTORE destination numkeys key [key ...] [WEIGHTS weight ...] [AGGREGATE SUM|MIN|MAX]. Takes `destination` and `keys` as a list of key names, at most 1000, and returns the number of members stored. A member must be in every set to be stored, once, with its weighted scores combined by the aggregate; pass `weights` as a list of numbers, one per key, to multiply each set's scores before aggregating (defaults to 1 per key), and `aggregate` as \"sum\", \"min\" or \"max\" (defaults to \"sum\"). A missing key counts as an empty set, so an intersection with one stores nothing. The destination is overwritten whatever it held — any type — and its TTL is cleared; an empty result deletes the destination instead of leaving an empty set, and the destination may itself be one of the input keys, since the intersection is computed before it is touched. When the destination already holds exactly the result, nothing is written and its TTL is kept. Fails with WRONGTYPE on an input key holding anything but a sorted set, and a failed store leaves the destination and its TTL untouched.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "keys": {"type": "array", "items": {"type": "string"}},
                "weights": {"type": "array", "items": {"type": "number"}},
                "aggregate": {"type": "string"},
            },
            "required": ["destination", "keys"],
        },
    },
    {
        "name": "kv_zdiffstore",
        "description": "Store the difference of several sorted sets at a destination key: ZDIFFSTORE destination numkeys key [key ...]. Takes `destination` and `keys` as a list of key names, at most 1000, and returns the number of members stored. The members of the first set that are in none of the other sets are stored, once each, with the first set's scores. A missing key counts as an empty set, so a difference against only missing keys stores the whole first set, and a missing first key stores nothing. There are no WEIGHTS or AGGREGATE options — the scores come from the first set, as in Redis — so the tool does not offer them. The destination is overwritten whatever it held — any type — and its TTL is cleared; an empty result deletes the destination instead of leaving an empty set, and the destination may itself be one of the input keys, since the difference is computed before it is touched. When the destination already holds exactly the result, nothing is written and its TTL is kept. Fails with WRONGTYPE on an input key holding anything but a sorted set, and a failed store leaves the destination and its TTL untouched.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "keys": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["destination", "keys"],
        },
    },
    {
        "name": "kv_pfadd",
        "description": "Add elements to a HyperLogLog: PFADD key element [element ...]. Takes `key` and `elements` as a list of strings, at least one. Returns 1 when the estimate changed (at least one register moved), 0 when every element was already counted. Creates the key when it does not exist and preserves its TTL; fails with WRONGTYPE on a key holding a container or a plain string that is not a HyperLogLog. Cinder stores the HyperLogLog as a string value with an HLL1 header, so PFADD never changes the key's type.",
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
        "name": "kv_pfcount",
        "description": "Estimate the number of distinct elements in one or more HyperLogLogs: PFCOUNT key [key ...]. Takes `keys` as a list of key names, at most 1000. Returns the estimate as an integer; several keys are merged register-wise, so the estimate is for the union of the keys. A missing key counts as an empty set, so PFCOUNT of only missing keys is 0. Fails with WRONGTYPE on a key holding a container or a plain string that is not a HyperLogLog. The estimate is approximate: small cardinalities come back exact, large ones within about one percent — the same approximation real HyperLogLog gives.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["keys"],
        },
    },
    {
        "name": "kv_pfmerge",
        "description": "Merge several HyperLogLogs into a destination key: PFMERGE destination source [source ...]. Takes `destination` and `sources` as a list of key names, at least one, at most 1000. Returns \"OK\". The destination is created when it does not exist and overwritten wholesale when it does — its old registers are discarded, not unioned in, unless it is itself one of the sources — and its TTL is cleared. A missing source counts as an empty set, so merging only missing sources creates an empty HyperLogLog. Sources are never modified, and the destination may itself be a source. Fails with WRONGTYPE on a key holding a container or a plain string that is not a HyperLogLog, at either end. Cinder stores the HyperLogLog as a string value with an HLL1 header, so PFMERGE never changes the key's type.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["destination", "sources"],
        },
    },
    {
        "name": "kv_geoadd",
        "description": "Add members with coordinates to a geo set: GEOADD key [NX | XX | CH] longitude latitude member [longitude latitude member ...]. Takes `members` as an object mapping member names to [longitude, latitude] pairs. Longitude is -180 to 180, latitude -85.05112878 to 85.05112878, as in Redis. With `nx: true` only members not already in the set are added, with `xx: true` only members already in the set are updated (a new member is skipped, and on a missing key nothing is created), and `nx` and `xx` cannot be used together; with `ch: true` the call returns the number of members added or changed instead of just the number added. Returns the number of members newly added; re-adding a member at its current coordinates is a no-op (0), and moving a member to new coordinates returns 0 added but updates its position. Every coordinate is checked before anything is applied, so a bad one fails the whole call with nothing written. Cinder stores the set as a sorted set of 52-bit geohash scores, so it reads back as a zset (ZRANGE, ZSCORE, ZCARD all work on it), and preserves the key's TTL. Fails with WRONGTYPE on a key holding anything but a sorted set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "members": {"type": "object"},
                "nx": {"type": "boolean"},
                "xx": {"type": "boolean"},
                "ch": {"type": "boolean"},
            },
            "required": ["key", "members"],
        },
    },
    {
        "name": "kv_geodist",
        "description": "The distance between two members of a geo set: GEODIST key member1 member2 [m | km | ft | mi]. Returns the distance as a number in the requested unit (\"m\" by default), or null when the key or either member does not exist. Cinder answers with four decimals, so the distance is rounded to four decimal places in the requested unit. The distance is the Haversine distance between the centres of the members' geohash cells, as in Redis, not between the coordinates as given. Fails with WRONGTYPE on a key holding anything but a sorted set, and with a bad unit even when the key does not exist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "member1": {"type": "string"},
                "member2": {"type": "string"},
                "unit": {"type": "string"},
            },
            "required": ["key", "member1", "member2"],
        },
    },
    {
        "name": "kv_geopos",
        "description": "The positions of several members of a geo set: GEOPOS key member [member ...]. Takes `members` as a list of member names, at most 1000. Returns the positions in the same order as a list of {\"longitude\": ..., \"latitude\": ...} objects, with null for a member that is not in the set — and null for every member when the key does not exist. The coordinates are the centres of the members' geohash cells, as in Redis, so they come back a hair off the coordinates as given. A member whose score does not decode as a geohash (a member added with ZADD holding a score of 0, a negative score, NaN, or 2^64 or more) also answers null. Fails with WRONGTYPE on a key holding anything but a sorted set.",
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
        "name": "kv_geohash",
        "description": "The geohash strings of several members of a geo set: GEOHASH key member [member ...]. Takes `members` as a list of member names, at most 1000. Returns the 11-character base32 geohash strings in the same order, with null for a member that is not in the set — and null for every member when the key does not exist. The string is re-encoded from the centre of the member's geohash cell over the standard [-90, 90] latitude range, as in Redis, and its eleventh character is always \"0\": 52 bits cannot fill 55, so the last five are assumed zero. A member whose score does not decode as a geohash (a member added with ZADD holding a score of 0, a negative score, NaN, or 2^64 or more) also answers null. Fails with WRONGTYPE on a key holding anything but a sorted set.",
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
        "name": "kv_geosearch",
        "description": "Search a geo set for the members inside a circle or a box: GEOSEARCH key <FROMMEMBER member | FROMLONLAT longitude latitude> <BYRADIUS radius <m | km | ft | mi> | BYBOX width height <m | km | ft | mi>> [ASC | DESC] [COUNT count [ANY]] [WITHCOORD] [WITHDIST] [WITHHASH]. Takes `key` plus exactly one centre — `member` for FROMMEMBER, or `longitude` and `latitude` for FROMLONLAT — and exactly one shape — `radius` for BYRADIUS, or `width` and `height` for BYBOX — with `unit` (\"m\" by default, \"km\" / \"ft\" / \"mi\" in any case). `sort` is \"asc\" (nearest-first, the default) or \"desc\"; `count` limits the hits (at most 1000 returned), and `any: true` with a count takes the first N in (score, member) order without sorting. Returns the member names in distance order, or with `withdist` / `withhash` / `withcoord` one object per hit — {\"member\": ..., \"distance\": ..., \"hash\": ..., \"coord\": {\"longitude\": ..., \"latitude\": ...}} with only the requested fields, in that order: the distance is in the shape's unit with four decimals, the hash is the 52-bit geohash score as an integer, the coordinates are the centres of the members' geohash cells. A missing key answers an empty list. Fails with WRONGTYPE on a key holding anything but a sorted set, and when a FROMMEMBER member does not exist or has no position.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "member": {"type": "string"},
                "longitude": {"type": "number"},
                "latitude": {"type": "number"},
                "radius": {"type": "number"},
                "width": {"type": "number"},
                "height": {"type": "number"},
                "unit": {"type": "string"},
                "sort": {"type": "string"},
                "count": {"type": "integer"},
                "any": {"type": "boolean"},
                "withdist": {"type": "boolean"},
                "withhash": {"type": "boolean"},
                "withcoord": {"type": "boolean"},
            },
            "required": ["key"],
        },
    },
    {
        "name": "kv_geosearchstore",
        "description": "Store the members of a geo set inside a circle or a box at a destination key: GEOSEARCHSTORE destination key <FROMMEMBER member | FROMLONLAT longitude latitude> <BYRADIUS radius <m | km | ft | mi> | BYBOX width height <m | km | ft | mi>> [ASC | DESC] [COUNT count [ANY]] [STOREDIST]. Takes `destination` and `key` plus exactly one centre — `member` for FROMMEMBER, or `longitude` and `latitude` for FROMLONLAT — and exactly one shape — `radius` for BYRADIUS, or `width` and `height` for BYBOX — with `unit` (\"m\" by default, \"km\" / \"ft\" / \"mi\" in any case). `sort` is \"asc\" (nearest-first, the default) or \"desc\"; `count` limits the hits (at most 1000 stored), and `any: true` with a count takes the first N in (score, member) order without sorting. The hits are stored at the destination as a sorted set with their geohash scores, or with `storedist: true` with their distances in the shape's unit as scores, and the call returns the number stored. Either overwrites the destination whatever it held and clears its TTL; an empty result deletes the destination instead; the destination may be the source key itself. A missing key stores 0. Fails with WRONGTYPE on a key holding anything but a sorted set, and when a FROMMEMBER member does not exist or has no position. Cinder has no WITH* options for GEOSEARCHSTORE, so the tool does not offer them.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "destination": {"type": "string"},
                "key": {"type": "string"},
                "member": {"type": "string"},
                "longitude": {"type": "number"},
                "latitude": {"type": "number"},
                "radius": {"type": "number"},
                "width": {"type": "number"},
                "height": {"type": "number"},
                "unit": {"type": "string"},
                "sort": {"type": "string"},
                "count": {"type": "integer"},
                "any": {"type": "boolean"},
                "storedist": {"type": "boolean"},
            },
            "required": ["destination", "key"],
        },
    },
    {
        "name": "kv_georadius",
        "description": "Search a geo set for the members inside a circle around a point: GEORADIUS key longitude latitude radius <m | km | ft | mi> [WITHCOORD] [WITHDIST] [WITHHASH] [COUNT count [ANY]] [ASC | DESC] [STORE key | STOREDIST key]. Takes `key`, `longitude`, `latitude`, `radius`, and `unit` (\"m\" by default, \"km\" / \"ft\" / \"mi\" in any case). The same `sort` / `count` / `any` / `withdist` / `withhash` / `withcoord` options as kv_geosearch, returning the member names or the member objects. With `store`, the hits are stored at the destination as a sorted set with their geohash scores and the call returns the number stored; with `storedist`, they are stored with their distances in the radius unit as scores. Either overwrites the destination whatever it held and clears its TTL; an empty result deletes the destination instead; the destination may be the source key itself. `store` / `storedist` cannot be combined with the `with*` options. A missing key answers an empty list (or 0 stored). Fails with WRONGTYPE on a key holding anything but a sorted set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "longitude": {"type": "number"},
                "latitude": {"type": "number"},
                "radius": {"type": "number"},
                "unit": {"type": "string"},
                "sort": {"type": "string"},
                "count": {"type": "integer"},
                "any": {"type": "boolean"},
                "withdist": {"type": "boolean"},
                "withhash": {"type": "boolean"},
                "withcoord": {"type": "boolean"},
                "store": {"type": "string"},
                "storedist": {"type": "string"},
            },
            "required": ["key", "longitude", "latitude", "radius"],
        },
    },
    {
        "name": "kv_georadiusbymember",
        "description": "Search a geo set for the members inside a circle around one of its members: GEORADIUSBYMEMBER key member radius <m | km | ft | mi> [WITHCOORD] [WITHDIST] [WITHHASH] [COUNT count [ANY]] [ASC | DESC] [STORE key | STOREDIST key]. Takes `key`, `member`, `radius`, and `unit` (\"m\" by default, \"km\" / \"ft\" / \"mi\" in any case). The same `sort` / `count` / `any` / `withdist` / `withhash` / `withcoord` options and the same `store` / `storedist` behaviour as kv_georadius: the hits are stored at the destination with their geohash scores or their distances, overwriting it whatever it held and clearing its TTL, an empty result deletes it, and the destination may be the source key itself. A missing key answers an empty list (or 0 stored). Fails with WRONGTYPE on a key holding anything but a sorted set, and when the centre member does not exist or has no position.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "member": {"type": "string"},
                "radius": {"type": "number"},
                "unit": {"type": "string"},
                "sort": {"type": "string"},
                "count": {"type": "integer"},
                "any": {"type": "boolean"},
                "withdist": {"type": "boolean"},
                "withhash": {"type": "boolean"},
                "withcoord": {"type": "boolean"},
                "store": {"type": "string"},
                "storedist": {"type": "string"},
            },
            "required": ["key", "member", "radius"],
        },
    },
    {
        "name": "kv_georadius_ro",
        "description": "Search a geo set for the members inside a circle around a point, read-only: GEORADIUS_RO key longitude latitude radius <m | km | ft | mi> [WITHCOORD] [WITHDIST] [WITHHASH] [COUNT count [ANY]] [ASC | DESC]. Takes `key`, `longitude`, `latitude`, `radius`, and `unit` (\"m\" by default, \"km\" / \"ft\" / \"mi\" in any case). The same `sort` / `count` / `any` / `withdist` / `withhash` / `withcoord` options as kv_georadius, returning the member names or the member objects — but no `store` / `storedist`: cinder refuses STORE and STOREDIST on the read-only variant, so the tool rejects them before anything is sent. The command never writes, never logs to the AOF, and never replicates, so it is safe to run on a replica. A missing key answers an empty list. Fails with WRONGTYPE on a key holding anything but a sorted set.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "longitude": {"type": "number"},
                "latitude": {"type": "number"},
                "radius": {"type": "number"},
                "unit": {"type": "string"},
                "sort": {"type": "string"},
                "count": {"type": "integer"},
                "any": {"type": "boolean"},
                "withdist": {"type": "boolean"},
                "withhash": {"type": "boolean"},
                "withcoord": {"type": "boolean"},
            },
            "required": ["key", "longitude", "latitude", "radius"],
        },
    },
    {
        "name": "kv_georadiusbymember_ro",
        "description": "Search a geo set for the members inside a circle around one of its members, read-only: GEORADIUSBYMEMBER_RO key member radius <m | km | ft | mi> [WITHCOORD] [WITHDIST] [WITHHASH] [COUNT count [ANY]] [ASC | DESC]. Takes `key`, `member`, `radius`, and `unit` (\"m\" by default, \"km\" / \"ft\" / \"mi\" in any case). The same `sort` / `count` / `any` / `withdist` / `withhash` / `withcoord` options as kv_georadiusbymember, returning the member names or the member objects — but no `store` / `storedist`: cinder refuses STORE and STOREDIST on the read-only variant, so the tool rejects them before anything is sent. The command never writes, never logs to the AOF, and never replicates, so it is safe to run on a replica. A missing key answers an empty list. Fails with WRONGTYPE on a key holding anything but a sorted set, and when the centre member does not exist or has no position.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "member": {"type": "string"},
                "radius": {"type": "number"},
                "unit": {"type": "string"},
                "sort": {"type": "string"},
                "count": {"type": "integer"},
                "any": {"type": "boolean"},
                "withdist": {"type": "boolean"},
                "withhash": {"type": "boolean"},
                "withcoord": {"type": "boolean"},
            },
            "required": ["key", "member", "radius"],
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
        "description": "Run several kv operations in one call, in order, and get one summary back. Each op is an object with an \"op\" naming one of kv_get, kv_set, kv_del, kv_keys, kv_dbsize, kv_incr, kv_ttl, kv_pttl, kv_exists, kv_expire, kv_pexpire, kv_mget, kv_mset, kv_getdel, kv_setnx, kv_setex, kv_getset, kv_append, kv_strlen, kv_decr, kv_decrby, kv_getex, kv_getrange, kv_setrange, kv_setbit, kv_getbit, kv_bitcount, kv_bitop, kv_bitfield, kv_hset, kv_hget, kv_hgetall, kv_hdel, kv_hexists, kv_hlen, kv_hmget, kv_hsetnx, kv_hincrby, kv_hscan, kv_hkeys, kv_hvals, kv_hincrbyfloat, kv_hexpire, kv_hpexpire, kv_hexpireat, kv_hpexpireat, kv_httl, kv_hpttl, kv_hpersist, kv_xadd, kv_xrange, kv_xrevrange, kv_xlen, kv_xread, kv_xreadgroup, kv_xpending, kv_xgroup_create, kv_xack, kv_xclaim, kv_xgroup_setid, kv_xgroup_destroy, kv_zadd, kv_zrange, kv_zrevrange, kv_zrangebyscore, kv_zrevrangebyscore, kv_zrangebylex, kv_zlexcount, kv_zcount, kv_zcard, kv_zscore, kv_zmscore, kv_zrank, kv_zrevrank, kv_zrem, kv_zremrangebyscore, kv_zremrangebyrank, kv_zremrangebylex, kv_zincrby, kv_zpopmin, kv_zpopmax, kv_zrandmember, kv_zscan, kv_zunion, kv_zinter, kv_zdiff, kv_zunionstore, kv_zinterstore, kv_zdiffstore, kv_pfadd, kv_pfcount, kv_pfmerge, kv_geoadd, kv_geodist, kv_geopos, kv_geohash, kv_geosearch, kv_geosearchstore, kv_georadius, kv_georadiusbymember, kv_georadius_ro, kv_georadiusbymember_ro, kv_lpush, kv_rpush, kv_lrange, kv_llen, kv_lpop, kv_rpop, kv_lindex, kv_lset, kv_linsert, kv_lpushx, kv_rpushx, kv_ltrim, kv_lmove, kv_sadd, kv_smembers, kv_sscan, kv_scard, kv_srem or kv_sismember plus that tool's arguments. Ops run sequentially and the batch keeps going past a failed op; each op's result or error is reported. At most 100 ops per call. Pass atomic=true to run the ops as one MULTI/EXEC transaction instead: they execute together with no other client interleaved, and an op that fails at EXEC time is recorded in place while the rest still run. An atomic batch only takes the single-command ops (kv_keys_scan cannot run inside a transaction); an op that cannot be queued fails the whole call before anything runs, so check the ops first. A kv_xread or kv_xreadgroup with block cannot run in an atomic batch: cinder refuses to queue a BLOCK inside MULTI/EXEC, so the whole call fails; a plain kv_xread or kv_xreadgroup queues and runs at EXEC.",
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
                            "streams": {"type": "object"},
                            "block": {"type": "integer"},
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
    "kv_hexpire", "kv_hpexpire", "kv_hexpireat", "kv_hpexpireat",
    "kv_httl", "kv_hpttl", "kv_hpersist",
    "kv_xadd", "kv_xrange", "kv_xrevrange", "kv_xlen", "kv_xread",
    "kv_xreadgroup", "kv_xpending", "kv_xgroup_create", "kv_xack",
    "kv_xclaim", "kv_xgroup_setid", "kv_xgroup_destroy",
    "kv_zadd", "kv_zrange", "kv_zrevrange", "kv_zrangebyscore",
    "kv_zrevrangebyscore", "kv_zrangebylex",
    "kv_zlexcount", "kv_zcount", "kv_zcard",
    "kv_zscore", "kv_zmscore", "kv_zrank", "kv_zrevrank", "kv_zrem",
    "kv_zremrangebyscore", "kv_zremrangebyrank", "kv_zremrangebylex",
    "kv_zincrby",
    "kv_zpopmin", "kv_zpopmax",
    "kv_zrandmember", "kv_zscan", "kv_zunion", "kv_zinter", "kv_zdiff",
    "kv_zunionstore", "kv_zinterstore", "kv_zdiffstore",
    "kv_pfadd", "kv_pfcount", "kv_pfmerge",
    "kv_geoadd", "kv_geodist", "kv_geopos", "kv_geohash",
    "kv_geosearch", "kv_geosearchstore", "kv_georadius",
    "kv_georadiusbymember", "kv_georadius_ro",
    "kv_georadiusbymember_ro",
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
    "kv_hexpire", "kv_hpexpire", "kv_hexpireat", "kv_hpexpireat",
    "kv_httl", "kv_hpttl", "kv_hpersist",
    "kv_xadd", "kv_xrange", "kv_xrevrange", "kv_xlen", "kv_xread",
    "kv_xreadgroup", "kv_xpending", "kv_xgroup_create", "kv_xack",
    "kv_xclaim", "kv_xgroup_setid", "kv_xgroup_destroy",
    "kv_zadd", "kv_zrange", "kv_zrevrange", "kv_zrangebyscore",
    "kv_zrevrangebyscore", "kv_zrangebylex",
    "kv_zlexcount", "kv_zcount", "kv_zcard",
    "kv_zscore", "kv_zmscore", "kv_zrank", "kv_zrevrank", "kv_zrem",
    "kv_zremrangebyscore", "kv_zremrangebyrank", "kv_zremrangebylex",
    "kv_zincrby",
    "kv_zpopmin", "kv_zpopmax",
    "kv_zrandmember", "kv_zscan", "kv_zunion", "kv_zinter", "kv_zdiff",
    "kv_zunionstore", "kv_zinterstore", "kv_zdiffstore",
    "kv_pfadd", "kv_pfcount", "kv_pfmerge",
    "kv_geoadd", "kv_geodist", "kv_geopos", "kv_geohash",
    "kv_geosearch", "kv_geosearchstore", "kv_georadius",
    "kv_georadiusbymember", "kv_georadius_ro",
    "kv_georadiusbymember_ro",
    "kv_lpush", "kv_rpush", "kv_lrange", "kv_llen", "kv_lpop", "kv_rpop",
    "kv_lindex", "kv_lset", "kv_linsert",
    "kv_lpushx", "kv_rpushx", "kv_ltrim", "kv_lmove",
    "kv_sadd", "kv_smembers", "kv_sscan", "kv_scard", "kv_srem",
    "kv_sismember",
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
        if op_name in ("kv_zrange", "kv_zrevrange"):
            # A range with a negative bound needs the set's size to
            # know how wide it is; check the bound before anything
            # is queued, like the standalone tool does.
            _check_zrange_window(client, op, op_name)
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
        elif op_name in ("kv_zrange", "kv_zrevrange"):
            # ZRANGE / ZREVRANGE came back as a flat list inside the
            # transaction; shape it like the standalone tool does,
            # including the withscores member/score objects.
            value = _zrange_result(reply or [], _zrange_args(op, op_name)[3])
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
        elif op_name in ("kv_zrangebyscore", "kv_zrevrangebyscore"):
            # ZRANGEBYSCORE / ZREVRANGEBYSCORE came back as a flat
            # list inside the transaction; shape it like the
            # standalone tool does, including the withscores
            # member/score objects. A range wider than the cap is
            # recorded as this op's error, in place, like an
            # EXEC-time failure — the rest still run.
            members = _zrange_result(
                reply or [], _zrangebyscore_args(op, op_name)[3])
            if len(members) > MAX_ZRANGE_MEMBERS:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "%s returns at most %d "
                              "members; narrow the range or pass a limit"
                              % (op_name, MAX_ZRANGE_MEMBERS)})
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
        elif op_name == "kv_xrange":
            # XRANGE came back as [[id, [field, value, ...]], ...]
            # inside the transaction; shape it like the standalone
            # tool does, into id/fields objects. A range wider
            # than the cap is recorded as this op's error, in
            # place, like an EXEC-time failure — the rest still
            # run.
            entries = _xrange_result(reply or [])
            if len(entries) > MAX_XRANGE_ENTRIES:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_xrange returns at most %d entries; "
                              "narrow the range or pass a count"
                              % MAX_XRANGE_ENTRIES})
                continue
            value = entries
        elif op_name == "kv_xrevrange":
            # XREVRANGE came back as [[id, [field, value, ...]],
            # ...] inside the transaction, highest first; shape it
            # like the standalone tool does, into id/fields
            # objects. A range wider than the cap is recorded as
            # this op's error, in place, like an EXEC-time failure
            # — the rest still run.
            entries = _xrange_result(reply or [])
            if len(entries) > MAX_XRANGE_ENTRIES:
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_xrevrange returns at most %d entries; "
                              "narrow the range or pass a count"
                              % MAX_XRANGE_ENTRIES})
                continue
            value = entries
        elif op_name == "kv_xread":
            # XREAD came back as [[key, [[id, [field, value,
            # ...]], ...]], ...] inside the transaction; shape it
            # like the standalone tool does, into per-stream
            # key/entries objects. A BLOCK never reaches EXEC:
            # cinder refuses to queue it, so the whole call fails
            # up front instead. A stream wider than the cap is
            # recorded as this op's error, in place, like an
            # EXEC-time failure — the rest still run.
            streams = _xread_result(reply)
            if any(len(s["entries"]) > MAX_XRANGE_ENTRIES
                   for s in streams):
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_xread returns at most %d entries "
                              "per stream; narrow the read or pass a "
                              "count" % MAX_XRANGE_ENTRIES})
                continue
            value = streams
        elif op_name == "kv_xreadgroup":
            # XREADGROUP came back shaped like XREAD inside the
            # transaction; shape it like the standalone tool does,
            # into per-stream key/entries objects. A BLOCK never
            # reaches EXEC: cinder refuses to queue it, so the
            # whole call fails up front instead. A stream wider
            # than the cap is recorded as this op's error, in
            # place, like an EXEC-time failure — the rest still
            # run.
            streams = _xread_result(reply)
            if any(len(s["entries"]) > MAX_XRANGE_ENTRIES
                   for s in streams):
                results.append(
                    {"op": op_name, "ok": False,
                     "error": "kv_xreadgroup returns at most %d entries "
                              "per stream; narrow the read or pass a "
                              "count" % MAX_XRANGE_ENTRIES})
                continue
            value = streams
        elif op_name == "kv_xpending":
            # XPENDING came back as the summary [total, min-id,
            # max-id, [[consumer, count], ...]] or the extended
            # [[id, consumer, idle-ms, deliveries], ...] inside the
            # transaction; shape it like the standalone tool does.
            value = _xpending_result(
                reply, _xpending_args(op)[2] is not None)
        elif op_name == "kv_xclaim":
            # XCLAIM came back as [[id, [field, value, ...]], ...]
            # — or only the IDs with JUSTID — inside the
            # transaction; shape it like the standalone tool does,
            # into id/fields objects in the order the IDs were
            # given. An EXEC-time NOGROUP or WRONGTYPE is recorded
            # in place, like any other EXEC-time failure.
            value = _xclaim_result(reply, _xclaim_args(op)[9])
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
        elif op_name == "kv_geodist":
            # GEODIST came back as a bulk distance string (or nil)
            # inside the transaction; parse it like the standalone
            # tool does.
            value = None if reply is None else float(reply)
        elif op_name == "kv_geopos":
            # GEOPOS came back as a list of [longitude, latitude]
            # pairs (or nulls) inside the transaction; shape it
            # like the standalone tool does.
            value = _geopos_result(reply)
        elif op_name in ("kv_geosearch", "kv_geosearchstore",
                         "kv_georadius", "kv_georadiusbymember",
                         "kv_georadius_ro", "kv_georadiusbymember_ro"):
            # A geo search came back as a member list — plain names
            # or nested arrays with the WITH* fields — or as a
            # stored count for a GEORADIUS with STORE / STOREDIST
            # or a GEOSEARCHSTORE, which always stores; shape it
            # like the standalone tool does. A search wider than
            # the cap is recorded as this op's error, in place,
            # like an EXEC-time failure — the rest still run.
            if op_name == "kv_geosearchstore":
                # GEOSEARCHSTORE always stores: cinder answers the
                # stored count as an integer.
                value = reply
            elif op_name == "kv_geosearch":
                options = _geosearch_args(op)[3]
                store = None
                try:
                    value = _geosearch_result(reply, options, op_name)
                except ValueError as exc:
                    results.append(
                        {"op": op_name, "ok": False, "error": str(exc)})
                    continue
            else:
                _k, _c, _r, _u, options, store = _georadius_args(
                    op, op_name,
                    op_name in ("kv_georadiusbymember",
                                "kv_georadiusbymember_ro"),
                    read_only=op_name.endswith("_ro"))
                if store is not None:
                    value = reply
                else:
                    try:
                        value = _geosearch_result(reply, options, op_name)
                    except ValueError as exc:
                        results.append(
                            {"op": op_name, "ok": False,
                             "error": str(exc)})
                        continue
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
                                     _zinter_args(op)[3])
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
    if name in ("kv_hexpire", "kv_hpexpire", "kv_hexpireat",
                "kv_hpexpireat"):
        # HEXPIRE key seconds [NX|XX|GT|LT] FIELDS numfields field
        # ... — HPEXPIRE the same in milliseconds, HEXPIREAT /
        # HPEXPIREAT with an absolute Unix time instead.
        command, time_field = {
            "kv_hexpire": ("HEXPIRE", "seconds"),
            "kv_hpexpire": ("HPEXPIRE", "milliseconds"),
            "kv_hexpireat": ("HEXPIREAT", "seconds"),
            "kv_hpexpireat": ("HPEXPIREAT", "milliseconds"),
        }[name]
        key, time_value, condition, fields = _hexpire_time_args(
            args, name, time_field,
            absolute=name.endswith("at"),
            is_ms=name in ("kv_hpexpire", "kv_hpexpireat"),
        )
        cmd = [command, key, time_value]
        if condition is not None:
            cmd.append(condition)
        return cmd + ["FIELDS", len(fields)] + fields
    if name in ("kv_httl", "kv_hpttl", "kv_hpersist"):
        # HTTL / HPTTL / HPERSIST key FIELDS numfields field ...
        command = {"kv_httl": "HTTL", "kv_hpttl": "HPTTL",
                   "kv_hpersist": "HPERSIST"}[name]
        fields = _hexpire_fields_args(args, name)
        return [command, _require(args, "key"),
                "FIELDS", len(fields)] + fields
    if name == "kv_xadd":
        # XADD key [MAXLEN [~] threshold] id field value ... —
        # the MAXLEN option comes before the ID, as in cinder.
        key, id_value, field_argv, maxlen, approximate = _xadd_args(args)
        cmd = ["XADD", key]
        if maxlen is not None:
            if approximate:
                cmd += ["MAXLEN", "~", maxlen]
            else:
                cmd += ["MAXLEN", maxlen]
        return cmd + [id_value] + field_argv
    if name == "kv_xrange":
        # XRANGE key start end [COUNT count] — COUNT is always
        # sent, so the reply stays bounded even when the caller
        # did not ask for a count: one past the cap, and the
        # extra entry proves the range is too wide.
        key, start, end, count = _xrange_args(args)
        return ["XRANGE", key, start, end, "COUNT",
                count if count is not None else MAX_XRANGE_ENTRIES + 1]
    if name == "kv_xrevrange":
        # XREVRANGE key end start [COUNT count] — the bounds are
        # given end-first, as in Redis, and COUNT is always sent,
        # so the reply stays bounded even when the caller did not
        # ask for a count: one past the cap, and the extra entry
        # proves the range is too wide.
        key, end, start, count = _xrevrange_args(args)
        return ["XREVRANGE", key, end, start, "COUNT",
                count if count is not None else MAX_XRANGE_ENTRIES + 1]
    if name == "kv_xlen":
        return ["XLEN", _require(args, "key")]
    if name == "kv_xread":
        # XREAD [COUNT count] [BLOCK milliseconds] STREAMS key ...
        # id ... — COUNT is always sent, so the reply stays bounded
        # even when the caller did not ask for a count: one past
        # the cap, and the extra entry proves the stream is too
        # wide. BLOCK is sent as given: cinder refuses it inside
        # MULTI at queue time, so an atomic batch carrying one
        # fails the whole call before anything runs.
        keys, ids, count, block = _xread_args(args)
        cmd = ["XREAD", "COUNT",
               count if count is not None else MAX_XRANGE_ENTRIES + 1]
        if block is not None:
            cmd += ["BLOCK", block]
        return cmd + ["STREAMS"] + keys + ids
    if name == "kv_xreadgroup":
        # XREADGROUP GROUP group consumer [COUNT count] [BLOCK ms]
        # STREAMS key ... id ... — COUNT is always sent, so the
        # reply stays bounded even when the caller did not ask for
        # a count: one past the cap, and the extra entry proves the
        # stream is too wide. BLOCK is sent as given: cinder
        # refuses it inside MULTI at queue time, so an atomic
        # batch carrying one fails the whole call before anything
        # runs.
        group, consumer, keys, ids, count, block = _xreadgroup_args(args)
        cmd = ["XREADGROUP", "GROUP", group, consumer, "COUNT",
               count if count is not None else MAX_XRANGE_ENTRIES + 1]
        if block is not None:
            cmd += ["BLOCK", block]
        return cmd + ["STREAMS"] + keys + ids
    if name == "kv_xpending":
        # XPENDING key group, or XPENDING key group start end count
        # [consumer] for the extended form.
        key, group, start, end, count, consumer = _xpending_args(args)
        if start is None:
            return ["XPENDING", key, group]
        cmd = ["XPENDING", key, group, start, end, count]
        if consumer is not None:
            cmd.append(consumer)
        return cmd
    if name == "kv_xgroup_create":
        # XGROUP CREATE key group id [MKSTREAM] — the id is "$" by
        # default (only entries added after the group is created),
        # "0" from the beginning, or an explicit ID; MKSTREAM
        # creates the stream empty when it does not exist.
        key, group, id_value, mkstream = _xgroup_create_args(args)
        cmd = ["XGROUP", "CREATE", key, group, id_value]
        if mkstream:
            cmd.append("MKSTREAM")
        return cmd
    if name == "kv_xack":
        # XACK key group id [id ...] — the count of entries
        # dropped from the group's pending list.
        key, group, ids = _xack_args(args)
        return ["XACK", key, group] + ids
    if name == "kv_xclaim":
        # XCLAIM key group consumer min-idle-time id [id ...]
        # [IDLE ms] [TIME ms] [RETRYCOUNT n] [FORCE] [JUSTID] —
        # the options are sent in that order, as in cinder's
        # parser, and IDLE and TIME never combine.
        (key, group, consumer, min_idle_ms, ids, idle_ms, time_ms,
         retrycount, force, justid) = _xclaim_args(args)
        cmd = ["XCLAIM", key, group, consumer, min_idle_ms] + ids
        if idle_ms is not None:
            cmd += ["IDLE", idle_ms]
        if time_ms is not None:
            cmd += ["TIME", time_ms]
        if retrycount is not None:
            cmd += ["RETRYCOUNT", retrycount]
        if force:
            cmd.append("FORCE")
        if justid:
            cmd.append("JUSTID")
        return cmd
    if name == "kv_xgroup_setid":
        # XGROUP SETID key group id — the id is "$" by default
        # (the top ID at call time), "0" from the beginning, or
        # an explicit ID; cinder has no ENTRIESREAD option, so
        # none is sent.
        key, group, id_value = _xgroup_setid_args(args)
        return ["XGROUP", "SETID", key, group, id_value]
    if name == "kv_xgroup_destroy":
        # XGROUP DESTROY key group — drops the whole group:
        # cursor, consumers and pending list. The stream and its
        # entries survive.
        key, group = _xgroup_destroy_args(args)
        return ["XGROUP", "DESTROY", key, group]
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
    if name == "kv_zunionstore":
        destination, keys, weights, aggregate = _zstore_args(
            args, name, True)
        cmd = ["ZUNIONSTORE", destination, len(keys)] + list(keys)
        if weights is not None:
            cmd.append("WEIGHTS")
            cmd += [repr(weight) for weight in weights]
        if aggregate is not None:
            cmd += ["AGGREGATE", aggregate.upper()]
        return cmd
    if name == "kv_zinterstore":
        destination, keys, weights, aggregate = _zstore_args(
            args, name, True)
        cmd = ["ZINTERSTORE", destination, len(keys)] + list(keys)
        if weights is not None:
            cmd.append("WEIGHTS")
            cmd += [repr(weight) for weight in weights]
        if aggregate is not None:
            cmd += ["AGGREGATE", aggregate.upper()]
        return cmd
    if name == "kv_zdiffstore":
        destination, keys, _weights, _aggregate = _zstore_args(
            args, name, False)
        return ["ZDIFFSTORE", destination, len(keys)] + list(keys)
    if name == "kv_pfadd":
        key, elements = _pfadd_args(args)
        return ["PFADD", key] + list(elements)
    if name == "kv_pfcount":
        return ["PFCOUNT"] + _pfcount_keys_args(args)
    if name == "kv_pfmerge":
        destination, sources = _pfmerge_args(args)
        return ["PFMERGE", destination] + list(sources)
    if name == "kv_geoadd":
        key, triples = _geoadd_args(args)
        argv = ["GEOADD", key] + _geoadd_options(args)
        for member, longitude, latitude in triples:
            argv += [repr(longitude), repr(latitude), member]
        return argv
    if name == "kv_geodist":
        key, member1, member2, unit = _geodist_args(args)
        if unit == "m":
            return ["GEODIST", key, member1, member2]
        return ["GEODIST", key, member1, member2, unit]
    if name == "kv_geopos":
        return ["GEOPOS", _require(args, "key")] + _geo_members_args(args, name)
    if name == "kv_geohash":
        return ["GEOHASH", _require(args, "key")] + _geo_members_args(args, name)
    if name == "kv_geosearch":
        key, centre, shape, options = _geosearch_args(args)
        sort_desc, count, count_any, withdist, withhash, withcoord = options
        cmd = ["GEOSEARCH", key]
        if centre[0] == "member":
            cmd += ["FROMMEMBER", centre[1]]
        else:
            cmd += ["FROMLONLAT", repr(centre[1]), repr(centre[2])]
        if shape[0] == "radius":
            cmd += ["BYRADIUS", repr(shape[1]), shape[2]]
        else:
            cmd += ["BYBOX", repr(shape[1]), repr(shape[2]), shape[3]]
        cmd += _geo_search_option_argv(sort_desc, count, count_any,
                                       withdist, withhash, withcoord)
        return cmd
    if name == "kv_geosearchstore":
        destination, key, centre, shape, options, storedist = \
            _geosearchstore_args(args)
        sort_desc, count, count_any, _wd, _wh, _wc = options
        cmd = ["GEOSEARCHSTORE", destination, key]
        if centre[0] == "member":
            cmd += ["FROMMEMBER", centre[1]]
        else:
            cmd += ["FROMLONLAT", repr(centre[1]), repr(centre[2])]
        if shape[0] == "radius":
            cmd += ["BYRADIUS", repr(shape[1]), shape[2]]
        else:
            cmd += ["BYBOX", repr(shape[1]), repr(shape[2]), shape[3]]
        # The WITH* options are rejected by _geosearchstore_args,
        # so they are always false here; GEOSEARCHSTORE stores
        # its hits instead of returning them.
        cmd += _geo_search_option_argv(sort_desc, count, count_any,
                                       False, False, False)
        if storedist:
            cmd.append("STOREDIST")
        return cmd
    if name == "kv_georadius":
        key, centre, radius, unit, options, store = _georadius_args(
            args, name, False)
        sort_desc, count, count_any, withdist, withhash, withcoord = options
        _kind, lon, lat = centre
        cmd = ["GEORADIUS", key, repr(lon), repr(lat), repr(radius), unit]
        cmd += _geo_search_option_argv(sort_desc, count, count_any,
                                       withdist, withhash, withcoord)
        if store is not None:
            cmd += [store[0].upper(), store[1]]
        return cmd
    if name == "kv_georadiusbymember":
        key, centre, radius, unit, options, store = _georadius_args(
            args, name, True)
        sort_desc, count, count_any, withdist, withhash, withcoord = options
        cmd = ["GEORADIUSBYMEMBER", key, centre[1], repr(radius), unit]
        cmd += _geo_search_option_argv(sort_desc, count, count_any,
                                       withdist, withhash, withcoord)
        if store is not None:
            cmd += [store[0].upper(), store[1]]
        return cmd
    if name == "kv_georadius_ro":
        # The read-only variant: same search, no STORE / STOREDIST
        # — _georadius_args rejects them before anything is sent.
        key, centre, radius, unit, options, _store = _georadius_args(
            args, name, False, read_only=True)
        sort_desc, count, count_any, withdist, withhash, withcoord = options
        _kind, lon, lat = centre
        cmd = ["GEORADIUS_RO", key, repr(lon), repr(lat), repr(radius), unit]
        cmd += _geo_search_option_argv(sort_desc, count, count_any,
                                       withdist, withhash, withcoord)
        return cmd
    if name == "kv_georadiusbymember_ro":
        key, centre, radius, unit, options, _store = _georadius_args(
            args, name, True, read_only=True)
        sort_desc, count, count_any, withdist, withhash, withcoord = options
        cmd = ["GEORADIUSBYMEMBER_RO", key, centre[1], repr(radius), unit]
        cmd += _geo_search_option_argv(sort_desc, count, count_any,
                                       withdist, withhash, withcoord)
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
    if name == "kv_zrevrange":
        key, start, stop, withscores = _zrevrange_args(args)
        # A range both ends of which are non-negative has a known
        # width; check the bound here. A negative bound needs the
        # set's size, which the caller checks with _check_zrange_window.
        if start >= 0 and stop >= 0 and stop - start + 1 > MAX_ZRANGE_MEMBERS:
            raise ValueError(
                "kv_zrevrange returns at most %d members; narrow the range"
                % MAX_ZRANGE_MEMBERS
            )
        cmd = ["ZREVRANGE", key, start, stop]
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
    if name == "kv_zrevrangebyscore":
        key, min_b, max_b, withscores, offset, count = \
            _zrevrangebyscore_args(args)
        # ZREVRANGEBYSCORE takes its bounds max-first, as in
        # cinder; the reply is capped at MAX_ZRANGE_MEMBERS members
        # the same way as kv_zrangebyscore (see above).
        probe = count if count >= 0 else MAX_ZRANGE_MEMBERS + 1
        cmd = ["ZREVRANGEBYSCORE", key, max_b, min_b]
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


# The most fields one hash-field TTL call covers; a wider call
# fails instead of returning a silently truncated list.
MAX_HASH_TTL_FIELDS = 1000

# The one condition a HEXPIRE-family call may carry, between the
# time and FIELDS.
HEXPIRE_CONDITIONS = ("nx", "xx", "gt", "lt")


def _hexpire_fields_args(args, name):
    """The field names for a hash-field TTL call, as an argv list.
    `fields` must be a non-empty list of strings, at most
    MAX_HASH_TTL_FIELDS; anything else fails the call instead of
    sending a half-formed command."""
    fields = _hash_fields_args(args, name)
    if len(fields) > MAX_HASH_TTL_FIELDS:
        raise ValueError(
            "%s fields must have at most %d entries, got %d"
            % (name, MAX_HASH_TTL_FIELDS, len(fields))
        )
    return fields


def _hexpire_condition(args, name):
    """The optional NX/XX/GT/LT condition for a HEXPIRE-family
    call, upper-cased for the argv, or None when no condition was
    given. Anything else fails as invalid params instead of as a
    server syntax error."""
    condition = args.get("condition")
    if condition is None:
        return None
    if not isinstance(condition, str) \
            or condition.lower() not in HEXPIRE_CONDITIONS:
        raise ValueError(
            "%s condition must be one of nx, xx, gt, lt: %r"
            % (name, condition)
        )
    return condition.upper()


def _hexpire_time_args(args, name, time_field, absolute, is_ms):
    """Validate a HEXPIRE-family call: (key, time, condition,
    fields). The time must be an integer: a relative one must be 0
    or more — 0 deletes the fields at once, as in Redis — while an
    absolute one may be in the past (it deletes the fields too)
    but must fit in a signed 64-bit integer, and for seconds must
    survive cinder's conversion to milliseconds, as cinder's
    parser requires."""
    key = _require(args, "key")
    time_value = _require(args, time_field)
    if isinstance(time_value, bool) or not isinstance(time_value, int):
        raise ValueError("%s %s must be an integer" % (name, time_field))
    if absolute:
        if is_ms:
            lo, hi = -(2 ** 63), 2 ** 63 - 1
        else:
            lo = -((2 ** 63 - 1) // 1000)
            hi = (2 ** 63 - 1) // 1000
        if time_value < lo or time_value > hi:
            raise ValueError(
                "%s %s is out of range: %r" % (name, time_field, time_value)
            )
    elif time_value < 0:
        raise ValueError(
            "%s %s must be 0 or more, got %d"
            % (name, time_field, time_value)
        )
    condition = _hexpire_condition(args, name)
    fields = _hexpire_fields_args(args, name)
    return key, time_value, condition, fields


# The most entries one kv_xrange call returns; a wider range fails
# instead of dumping a huge slice of a stream into one tool result.
MAX_XRANGE_ENTRIES = 1000

# Stream IDs are two unsigned 64-bit parts; cinder's parser rejects
# anything wider, as well as any non-digit.
_STREAM_U64_MAX = 2 ** 64 - 1


def _stream_u64(text, tool, what):
    """One millisecond or sequence part of a stream ID or bound, as
    an integer. The text must be non-empty decimal digits that fit
    in an unsigned 64-bit integer — cinder's parser rejects
    anything else as an invalid stream ID, so fail here as invalid
    params instead."""
    if (not isinstance(text, str) or not text
            or any(ch < "0" or ch > "9" for ch in text)):
        raise ValueError(
            "%s %s must be decimal digits, got %r" % (tool, what, text)
        )
    value = int(text)
    if value > _STREAM_U64_MAX:
        raise ValueError(
            "%s %s is out of range: %r" % (tool, what, text)
        )
    return value


def _stream_xadd_id(value, tool="kv_xadd"):
    """The ID for an XADD: "*" (auto), "ms-seq" (explicit), or
    "ms-*" / "ms-" (partial, the sequence is automatic). A bare
    millisecond is not an ID — cinder rejects it — and an explicit
    "0-0" fails, since an ID must be greater than 0-0; a partial
    "0-*" is allowed, and on an empty stream it resolves to 0-0.
    The ID is returned verbatim for the argv."""
    if not isinstance(value, str):
        raise ValueError("%s id must be a string" % tool)
    if value == "*":
        return value
    if "-" not in value:
        raise ValueError(
            "%s id must be \"*\", \"ms-seq\", \"ms-*\" or \"ms-\", got %r"
            % (tool, value)
        )
    ms_text, seq_text = value.split("-", 1)
    ms = _stream_u64(ms_text, tool, "id ms part")
    if seq_text in ("*", ""):
        # Partial ID: the sequence is automatic for this ms.
        return value
    seq = _stream_u64(seq_text, tool, "id sequence part")
    if ms == 0 and seq == 0:
        raise ValueError(
            "%s id must be greater than 0-0" % tool
        )
    return value


def _stream_bound(value, tool="kv_xrange"):
    """One XRANGE bound: "-" (the first entry), "+" (the last), a
    bare millisecond (the whole millisecond), or "ms-seq". A bound
    like "7-" — a dash with no sequence — is not valid, and neither
    is "*" or a non-numeric bound. The bound is returned verbatim
    for the argv."""
    if not isinstance(value, str):
        raise ValueError("%s bound must be a string" % tool)
    if value in ("-", "+"):
        return value
    if "-" not in value:
        _stream_u64(value, tool, "bound")
        return value
    ms_text, seq_text = value.split("-", 1)
    _stream_u64(ms_text, tool, "bound ms part")
    _stream_u64(seq_text, tool, "bound sequence part")
    return value


def _xadd_args(args):
    """Validate a kv_xadd call: (key, id, field argv, maxlen,
    approximate). `fields` must be a non-empty object of string
    field names to string values, sent in sorted field order so
    the argv is deterministic, like kv_hset's. `maxlen` must be an
    integer 0 or more when given; `approximate` must be a boolean
    when given."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xadd key must be a string")
    id_value = _stream_xadd_id(args.get("id", "*"))
    fields = args.get("fields")
    if not isinstance(fields, dict) or not fields:
        raise ValueError("kv_xadd fields must be a non-empty object")
    field_argv = []
    for field in sorted(fields):
        value = fields[field]
        if not isinstance(field, str) or not isinstance(value, str):
            raise ValueError(
                "kv_xadd fields must map string field names to string values"
            )
        field_argv += [field, value]
    maxlen = args.get("maxlen")
    approximate = args.get("approximate", False)
    if not isinstance(approximate, bool):
        raise ValueError("kv_xadd approximate must be true or false")
    if maxlen is not None:
        if isinstance(maxlen, bool) or not isinstance(maxlen, int):
            raise ValueError("kv_xadd maxlen must be an integer")
        if maxlen < 0:
            raise ValueError(
                "kv_xadd maxlen must be 0 or more, got %d" % maxlen
            )
    return key, id_value, field_argv, maxlen, approximate


def _xrange_args(args):
    """Validate a kv_xrange call: (key, start, end, count). The
    bounds default to "-" and "+". `count` must be an integer
    between 0 and MAX_XRANGE_ENTRIES when given — 0 answers an
    empty list, as in cinder."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xrange key must be a string")
    start = _stream_bound(args.get("start", "-"))
    end = _stream_bound(args.get("end", "+"))
    count = args.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("kv_xrange count must be an integer")
        if count < 0 or count > MAX_XRANGE_ENTRIES:
            raise ValueError(
                "kv_xrange count must be between 0 and %d, got %d"
                % (MAX_XRANGE_ENTRIES, count)
            )
    return key, start, end, count


def _xrange_result(reply):
    """Shape a flat XRANGE reply [[id, [field, value, ...]], ...]
    into [{"id": ..., "fields": {...}}, ...], in ID order. A
    missing key replies as an empty list, which becomes []. A
    field named twice in one entry keeps only its last value in
    the object — cinder stores both, but the object has one slot
    per field name, as in HGETALL's dict shaping."""
    entries = []
    for entry_id, flat in reply or []:
        entries.append({
            "id": entry_id,
            "fields": {flat[i]: flat[i + 1]
                       for i in range(0, len(flat), 2)},
        })
    return entries


def _xrevrange_args(args):
    """Validate a kv_xrevrange call: (key, end, start, count). The
    bounds default to "+" and "-" — given end-first, as in Redis,
    so the defaults read the whole stream newest-first. `count`
    must be an integer between 0 and MAX_XRANGE_ENTRIES when given
    — 0 answers an empty list, as in cinder. The bounds validate
    with the same rules as kv_xrange's, so a malformed bound fails
    here as invalid params instead of as a server error."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xrevrange key must be a string")
    end = _stream_bound(args.get("end", "+"), "kv_xrevrange")
    start = _stream_bound(args.get("start", "-"), "kv_xrevrange")
    count = args.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("kv_xrevrange count must be an integer")
        if count < 0 or count > MAX_XRANGE_ENTRIES:
            raise ValueError(
                "kv_xrevrange count must be between 0 and %d, got %d"
                % (MAX_XRANGE_ENTRIES, count)
            )
    return key, end, start, count


def _call_xrevrange(client, args):
    """kv_xrevrange: the entries in [start, end], newest first,
    shaped into id/fields objects. At most MAX_XRANGE_ENTRIES
    entries per call; a wider range fails instead of returning a
    truncated list."""
    reply = client.command(*_op_argv("kv_xrevrange", args))
    entries = _xrange_result(reply or [])
    if len(entries) > MAX_XRANGE_ENTRIES:
        raise ValueError(
            "kv_xrevrange returns at most %d entries; narrow the range "
            "or pass a count" % MAX_XRANGE_ENTRIES
        )
    return entries


def _call_xrange(client, args):
    """kv_xrange: the entries in [start, end], shaped into
    id/fields objects. At most MAX_XRANGE_ENTRIES entries per call;
    a wider range fails instead of returning a truncated list."""
    reply = client.command(*_op_argv("kv_xrange", args))
    entries = _xrange_result(reply or [])
    if len(entries) > MAX_XRANGE_ENTRIES:
        raise ValueError(
            "kv_xrange returns at most %d entries; narrow the range "
            "or pass a count" % MAX_XRANGE_ENTRIES
        )
    return entries


# The most streams one kv_xread call reads; each stream can return
# up to MAX_XRANGE_ENTRIES entries, so the bound keeps one call
# from asking for an unbounded slice of the keyspace.
MAX_XREAD_STREAMS = 100

# The longest a kv_xread BLOCK may wait, in milliseconds. BLOCK 0
# waits forever, which has no place in a one-shot tool call, and
# the socket to cinder times out after 5 seconds — a longer block
# would die as a connection error instead of a clean timeout.
MAX_XREAD_BLOCK_MS = 4000


def _stream_xread_id(value, tool="kv_xread"):
    """One XREAD stream ID: "$" (the stream's top ID at read time,
    resolved once, so only entries added after the read qualify),
    "-" (after 0-0: every entry), "+" (after the last ID:
    nothing), a bare millisecond (the whole millisecond: entries
    after ms-0), or "ms-seq". ">" needs kv_xreadgroup, so it fails here as invalid params instead of
    as a server error. The ID is returned verbatim for the argv."""
    if not isinstance(value, str):
        raise ValueError("%s id must be a string" % tool)
    if value == "$":
        return value
    if value == ">":
        raise ValueError(
            "%s id \">\" needs kv_xreadgroup, not kv_xread"
            % tool
        )
    return _stream_bound(value, tool)


def _xread_args(args):
    """Validate a kv_xread call: (keys, ids, count, block).
    `streams` must be a non-empty object mapping stream keys to
    IDs, at most MAX_XREAD_STREAMS, sent in sorted key order so
    the argv is deterministic. `count` is the entries per stream,
    1..MAX_XRANGE_ENTRIES when given — 0 is not sent, since
    cinder needs a positive COUNT for XREAD (unlike XRANGE).
    `block` is the milliseconds to wait for new entries,
    1..MAX_XREAD_BLOCK_MS when given — 0 would wait forever."""
    streams = args.get("streams")
    if not isinstance(streams, dict) or not streams:
        raise ValueError("kv_xread streams must be a non-empty object")
    if len(streams) > MAX_XREAD_STREAMS:
        raise ValueError(
            "kv_xread reads at most %d streams; narrow the list"
            % MAX_XREAD_STREAMS
        )
    keys = []
    for key in streams:
        if not isinstance(key, str):
            raise ValueError(
                "kv_xread streams must map string stream names to IDs"
            )
        keys.append(key)
    keys.sort()
    ids = [_stream_xread_id(streams[key]) for key in keys]
    count = args.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("kv_xread count must be an integer")
        if count < 1 or count > MAX_XRANGE_ENTRIES:
            raise ValueError(
                "kv_xread count must be between 1 and %d, got %d"
                % (MAX_XRANGE_ENTRIES, count)
            )
    block = args.get("block")
    if block is not None:
        if isinstance(block, bool) or not isinstance(block, int):
            raise ValueError("kv_xread block must be an integer")
        if block < 1 or block > MAX_XREAD_BLOCK_MS:
            raise ValueError(
                "kv_xread block must be between 1 and %d "
                "milliseconds, got %d" % (MAX_XREAD_BLOCK_MS, block)
            )
    return keys, ids, count, block


def _xread_result(reply):
    """Shape a flat XREAD reply [[key, [[id, [field, value,
    ...]], ...]], ...] into [{"key": ..., "entries": [{"id": ...,
    "fields": {...}}, ...]}, ...], in cinder's order — streams
    with nothing new are left out. A nil reply (a BLOCK that
    timed out) becomes [], as does an empty array."""
    streams = []
    for key, entries in reply or []:
        streams.append({
            "key": key,
            "entries": _xrange_result(entries),
        })
    return streams


def _call_xread(client, args):
    """kv_xread: the entries after each stream's ID, shaped into
    per-stream key/entries objects. At most MAX_XRANGE_ENTRIES
    entries per stream; a wider stream fails instead of returning
    a truncated list."""
    reply = client.command(*_op_argv("kv_xread", args))
    streams = _xread_result(reply)
    for stream in streams:
        if len(stream["entries"]) > MAX_XRANGE_ENTRIES:
            raise ValueError(
                "kv_xread returns at most %d entries per stream; "
                "narrow the read or pass a count"
                % MAX_XRANGE_ENTRIES
            )
    return streams


def _xreadgroup_id(value, tool="kv_xreadgroup"):
    """One XREADGROUP stream ID: ">" (the entries after the group's
    cursor — the new entries, delivered to this consumer and
    recorded in the pending list) or an explicit ID ("-" for every
    pending entry of this consumer, a bare millisecond for the
    entries after that whole millisecond, or "ms-seq"). "$" is not
    valid here: cinder rejects it, so it fails as invalid params
    instead of as a server error. The ID is returned verbatim for
    the argv."""
    if not isinstance(value, str):
        raise ValueError("%s id must be a string" % tool)
    if value == ">":
        return value
    if value == "$":
        raise ValueError(
            "%s id \"$\" is not valid: use \">\" for new entries or an "
            "explicit ID to re-read pending entries" % tool
        )
    return _stream_bound(value, tool)


def _xreadgroup_args(args):
    """Validate a kv_xreadgroup call: (group, consumer, keys, ids,
    count, block). `group` and `consumer` must be strings.
    `streams` must be a non-empty object mapping stream keys to
    IDs, at most MAX_XREAD_STREAMS, sent in sorted key order so
    the argv is deterministic. `count` is the entries per stream,
    1..MAX_XRANGE_ENTRIES when given — 0 is not sent, since cinder
    needs a positive COUNT for XREADGROUP (unlike XRANGE).
    `block` is the milliseconds to wait for new entries,
    1..MAX_XREAD_BLOCK_MS when given — 0 would wait forever, and
    the socket to cinder times out after 5 seconds, so a longer
    block would die as a connection error instead of a clean
    timeout. A blocked read with an explicit ID never wakes on
    new entries: only entries already pending for this consumer
    answer it, so it waits out the whole block when nothing is
    pending."""
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xreadgroup group must be a string")
    consumer = _require(args, "consumer")
    if not isinstance(consumer, str):
        raise ValueError("kv_xreadgroup consumer must be a string")
    streams = args.get("streams")
    if not isinstance(streams, dict) or not streams:
        raise ValueError("kv_xreadgroup streams must be a non-empty object")
    if len(streams) > MAX_XREAD_STREAMS:
        raise ValueError(
            "kv_xreadgroup reads at most %d streams; narrow the list"
            % MAX_XREAD_STREAMS
        )
    keys = []
    for key in streams:
        if not isinstance(key, str):
            raise ValueError(
                "kv_xreadgroup streams must map string stream names to IDs"
            )
        keys.append(key)
    keys.sort()
    ids = [_xreadgroup_id(streams[key]) for key in keys]
    count = args.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("kv_xreadgroup count must be an integer")
        if count < 1 or count > MAX_XRANGE_ENTRIES:
            raise ValueError(
                "kv_xreadgroup count must be between 1 and %d, got %d"
                % (MAX_XRANGE_ENTRIES, count)
            )
    block = args.get("block")
    if block is not None:
        if isinstance(block, bool) or not isinstance(block, int):
            raise ValueError("kv_xreadgroup block must be an integer")
        if block < 1 or block > MAX_XREAD_BLOCK_MS:
            raise ValueError(
                "kv_xreadgroup block must be between 1 and %d "
                "milliseconds, got %d" % (MAX_XREAD_BLOCK_MS, block)
            )
    return group, consumer, keys, ids, count, block


def _call_xreadgroup(client, args):
    """kv_xreadgroup: the entries delivered to one consumer of a
    group, shaped into per-stream key/entries objects like
    kv_xread. At most MAX_XRANGE_ENTRIES entries per stream; a
    wider stream fails instead of returning a truncated list."""
    reply = client.command(*_op_argv("kv_xreadgroup", args))
    streams = _xread_result(reply)
    for stream in streams:
        if len(stream["entries"]) > MAX_XRANGE_ENTRIES:
            raise ValueError(
                "kv_xreadgroup returns at most %d entries per stream; "
                "narrow the read or pass a count"
                % MAX_XRANGE_ENTRIES
            )
    return streams


# The most pending entries one kv_xpending extended call lists;
# the same bounded-reply cap as the stream range tools.
MAX_XPENDING_ENTRIES = 1000


def _xpending_args(args):
    """Validate a kv_xpending call: (key, group, start, end, count,
    consumer). With no range arguments the call is the summary form
    and start/end/count/consumer are all None. The extended form
    needs start, end and count together — cinder takes no partial
    form — and consumer only with it. `count` is the entries
    listed, 1..MAX_XPENDING_ENTRIES. The bounds validate with the
    same rules as kv_xrange's, so a malformed bound fails here as
    invalid params instead of as a server error."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xpending key must be a string")
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xpending group must be a string")
    start = args.get("start")
    end = args.get("end")
    count = args.get("count")
    consumer = args.get("consumer")
    if start is None and end is None and count is None and consumer is None:
        return key, group, None, None, None, None
    if start is None or end is None or count is None:
        raise ValueError(
            "kv_xpending extended form needs start, end and count together"
        )
    start = _stream_bound(start, "kv_xpending")
    end = _stream_bound(end, "kv_xpending")
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("kv_xpending count must be an integer")
    if count < 1 or count > MAX_XPENDING_ENTRIES:
        raise ValueError(
            "kv_xpending count must be between 1 and %d, got %d"
            % (MAX_XPENDING_ENTRIES, count)
        )
    if consumer is not None and not isinstance(consumer, str):
        raise ValueError("kv_xpending consumer must be a string")
    return key, group, start, end, count, consumer


def _xpending_result(reply, extended):
    """Shape an XPENDING reply. The summary [total, min-id-or-nil,
    max-id-or-nil, [[consumer, count], ...]] becomes an object with
    total, min_id, max_id and a consumers list of consumer/count
    objects. The extended form [[id, consumer, idle-ms,
    deliveries], ...] becomes a list of id/consumer/idle_ms/
    deliveries objects, in ID order."""
    if not extended:
        total, min_id, max_id, counts = reply
        return {
            "total": total,
            "min_id": min_id,
            "max_id": max_id,
            "consumers": [
                {"consumer": consumer, "count": count}
                for consumer, count in counts
            ],
        }
    return [
        {"id": entry_id, "consumer": consumer,
         "idle_ms": idle_ms, "deliveries": deliveries}
        for entry_id, consumer, idle_ms, deliveries in reply or []
    ]


def _call_xpending(client, args):
    """kv_xpending: the summary object for a group's pending list,
    or the extended per-entry list for a range of it."""
    key, group, start, end, count, consumer = _xpending_args(args)
    reply = client.command(*_op_argv("kv_xpending", args))
    return _xpending_result(reply, start is not None)


# The most entry IDs one kv_xack call acknowledges; a wider call
# fails instead of sending a huge ack.
MAX_XACK_IDS = 1000


def _xgroup_create_args(args):
    """Validate a kv_xgroup_create call: (key, group, id,
    mkstream). `key` and `group` must be strings. `id` is the ID
    the group starts at — "$" (only entries added after the group
    is created) by default, "0" from the beginning, or an explicit
    ID validated like kv_xrange's bounds. `mkstream` must be a
    boolean when given."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xgroup_create key must be a string")
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xgroup_create group must be a string")
    id_value = args.get("id", "$")
    if not isinstance(id_value, str):
        raise ValueError("kv_xgroup_create id must be a string")
    if id_value != "$":
        id_value = _stream_bound(id_value, "kv_xgroup_create")
    mkstream = args.get("mkstream", False)
    if not isinstance(mkstream, bool):
        raise ValueError("kv_xgroup_create mkstream must be true or false")
    return key, group, id_value, mkstream


def _call_xgroup_create(client, args):
    """kv_xgroup_create: make a consumer group on a stream,
    answering "OK"."""
    reply = client.command(*_op_argv("kv_xgroup_create", args))
    return reply


def _xack_args(args):
    """Validate a kv_xack call: (key, group, ids). `key` and
    `group` must be strings. `ids` must be a non-empty list of
    entry IDs, at most MAX_XACK_IDS, each validated like
    kv_xpending's bounds — "ms-seq", or a bare millisecond, which
    cinder reads as the first sequence of that millisecond."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xack key must be a string")
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xack group must be a string")
    ids = args.get("ids")
    if not isinstance(ids, list) or not ids:
        raise ValueError("kv_xack ids must be a non-empty list")
    if len(ids) > MAX_XACK_IDS:
        raise ValueError(
            "kv_xack acks at most %d entries; narrow the list"
            % MAX_XACK_IDS
        )
    checked = []
    for id_value in ids:
        checked.append(_stream_bound(id_value, "kv_xack"))
    return key, group, checked


def _call_xack(client, args):
    """kv_xack: drop entries from a group's pending list,
    answering how many were dropped."""
    reply = client.command(*_op_argv("kv_xack", args))
    return reply


# The most entry IDs one kv_xclaim call claims; a wider call
# fails instead of sending a huge claim.
MAX_XCLAIM_IDS = 1000


def _xclaim_args(args):
    """Validate a kv_xclaim call: (key, group, consumer,
    min_idle_ms, ids, idle_ms, time_ms, retrycount, force,
    justid). `key`, `group` and `consumer` must be strings.
    `min_idle_ms` is the milliseconds an entry must have been
    idle since its last delivery, 0 or more. `ids` must be a
    non-empty list of entry IDs, at most MAX_XCLAIM_IDS, each
    validated like kv_xack's — "ms-seq", or a bare millisecond,
    which cinder reads as the first sequence of that millisecond.
    `idle_ms` sets the claimed entries' delivery time that many
    milliseconds ago and `time_ms` an absolute Unix time in
    milliseconds — both 0 or more, and never together, since
    cinder errors when they combine. `retrycount` sets the
    delivery count instead of bumping it, 0 or more. `force` and
    `justid` must be booleans when given."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xclaim key must be a string")
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xclaim group must be a string")
    consumer = _require(args, "consumer")
    if not isinstance(consumer, str):
        raise ValueError("kv_xclaim consumer must be a string")
    min_idle_ms = _require(args, "min_idle_ms")
    if isinstance(min_idle_ms, bool) or not isinstance(min_idle_ms, int):
        raise ValueError("kv_xclaim min_idle_ms must be an integer")
    if min_idle_ms < 0:
        raise ValueError(
            "kv_xclaim min_idle_ms must be 0 or more, got %d" % min_idle_ms
        )
    ids = args.get("ids")
    if not isinstance(ids, list) or not ids:
        raise ValueError("kv_xclaim ids must be a non-empty list")
    if len(ids) > MAX_XCLAIM_IDS:
        raise ValueError(
            "kv_xclaim claims at most %d entries; narrow the list"
            % MAX_XCLAIM_IDS
        )
    checked = []
    for id_value in ids:
        checked.append(_stream_bound(id_value, "kv_xclaim"))
    idle_ms = args.get("idle_ms")
    if idle_ms is not None:
        if isinstance(idle_ms, bool) or not isinstance(idle_ms, int):
            raise ValueError("kv_xclaim idle_ms must be an integer")
        if idle_ms < 0:
            raise ValueError(
                "kv_xclaim idle_ms must be 0 or more, got %d" % idle_ms
            )
    time_ms = args.get("time_ms")
    if time_ms is not None:
        if isinstance(time_ms, bool) or not isinstance(time_ms, int):
            raise ValueError("kv_xclaim time_ms must be an integer")
        if time_ms < 0:
            raise ValueError(
                "kv_xclaim time_ms must be 0 or more, got %d" % time_ms
            )
    if idle_ms is not None and time_ms is not None:
        raise ValueError(
            "kv_xclaim idle_ms and time_ms cannot be used at the same time"
        )
    retrycount = args.get("retrycount")
    if retrycount is not None:
        if isinstance(retrycount, bool) or not isinstance(retrycount, int):
            raise ValueError("kv_xclaim retrycount must be an integer")
        if retrycount < 0:
            raise ValueError(
                "kv_xclaim retrycount must be 0 or more, got %d"
                % retrycount
            )
    force = args.get("force", False)
    if not isinstance(force, bool):
        raise ValueError("kv_xclaim force must be true or false")
    justid = args.get("justid", False)
    if not isinstance(justid, bool):
        raise ValueError("kv_xclaim justid must be true or false")
    return (key, group, consumer, min_idle_ms, checked, idle_ms,
            time_ms, retrycount, force, justid)


def _xclaim_result(reply, justid):
    """Shape an XCLAIM reply. The full form [[id, [field, value,
    ...]], ...] becomes [{"id": ..., "fields": {...}}, ...] in the
    order the IDs were given, like kv_xrange's; JUSTID answers
    only the IDs, as a list of strings. An empty claim is []."""
    if justid:
        return reply or []
    return _xrange_result(reply or [])


def _call_xclaim(client, args):
    """kv_xclaim: claim pending entries of a consumer group for
    another consumer, answering the claimed entries — or only
    their IDs with justid."""
    (key, group, consumer, min_idle_ms, ids, idle_ms, time_ms,
     retrycount, force, justid) = _xclaim_args(args)
    reply = client.command(*_op_argv("kv_xclaim", args))
    return _xclaim_result(reply, justid)


def _xgroup_setid_args(args):
    """Validate a kv_xgroup_setid call: (key, group, id). `key`
    and `group` must be strings. `id` is the ID the group moves
    to — "$" (the top ID at call time) by default, "0" from the
    beginning, or an explicit ID validated like kv_xrange's
    bounds: a bare millisecond is the first sequence of that
    millisecond, "-" the first ID, "+" the last. Cinder has no
    ENTRIESREAD option for SETID, so none is accepted here."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xgroup_setid key must be a string")
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xgroup_setid group must be a string")
    id_value = args.get("id", "$")
    if not isinstance(id_value, str):
        raise ValueError("kv_xgroup_setid id must be a string")
    if id_value != "$":
        id_value = _stream_bound(id_value, "kv_xgroup_setid")
    return key, group, id_value


def _call_xgroup_setid(client, args):
    """kv_xgroup_setid: move a consumer group's last-delivered
    ID, answering "OK"."""
    reply = client.command(*_op_argv("kv_xgroup_setid", args))
    return reply


def _xgroup_destroy_args(args):
    """Validate a kv_xgroup_destroy call: (key, group). Both
    must be strings. There is no id: the whole group goes,
    whatever its cursor is."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_xgroup_destroy key must be a string")
    group = _require(args, "group")
    if not isinstance(group, str):
        raise ValueError("kv_xgroup_destroy group must be a string")
    return key, group


def _call_xgroup_destroy(client, args):
    """kv_xgroup_destroy: drop a consumer group from a stream,
    answering 1 when a group was destroyed, 0 when there was no
    such group on the stream."""
    reply = client.command(*_op_argv("kv_xgroup_destroy", args))
    return reply


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


def _zrange_args(args, tool="kv_zrange"):
    """Validate a kv_zrange call: (key, start, stop, withscores, rev).
    start defaults to 0 and stop to -1, as in Redis; withscores and
    rev default to false. Bad types fail the call instead of sending
    a half-formed ZRANGE. `tool` names the tool in the error
    messages, so kv_zrevrange shares this validator."""
    key = _require(args, "key")
    start = args.get("start", 0)
    if isinstance(start, bool) or not isinstance(start, int):
        raise ValueError("%s start must be an integer" % tool)
    stop = args.get("stop", -1)
    if isinstance(stop, bool) or not isinstance(stop, int):
        raise ValueError("%s stop must be an integer" % tool)
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("%s withscores must be true or false" % tool)
    rev = args.get("rev", False)
    if not isinstance(rev, bool):
        raise ValueError("%s rev must be true or false" % tool)
    return key, start, stop, withscores, rev


def _zrevrange_args(args):
    """Validate a kv_zrevrange call: (key, start, stop, withscores).
    The same bounds as kv_zrange, without rev — the tool always
    reads highest score first. A stray rev argument is read and
    checked like any other, then ignored, as with any extra
    argument this server does not use."""
    key, start, stop, withscores, _rev = _zrange_args(
        args, "kv_zrevrange")
    return key, start, stop, withscores


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


def _check_zrange_window(client, args, tool="kv_zrange"):
    """Fail a kv_zrange call whose range would return more than
    MAX_ZRANGE_MEMBERS members. A range with a negative bound needs
    the set's size first, so it reads ZCARD; a range both ends of
    which are non-negative is checked without a round trip. A missing
    key has size 0, so the check passes and the range returns [].
    `tool` names the tool in the error message, so kv_zrevrange
    shares this check."""
    key, start, stop, _, _ = _zrange_args(args, tool)
    if start >= 0 and stop >= 0:
        window = stop - start + 1
    else:
        window = _zrange_window(start, stop, client.command("ZCARD", key) or 0)
    if window > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "%s returns at most %d members; narrow the range"
            % (tool, MAX_ZRANGE_MEMBERS)
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


def _geopos_result(reply):
    """Shape a GEOPOS reply into the tool's return value: one
    {"longitude": ..., "latitude": ...} object per member, in
    request order, or null for a member that is not in the set —
    and for a member whose score does not decode as a geohash
    (cinder replies with a null array for those)."""
    positions = []
    for pair in (reply or []):
        if pair is None:
            positions.append(None)
        else:
            positions.append({
                "longitude": float(pair[0]),
                "latitude": float(pair[1]),
            })
    return positions


def _call_geodist(client, args):
    """kv_geodist: the distance as a number in the requested unit,
    or null when the key or either member does not exist (cinder
    replies nil). Cinder answers with four decimals, so the number
    carries that rounding."""
    reply = client.command(*_op_argv("kv_geodist", args))
    return None if reply is None else float(reply)


def _call_geopos(client, args):
    """kv_geopos: the members' positions in request order, with
    null for a member that is not in the set."""
    return _geopos_result(client.command(*_op_argv("kv_geopos", args)))


def _call_geohash(client, args):
    """kv_geohash: the members' geohash strings in request order,
    with null for a member that is not in the set."""
    return list(client.command(*_op_argv("kv_geohash", args)) or [])


def _geosearch_result(reply, options, tool):
    """Shape a GEOSEARCH / GEORADIUS reply into the tool's return
    value: member names in distance order, or one object per hit
    when any WITH* option was given — {"member": ...} plus
    "distance" (a number in the shape's unit), "hash" (the 52-bit
    geohash score as an integer) and "coord" ({"longitude": ...,
    "latitude": ...}) for the options requested, in that order.
    Cinder answers the distance as a "%.4f" bulk string and the
    coordinates as bulk strings, the hash as an integer. A search
    wider than MAX_GEOSEARCH_MEMBERS fails instead of returning a
    truncated list."""
    _sort_desc, _count, _any, withdist, withhash, withcoord = options
    hits = reply or []
    if len(hits) > MAX_GEOSEARCH_MEMBERS:
        raise ValueError(
            "%s returns at most %d members; narrow the search or "
            "add a count" % (tool, MAX_GEOSEARCH_MEMBERS))
    if not (withdist or withhash or withcoord):
        return list(hits)
    shaped = []
    for hit in hits:
        # A hit is [member, distance?, hash?, [lon, lat]?] in that
        # order — the distance, then the hash, then the
        # coordinates, as in Redis.
        item = {"member": hit[0]}
        index = 1
        if withdist:
            item["distance"] = float(hit[index])
            index += 1
        if withhash:
            item["hash"] = hit[index]
            index += 1
        if withcoord:
            item["coord"] = {
                "longitude": float(hit[index][0]),
                "latitude": float(hit[index][1]),
            }
        shaped.append(item)
    return shaped


def _call_geosearch(client, args):
    """kv_geosearch: the members inside the shape, nearest-first
    by default, or one object per hit with the WITH* fields."""
    options = _geosearch_args(args)[3]
    return _geosearch_result(
        client.command(*_op_argv("kv_geosearch", args)), options,
        "kv_geosearch")


def _call_geosearchstore(client, args):
    """kv_geosearchstore: the number of hits stored at the
    destination (cinder answers an integer then, not a member
    list)."""
    return client.command(*_op_argv("kv_geosearchstore", args))


def _call_georadius(client, args, name):
    """kv_georadius / kv_georadiusbymember (and the _ro read-only
    variants): the members inside the circle, or the number stored
    when STORE / STOREDIST was given (cinder answers an integer
    then, not a member list). The _ro variants never store —
    _georadius_args rejects store / storedist for them — so they
    always return the shaped member list."""
    read_only = name.endswith("_ro")
    _key, _centre, _radius, _unit, options, store = _georadius_args(
        args, name,
        name in ("kv_georadiusbymember", "kv_georadiusbymember_ro"),
        read_only=read_only)
    reply = client.command(*_op_argv(name, args))
    if store is not None:
        return reply
    return _geosearch_result(reply, options, name)


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


# The most keys one kv_zunionstore / kv_zinterstore / kv_zdiffstore
# call reads; a wider call fails instead of sending a half-formed
# STORE command with a huge argv.
MAX_ZSTORE_KEYS = 1000


def _zstore_args(args, name, with_options):
    """Validate a kv_zunionstore / kv_zinterstore / kv_zdiffstore
    call: (destination, keys, weights, aggregate). `destination`
    must be a string and `keys` a non-empty list of string key
    names, at most MAX_ZSTORE_KEYS; `weights`, when given, must be
    a list of numbers, one per key (NaN is rejected — cinder
    rejects it too); `aggregate`, when given, must be "sum", "min"
    or "max" (any case). Anything else fails the call instead of
    sending a half-formed STORE command. Weights and aggregate
    default to None, meaning the tool sends neither option and
    cinder weights every set by 1 and sums. kv_zdiffstore takes
    neither option — cinder's ZDIFFSTORE has none, the scores come
    from the first set — so passing either fails the call instead
    of being silently ignored."""
    destination = _require(args, "destination")
    if not isinstance(destination, str):
        raise ValueError("%s destination must be a string" % name)
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("%s keys must be a non-empty list" % name)
    if len(keys) > MAX_ZSTORE_KEYS:
        raise ValueError(
            "%s reads at most %d keys; narrow the list"
            % (name, MAX_ZSTORE_KEYS)
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError("%s keys must be strings" % name)
    weights = args.get("weights")
    if weights is not None:
        if not isinstance(weights, list):
            raise ValueError("%s weights must be a list" % name)
        if len(weights) != len(keys):
            raise ValueError(
                "%s weights must have one weight per key" % name
            )
        for weight in weights:
            if isinstance(weight, bool) or not isinstance(
                    weight, (int, float)):
                raise ValueError(
                    "%s weights must be numbers" % name)
            if isinstance(weight, float) and weight != weight:
                raise ValueError(
                    "%s weights must not be NaN" % name)
    aggregate = args.get("aggregate")
    if aggregate is not None:
        if not isinstance(aggregate, str):
            raise ValueError("%s aggregate must be a string" % name)
        if aggregate.lower() not in ZINTER_AGGREGATES:
            raise ValueError(
                "%s aggregate must be sum, min or max" % name)
    if not with_options and (weights is not None
                             or aggregate is not None):
        raise ValueError(
            "%s takes no weights or aggregate: cinder's ZDIFFSTORE "
            "has no options" % name
        )
    return destination, list(keys), weights, aggregate


def _call_zunionstore(client, args):
    """kv_zunionstore: store the union of several sorted sets at
    the destination and return the number of members stored
    (cinder answers an integer, not a member list). The destination
    is overwritten whatever it held and its TTL is cleared, an
    empty result deletes it instead, and it may itself be one of
    the inputs, since the union is computed before it is touched.
    The call writes, so the audit treats it as a write op."""
    return client.command(*_op_argv("kv_zunionstore", args))


def _call_zinterstore(client, args):
    """kv_zinterstore: store the intersection of several sorted
    sets at the destination and return the number of members
    stored (cinder answers an integer, not a member list). The
    destination is overwritten whatever it held and its TTL is
    cleared, an empty result deletes it instead, and it may
    itself be one of the inputs, since the intersection is
    computed before it is touched. The call writes, so the audit
    treats it as a write op."""
    return client.command(*_op_argv("kv_zinterstore", args))


def _call_zdiffstore(client, args):
    """kv_zdiffstore: store the difference of several sorted sets
    at the destination and return the number of members stored
    (cinder answers an integer, not a member list). The
    destination is overwritten whatever it held and its TTL is
    cleared, an empty result deletes it instead, and it may
    itself be one of the inputs, since the difference is computed
    before it is touched. The call writes, so the audit treats it
    as a write op."""
    return client.command(*_op_argv("kv_zdiffstore", args))


# The most keys one kv_pfcount call reads; a wider call fails
# instead of sending a half-formed PFCOUNT with a huge argv.
MAX_PFCOUNT_KEYS = 1000

# The most sources one kv_pfmerge call merges; a wider call fails
# instead of sending a half-formed PFMERGE with a huge argv.
MAX_PFMERGE_SOURCES = 1000


def _pfadd_args(args):
    """Validate a kv_pfadd call: (key, elements). `key` must be a
    string and `elements` a non-empty list of strings; anything
    else fails the call instead of sending a half-formed PFADD.
    There is no cap on the elements, as with kv_sadd: the reply
    is one integer either way, so a long element list costs
    cinder one pass and the caller one number."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_pfadd key must be a string")
    elements = args.get("elements")
    if not isinstance(elements, list) or not elements:
        raise ValueError("kv_pfadd elements must be a non-empty list")
    for element in elements:
        if not isinstance(element, str):
            raise ValueError("kv_pfadd elements must be strings")
    return key, list(elements)


def _pfcount_keys_args(args):
    """Validate a kv_pfcount call: the key names, as an argv list.
    `keys` must be a non-empty list of strings, at most
    MAX_PFCOUNT_KEYS; anything else fails the call instead of
    sending a half-formed PFCOUNT."""
    keys = args.get("keys")
    if not isinstance(keys, list) or not keys:
        raise ValueError("kv_pfcount keys must be a non-empty list")
    if len(keys) > MAX_PFCOUNT_KEYS:
        raise ValueError(
            "kv_pfcount reads at most %d keys; narrow the list"
            % MAX_PFCOUNT_KEYS
        )
    for key in keys:
        if not isinstance(key, str):
            raise ValueError("kv_pfcount keys must be strings")
    return list(keys)


def _pfmerge_args(args):
    """Validate a kv_pfmerge call: (destination, sources).
    `destination` must be a string and `sources` a non-empty list
    of strings, at most MAX_PFMERGE_SOURCES; anything else fails
    the call instead of sending a half-formed PFMERGE."""
    destination = _require(args, "destination")
    if not isinstance(destination, str):
        raise ValueError("kv_pfmerge destination must be a string")
    sources = args.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("kv_pfmerge sources must be a non-empty list")
    if len(sources) > MAX_PFMERGE_SOURCES:
        raise ValueError(
            "kv_pfmerge merges at most %d sources; narrow the list"
            % MAX_PFMERGE_SOURCES
        )
    for source in sources:
        if not isinstance(source, str):
            raise ValueError("kv_pfmerge sources must be strings")
    return destination, list(sources)


# Longitude and latitude bounds for GEOADD, as in Redis: longitude
# is -180 to 180, latitude -85.05112878 to 85.05112878 — the
# Mercator limit, not -90 to 90.
GEO_LON_MIN = -180.0
GEO_LON_MAX = 180.0
GEO_LAT_MIN = -85.05112878
GEO_LAT_MAX = 85.05112878

# The units kv_geodist accepts, as in Redis.
GEO_UNITS = ("m", "km", "ft", "mi")

# The most members one kv_geopos / kv_geohash call reads; a wider
# call fails instead of sending a half-formed GEOPOS with a huge
# argv.
MAX_GEO_MEMBERS = 1000


def _geo_coordinate(value, name, tool="kv_geoadd"):
    """One GEOADD coordinate as a number: finite, in range, and not
    a boolean (True is an int in Python, but it is not a
    coordinate). Anything else fails the call instead of sending a
    half-formed GEOADD. The same ranges bound the FROMLONLAT /
    GEORADIUS centre coordinates, so the search tools pass their
    own name for the error message."""
    low, high = (GEO_LON_MIN, GEO_LON_MAX) if name == "longitude" \
        else (GEO_LAT_MIN, GEO_LAT_MAX)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("%s %s must be a number" % (tool, name))
    if not math.isfinite(value):
        raise ValueError("%s %s must be finite" % (tool, name))
    if value < low or value > high:
        raise ValueError(
            "%s %s must be between %s and %s, got %r"
            % (tool, name, low, high, value)
        )
    return value


def _geoadd_options(args):
    """The GEOADD option flags for a kv_geoadd call, as argv tokens
    in cinder's order (NX | XX | CH, after the key and before the
    first longitude). Each flag must be a boolean when present. NX
    and XX are mutually exclusive, as in Redis, and fail here as
    invalid params instead of as a server error. CH only changes
    what the reply counts, so it composes with either."""
    opts = []
    nx = args.get("nx", False)
    xx = args.get("xx", False)
    ch = args.get("ch", False)
    for name, value in (("nx", nx), ("xx", xx), ("ch", ch)):
        if not isinstance(value, bool):
            raise ValueError(
                "kv_geoadd %s must be true or false" % name)
    if nx and xx:
        raise ValueError("kv_geoadd nx and xx cannot be used together")
    if nx:
        opts.append("NX")
    if xx:
        opts.append("XX")
    if ch:
        opts.append("CH")
    return opts


def _geoadd_args(args):
    """Validate a kv_geoadd call: (key, [(member, lon, lat), ...]).
    `members` must be a non-empty object mapping member names to
    [longitude, latitude] pairs; anything else fails the call
    instead of sending a half-formed GEOADD. The triples come back
    in the object's order, which is the order cinder adds them —
    and cinder checks every coordinate before applying any of
    them, so a bad one fails the whole call with nothing written."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_geoadd key must be a string")
    members = args.get("members")
    if not isinstance(members, dict) or not members:
        raise ValueError("kv_geoadd members must be a non-empty object")
    triples = []
    for member, pair in members.items():
        if not isinstance(member, str):
            raise ValueError("kv_geoadd members must be strings")
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError(
                "kv_geoadd member %r must be a [longitude, latitude] "
                "pair" % (member,)
            )
        longitude = _geo_coordinate(pair[0], "longitude")
        latitude = _geo_coordinate(pair[1], "latitude")
        triples.append((member, longitude, latitude))
    return key, triples


def _geodist_args(args):
    """Validate a kv_geodist call: (key, member1, member2, unit).
    `unit` defaults to "m" and must be one of "m", "km", "ft",
    "mi" in any case; anything else fails the call instead of
    sending a half-formed GEODIST."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("kv_geodist key must be a string")
    member1 = _require(args, "member1")
    if not isinstance(member1, str):
        raise ValueError("kv_geodist member1 must be a string")
    member2 = _require(args, "member2")
    if not isinstance(member2, str):
        raise ValueError("kv_geodist member2 must be a string")
    unit = args.get("unit", "m")
    if not isinstance(unit, str) or unit.lower() not in GEO_UNITS:
        raise ValueError(
            "kv_geodist unit must be one of %s, got %r"
            % (", ".join(GEO_UNITS), unit)
        )
    return key, member1, member2, unit.lower()


def _geo_members_args(args, name):
    """Validate a kv_geopos / kv_geohash call: the member names.
    `members` must be a non-empty list of strings, at most
    MAX_GEO_MEMBERS; anything else fails the call instead of
    sending a half-formed GEOPOS or GEOHASH."""
    members = args.get("members")
    if not isinstance(members, list) or not members:
        raise ValueError("%s members must be a non-empty list" % name)
    if len(members) > MAX_GEO_MEMBERS:
        raise ValueError(
            "%s reads at most %d members; narrow the list"
            % (name, MAX_GEO_MEMBERS)
        )
    for member in members:
        if not isinstance(member, str):
            raise ValueError("%s members must be strings" % name)
    return list(members)


# The most members one kv_geosearch / kv_georadius /
# kv_georadiusbymember call returns; a wider search fails instead
# of returning a truncated list, as the other range tools do.
MAX_GEOSEARCH_MEMBERS = 1000


def _geo_search_number(value, name, tool):
    """One GEOSEARCH / GEORADIUS radius, width or height: a finite
    number, 0 or more, and not a boolean. Cinder accepts 0 (an
    empty shape) and rejects a negative one, so the tool does the
    same instead of sending a half-formed search."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("%s %s must be a number" % (tool, name))
    if not math.isfinite(value):
        raise ValueError("%s %s must be finite" % (tool, name))
    if value < 0:
        raise ValueError(
            "%s %s must be 0 or more, got %r" % (tool, name, value))
    return value


def _geo_search_unit(args, tool):
    """The unit of a geo search shape: "m" by default, one of "m",
    "km", "ft", "mi" in any case; anything else fails the call
    instead of sending a half-formed search."""
    unit = args.get("unit", "m")
    if not isinstance(unit, str) or unit.lower() not in GEO_UNITS:
        raise ValueError(
            "%s unit must be one of %s, got %r"
            % (tool, ", ".join(GEO_UNITS), unit)
        )
    return unit.lower()


def _geo_search_options(args, tool):
    """The options shared by the three geo search tools: sort,
    count, any, withdist, withhash, withcoord. Returns (sort_desc,
    count, count_any, withdist, withhash, withcoord). `sort`
    defaults to "asc"; `count` is a non-negative integer at most
    MAX_GEOSEARCH_MEMBERS, and `any` needs a count."""
    sort = args.get("sort", "asc")
    if not isinstance(sort, str) or sort.lower() not in ("asc", "desc"):
        raise ValueError(
            "%s sort must be \"asc\" or \"desc\", got %r" % (tool, sort))
    count = args.get("count")
    if count is not None:
        if isinstance(count, bool) or not isinstance(count, int):
            raise ValueError("%s count must be an integer" % tool)
        if count < 0:
            raise ValueError(
                "%s count must be 0 or more, got %r" % (tool, count))
        if count > MAX_GEOSEARCH_MEMBERS:
            raise ValueError(
                "%s returns at most %d members; narrow the count"
                % (tool, MAX_GEOSEARCH_MEMBERS))
    any_ = args.get("any", False)
    if not isinstance(any_, bool):
        raise ValueError("%s any must be true or false" % tool)
    if any_ and count is None:
        raise ValueError("%s any needs a count" % tool)
    flags = []
    for flag in ("withdist", "withhash", "withcoord"):
        value = args.get(flag, False)
        if not isinstance(value, bool):
            raise ValueError(
                "%s %s must be true or false" % (tool, flag))
        flags.append(value)
    return (sort.lower() == "desc", count, any_,
            flags[0], flags[1], flags[2])


def _geo_search_option_argv(sort_desc, count, count_any,
                            withdist, withhash, withcoord):
    """The trailing options of a geo search command, in the order
    cinder documents them: the sort, then COUNT [ANY], then the
    WITH* flags."""
    cmd = ["DESC" if sort_desc else "ASC"]
    if count is not None:
        cmd += ["COUNT", count]
        if count_any:
            cmd.append("ANY")
    if withdist:
        cmd.append("WITHDIST")
    if withhash:
        cmd.append("WITHHASH")
    if withcoord:
        cmd.append("WITHCOORD")
    return cmd


def _geosearch_args(args, tool="kv_geosearch"):
    """Validate a kv_geosearch / kv_geosearchstore call: (key,
    centre, shape, options). The centre is ("member", name) for
    FROMMEMBER or ("lonlat", lon, lat) for FROMLONLAT; the shape
    is ("radius", radius, unit) for BYRADIUS or ("box", width,
    height, unit) for BYBOX. Exactly one centre and exactly one
    shape; anything else fails the call instead of sending a
    half-formed GEOSEARCH. `tool` names the caller, so the error
    messages name the tool that was actually called."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("%s key must be a string" % tool)
    member = args.get("member")
    has_lonlat = "longitude" in args or "latitude" in args
    if member is not None and has_lonlat:
        raise ValueError(
            "%s takes either member or longitude/latitude, "
            "not both" % tool)
    if member is None and not has_lonlat:
        raise ValueError(
            "%s needs a centre: member or "
            "longitude/latitude" % tool)
    if member is not None:
        if not isinstance(member, str):
            raise ValueError("%s member must be a string" % tool)
        centre = ("member", member)
    else:
        if "longitude" not in args or "latitude" not in args:
            raise ValueError(
                "%s needs both longitude and latitude" % tool)
        centre = ("lonlat",
                  _geo_coordinate(args["longitude"], "longitude", tool),
                  _geo_coordinate(args["latitude"], "latitude", tool))
    radius = args.get("radius")
    has_box = "width" in args or "height" in args
    if radius is not None and has_box:
        raise ValueError(
            "%s takes either radius or width/height, "
            "not both" % tool)
    if radius is None and not has_box:
        raise ValueError(
            "%s needs a shape: radius or width/height" % tool)
    unit = _geo_search_unit(args, tool)
    if radius is not None:
        shape = ("radius",
                 _geo_search_number(radius, "radius", tool), unit)
    else:
        if "width" not in args or "height" not in args:
            raise ValueError(
                "%s needs both width and height" % tool)
        shape = ("box",
                 _geo_search_number(args["width"], "width", tool),
                 _geo_search_number(args["height"], "height", tool),
                 unit)
    return key, centre, shape, _geo_search_options(args, tool)


def _geosearchstore_args(args):
    """Validate a kv_geosearchstore call: (destination, key,
    centre, shape, options, storedist). The centre and the shape
    validate exactly like kv_geosearch's — the same FROMMEMBER /
    FROMLONLAT centre and BYRADIUS / BYBOX shape — and the
    destination is required: GEOSEARCHSTORE always stores its
    hits. `storedist` stores the distances in the shape's unit as
    scores instead of the geohash scores. The WITH* options are
    for returning the hits, so they are rejected here before
    anything is sent — cinder rejects them too."""
    tool = "kv_geosearchstore"
    destination = _require(args, "destination")
    if not isinstance(destination, str):
        raise ValueError(
            "%s destination must be a string" % tool)
    storedist = args.get("storedist", False)
    if not isinstance(storedist, bool):
        raise ValueError(
            "%s storedist must be true or false" % tool)
    key, centre, shape, options = _geosearch_args(args, tool)
    _sort_desc, _count, _any, withdist, withhash, withcoord = options
    if withdist or withhash or withcoord:
        raise ValueError(
            "%s cannot be combined with withdist, withhash or "
            "withcoord: GEOSEARCHSTORE stores its hits instead of "
            "returning them" % tool)
    return destination, key, centre, shape, options, storedist


def _georadius_args(args, tool, by_member, read_only=False):
    """Validate a kv_georadius / kv_georadiusbymember call: (key,
    centre, radius, unit, options, store). The centre is
    ("lonlat", lon, lat) for GEORADIUS and ("member", name) for
    GEORADIUSBYMEMBER; store is ("store", key), ("storedist",
    key) or None. The two store forms are mutually exclusive, and
    neither combines with the WITH* options — cinder rejects that
    combination, so the tool does too, before anything is sent.
    With read_only (the kv_georadius_ro / kv_georadiusbymember_ro
    tools), a store or storedist argument is rejected outright —
    cinder refuses STORE / STOREDIST on GEORADIUS_RO /
    GEORADIUSBYMEMBER_RO — so store is always None then."""
    key = _require(args, "key")
    if not isinstance(key, str):
        raise ValueError("%s key must be a string" % tool)
    if by_member:
        member = _require(args, "member")
        if not isinstance(member, str):
            raise ValueError("%s member must be a string" % tool)
        centre = ("member", member)
    else:
        if "longitude" not in args or "latitude" not in args:
            raise ValueError(
                "%s needs both longitude and latitude" % tool)
        centre = ("lonlat",
                  _geo_coordinate(args["longitude"], "longitude", tool),
                  _geo_coordinate(args["latitude"], "latitude", tool))
    if "radius" not in args:
        raise ValueError("%s needs a radius" % tool)
    radius = _geo_search_number(args["radius"], "radius", tool)
    unit = _geo_search_unit(args, tool)
    options = _geo_search_options(args, tool)
    _sort_desc, _count, _any, withdist, withhash, withcoord = options
    store = args.get("store")
    storedist = args.get("storedist")
    if read_only and (store is not None or storedist is not None):
        raise ValueError(
            "%s does not take store or storedist: STORE and "
            "STOREDIST are not compatible with the read-only "
            "variant" % tool)
    if store is not None and storedist is not None:
        raise ValueError(
            "%s takes either store or storedist, not both" % tool)
    dest = store if store is not None else storedist
    if dest is None:
        return key, centre, radius, unit, options, None
    if not isinstance(dest, str):
        raise ValueError("%s store must be a string" % tool)
    if withdist or withhash or withcoord:
        raise ValueError(
            "%s store cannot be combined with withdist, withhash "
            "or withcoord" % tool)
    return (key, centre, radius, unit, options,
            ("store" if store is not None else "storedist", dest))


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


def _call_zrevrange(client, args):
    """kv_zrevrange: the same as kv_zrange with rev, as its own
    tool — bound the range first, then run ZREVRANGE and shape
    the reply."""
    _check_zrange_window(client, args, "kv_zrevrange")
    return _zrange_result(
        client.command(*_op_argv("kv_zrevrange", args)) or [],
        _zrevrange_args(args)[3],
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


def _zrangebyscore_args(args, tool="kv_zrangebyscore"):
    """Validate a kv_zrangebyscore call: (key, min, max, withscores,
    rev, offset, count). min defaults to -inf and max to +inf, as in
    Redis; offset defaults to 0 and count to -1, meaning all matches
    from the offset. count is at most MAX_ZRANGE_MEMBERS, and an
    offset below 0 or a count below -1 fails the call instead of
    sending a half-formed ZRANGEBYSCORE. `tool` names the tool in
    the error messages, so kv_zrevrangebyscore shares this
    validator."""
    key = _require(args, "key")
    min_b = _format_score_bound(args.get("min", "-inf"), tool)
    max_b = _format_score_bound(args.get("max", "+inf"), tool)
    withscores = args.get("withscores", False)
    if not isinstance(withscores, bool):
        raise ValueError("%s withscores must be true or false" % tool)
    rev = args.get("rev", False)
    if not isinstance(rev, bool):
        raise ValueError("%s rev must be true or false" % tool)
    offset = args.get("offset", 0)
    if isinstance(offset, bool) or not isinstance(offset, int):
        raise ValueError("%s offset must be an integer" % tool)
    if offset < 0:
        raise ValueError("%s offset must be 0 or more" % tool)
    count = args.get("count", -1)
    if isinstance(count, bool) or not isinstance(count, int):
        raise ValueError("%s count must be an integer" % tool)
    if count < -1:
        raise ValueError("%s count must be -1 or more" % tool)
    if count > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "%s returns at most %d members; narrow the "
            "range or pass a smaller count" % (tool, MAX_ZRANGE_MEMBERS)
        )
    return key, min_b, max_b, withscores, rev, offset, count


def _zrevrangebyscore_args(args):
    """Validate a kv_zrevrangebyscore call: (key, min, max,
    withscores, offset, count). The same bounds as
    kv_zrangebyscore, without rev — the tool always reads highest
    score first, and the bounds are still given min then max. A
    stray rev argument is read and checked like any other, then
    ignored, as with any extra argument this server does not use."""
    key, min_b, max_b, withscores, _rev, offset, count = \
        _zrangebyscore_args(args, "kv_zrevrangebyscore")
    return key, min_b, max_b, withscores, offset, count


def _zrangebyscore_result(flat, withscores, tool="kv_zrangebyscore"):
    """Shape a flat ZRANGEBYSCORE reply into the tool's return value,
    like _zrange_result, and fail when the probe asked for one extra
    member and got it — the range holds more than MAX_ZRANGE_MEMBERS
    members, so the caller must narrow it or pass a limit instead of
    getting a silently truncated list. `tool` names the tool in the
    error message, so kv_zrevrangebyscore shares this shaper."""
    members = _zrange_result(flat, withscores)
    if len(members) > MAX_ZRANGE_MEMBERS:
        raise ValueError(
            "%s returns at most %d members; narrow the "
            "range or pass a limit" % (tool, MAX_ZRANGE_MEMBERS)
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


def _call_zrevrangebyscore(client, args):
    """kv_zrevrangebyscore: the same as kv_zrangebyscore with rev,
    as its own tool — run ZREVRANGEBYSCORE and shape the reply.
    The argv always carries a LIMIT (see _op_argv), so a range
    wider than the cap is caught from the reply."""
    return _zrangebyscore_result(
        client.command(*_op_argv("kv_zrevrangebyscore", args)) or [],
        _zrevrangebyscore_args(args)[3],
        "kv_zrevrangebyscore",
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
    if name == "kv_xrange":
        return _call_xrange(client, args)
    if name == "kv_xrevrange":
        return _call_xrevrange(client, args)
    if name == "kv_xread":
        return _call_xread(client, args)
    if name == "kv_xreadgroup":
        return _call_xreadgroup(client, args)
    if name == "kv_xpending":
        return _call_xpending(client, args)
    if name == "kv_xgroup_create":
        return _call_xgroup_create(client, args)
    if name == "kv_xack":
        return _call_xack(client, args)
    if name == "kv_xclaim":
        return _call_xclaim(client, args)
    if name == "kv_xgroup_setid":
        return _call_xgroup_setid(client, args)
    if name == "kv_xgroup_destroy":
        return _call_xgroup_destroy(client, args)
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
    if name == "kv_zunionstore":
        return _call_zunionstore(client, args)
    if name == "kv_zinterstore":
        return _call_zinterstore(client, args)
    if name == "kv_zdiffstore":
        return _call_zdiffstore(client, args)
    if name == "kv_zincrby":
        return _call_zincrby(client, args)
    if name == "kv_zrange":
        return _call_zrange(client, args)
    if name == "kv_zrevrange":
        return _call_zrevrange(client, args)
    if name == "kv_zrangebyscore":
        return _call_zrangebyscore(client, args)
    if name == "kv_zrevrangebyscore":
        return _call_zrevrangebyscore(client, args)
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
    if name == "kv_geodist":
        return _call_geodist(client, args)
    if name == "kv_geopos":
        return _call_geopos(client, args)
    if name == "kv_geohash":
        return _call_geohash(client, args)
    if name == "kv_geosearch":
        return _call_geosearch(client, args)
    if name == "kv_geosearchstore":
        return _call_geosearchstore(client, args)
    if name in ("kv_georadius", "kv_georadiusbymember",
                "kv_georadius_ro", "kv_georadiusbymember_ro"):
        return _call_georadius(client, args, name)
    return client.command(*_op_argv(name, args))
