# cinder-mcp

An MCP (Model Context Protocol) server that exposes
[cinder](https://github.com/muhammadrashid4587/cinder) — a Redis-compatible
key-value store in C — as tools for AI agents.

## What it is

A bridge. It speaks MCP (JSON-RPC 2.0 over stdio) on one side and cinder's
RESP protocol over a plain socket on the other, so an agent that can call
MCP tools can read and write a cinder instance. Pure Python 3 standard
library, zero dependencies.

## What it is not

It is not a database. It stores nothing itself. It requires a running
cinder instance, and if cinder is not reachable every tool call fails
with a clean JSON-RPC error instead of silently returning nothing.

## Setup

```sh
# 1. Start cinder (from the cinder repo, default port 6379)
./cinder --port 6379 --data-dir ./data

# 2. Run this server (it connects to cinder on 127.0.0.1:6379 by default)
python3 -m cinder_mcp.server

# Or point it elsewhere:
CINDER_HOST=127.0.0.1 CINDER_PORT=6380 python3 -m cinder_mcp.server
```

Wire it into an MCP client as a stdio server with the command
`python3 -m cinder_mcp.server` and the working directory set to this repo.

## Latency budgets

Every tool has a latency budget: a warn threshold and a slow threshold
in milliseconds. Defaults are 100ms warn / 500ms slow; override them
with environment variables:

```sh
CINDER_MCP_WARN_MS=50 CINDER_MCP_SLOW_MS=200 python3 -m cinder_mcp.server

# Per-tool overrides as JSON (partial overrides inherit the defaults):
CINDER_MCP_BUDGETS='{"kv_keys": {"warn_ms": 250, "slow_ms": 1000}}' python3 -m cinder_mcp.server
```

A tool whose p95 latency is over its warn threshold is flagged `warn`
in `cinder://metrics`; over its slow threshold it is `slow`. The
metrics resource also counts, per tool, how many individual samples
crossed each threshold, and `cinder://info` ends with a summary line
listing the tools currently over each threshold. A misconfigured
budget (non-numeric, non-positive, or slow at or below warn) fails
the server at startup instead of running with nonsense thresholds.

Each tool's budget is also advertised up front: `tools/list` appends
"Latency budget: warn >100ms, slow >500ms." (or the tool's override
values) to the tool's description, so a client knows the budget
before calling.

A single call that crosses its own budget is also flagged inline, in
the moment: the `tools/call` result carries a `warning` field with
the level (`warn` or `slow`), the tool, the measured latency and the
threshold it crossed, so the client sees it without polling
`cinder://metrics`. Calls within budget carry no `warning` field.

## Tools

| Tool | Cinder command | Notes |
| --- | --- | --- |
| `kv_get` | `GET key` | Returns `null` when the key is missing |
| `kv_set` | `SET key value [EX s \| PX ms]` | Optional `ex` / `px` TTL |
| `kv_del` | `DEL key` | 1 if the key existed, 0 otherwise |
| `kv_keys` | `KEYS pattern` | Glob `*` and `?`, defaults to `*`. Returns `{"keys": [...], "total": n, "returned": m, "sampled": bool}`: at most `limit` keys (default 100); a larger keyspace returns a deterministic sample seeded by `seed`, and `full: true` returns the whole list |
| `kv_keys_scan` | `SCAN cursor [MATCH pattern] [COUNT n]` | Walk the matching keys one bounded page at a time with cinder's real `SCAN`. Returns `{"keys": [...], "cursor": str, "done": bool, "batch_size": n}`: about `batch_size` keys per page (default 100, max 1000) — `COUNT` is a hint, so a page can run a few keys over when several matches share one hash bucket. Pass the returned `cursor` back for the next page; `""` starts over. When `done` is true the cursor is `""` and the walk is finished. The cursor is opaque: pass it back verbatim. Pages are in `SCAN` order, not sorted; keys added after the cursor are picked up later, keys deleted or renamed between pages can shift the window, and a key can come back twice if the table resizes mid-walk — the same caveats real `SCAN` has |
| `kv_incr` | `INCR key` / `INCRBY key n` | `by` defaults to 1 |
| `kv_ttl` | `TTL key` | -1 = no expiry, -2 = missing key |
| `kv_exists` | `EXISTS key` | 1 if the key exists, 0 otherwise |
| `kv_expire` | `EXPIRE key seconds` | 1 if the timeout was set, 0 if the key is missing |
| `kv_hset` | `HSET key field value [field value ...]` | `fields` is an object of field names to values; returns the number of fields newly added (updating an existing field counts 0) |
| `kv_hget` | `HGET key field` | Returns `null` when the key or the field is missing |
| `kv_hgetall` | `HGETALL key` | Every field as an object of field names to values; `{}` when the key is missing |
| `kv_zadd` | `ZADD key [NX \| XX \| GT \| LT \| CH \| INCR] score member [score member ...]` | `members` is an object of member names to scores; returns the number of members newly added (updating an existing member's score counts 0), or with `ch: true` the number added or updated. `nx` adds only new members, `xx` updates only existing ones, `gt` only moves a score up, `lt` only moves it down; `nx` cannot combine with `xx`, `gt` or `lt`, and `gt` cannot combine with `lt`. With `incr: true` exactly one member is given and the call returns that member's new score as a number, or `null` when the conditions rejected the update |
| `kv_zrange` | `ZRANGE key start stop [WITHSCORES]` / `ZREVRANGE` | Members in index order, lowest score first; negative indices count from the end. `withscores: true` returns `[{"member": ..., "score": ...}]` instead of plain names; `rev: true` reads highest score first. At most 1000 members per call |
| `kv_zrangebyscore` | `ZRANGEBYSCORE key min max [WITHSCORES] [LIMIT offset count]` / `ZREVRANGEBYSCORE` | Members whose scores fall in the range, lowest score first. `min` / `max` are numbers or strings like `"5"`, `"(5"` for an exclusive bound, `"-inf"` / `"+inf"`; they default to `-inf` / `+inf`. `withscores: true` returns `[{"member": ..., "score": ...}]`; `rev: true` reads highest score first. `offset` / `count` page through the matches (count defaults to all). At most 1000 members per call |
| `kv_zcount` | `ZRANGEBYSCORE key min max [LIMIT 0 1001]` | The number of members whose scores fall in the range. Cinder has no `ZCOUNT`, so this counts by fetching the range and counting the members — the count is honest, not a server-side count. `min` / `max` parse like `kv_zrangebyscore`'s (numbers or strings, `"("` for exclusive, `"-inf"` / `"+inf"`, defaulting to `-inf` / `+inf`). At most 1000 members per call: a wider range fails instead of returning a truncated count |
| `kv_zcard` | `ZCARD key` | The number of members in the sorted set; 0 when the key does not exist |
| `kv_zscore` | `ZSCORE key member` | The member's score as a number; `null` when the key or the member does not exist |
| `kv_zrank` | `ZRANK key member` | The member's rank, lowest score first; `null` when the key or the member does not exist |
| `kv_zrevrank` | `ZRANK key member` + `ZCARD key` | The member's rank, highest score first: `ZCARD - 1 - ZRANK`. Cinder has no `ZREVRANK`, so this reads both and combines them; `null` when the key or the member does not exist |
| `kv_zrem` | `ZREM key member [member ...]` | `members` is a list of member names; returns the number of members actually removed |
| `kv_zincrby` | `ZINCRBY key increment member` | Adds to a member's score, creating the member with the increment as its score when it is not already present; returns the new score as a number |
| `kv_batch` | several kv ops in one call | Runs the `ops` list in order and returns one summary: per-op result or error plus `ok` / `failed` counts. A failed op is recorded and the batch keeps going; at most 100 ops. Pass `atomic: true` to run the ops as one `MULTI`/`EXEC` transaction instead, with no other client interleaved; an op that cannot be queued (unknown name, `kv_keys_scan`, a missing argument) fails the whole call before anything runs |

## Atomic batches

`kv_batch` takes an `atomic` flag (default `false`). With
`atomic: true` the ops run as one `MULTI`/`EXEC` transaction on a
single connection to cinder, so they execute together with no other
client interleaved — a `kv_set` followed by a `kv_incr` on the same
key is one indivisible step. The summary carries `"atomic": true`.

Two honest limits. First, only the single-command ops can be
queued: `kv_keys_scan` cannot run inside a transaction, because its
cursor walk needs one `SCAN` call per page, which cannot happen
inside a transaction. Second, queue-time and
EXEC-time failures behave differently, as in real Redis: an op that
cannot be queued at all (unknown name, `kv_keys_scan`, a missing
required argument, a bad `kv_keys` limit) fails the whole call
before anything runs, while an op that fails at EXEC time (an
`INCR` on a non-integer, an `EXPIRE` with a bad time) is recorded
in place as that op's error and the rest still run. `kv_keys`
inside an atomic batch returns the same sampled shape as the
standalone tool.

## Resources

| URI | Cinder command | Notes |
| --- | --- | --- |
| `cinder://info` | `INFO` | Server version, uptime, commands processed, key count, plus this server's per-tool latency metrics for the current session and a summary of which tools are over their latency budgets |
| `cinder://metrics` | — | Per-tool call counts, error counts and mean/p50/p95 latency in milliseconds for this server session, as JSON, with each tool's warn/slow latency budget, its warn/slow/ok status, per-threshold breach counts, and a `budget_breaches` summary. Metrics are recorded in memory by the server itself (every `tools/call`, success or failure); nothing is stored in cinder. |
| `cinder://changes` | `KEYS` + per-key value fingerprints | Keys added, changed or removed since a checkpoint, as JSON, so an agent can poll for what moved instead of re-listing the whole keyspace. The first read reports every current key as added and returns a `checkpoint`; poll again as `cinder://changes?since=<checkpoint>` for only the delta. Checkpoints older than the last 16 reads are forgotten (re-read without `since` to re-baseline). A key whose TTL changed but whose value did not is not reported as changed. |
| `cinder://key/<key>` | `EXISTS` + `GET` / `LLEN` / `SCARD` / `HLEN` | Value and type as JSON; not-found error for missing keys. Non-string values report their type and length instead of a value (cinder has no `TYPE` command, so the type is probed) |

Fetchable with `resources/list` and `resources/read`.

## Prompts

| Prompt | Arguments | Notes |
| --- | --- | --- |
| `keyspace-summary` | `pattern` (optional, defaults to `*`) | Samples `INFO`, lists the keys matching the pattern, and asks the model to summarize the keyspace and suggest what to check next: keys worth reading, TTLs worth checking, and keys that look stale |
| `key-deep-dive` | `key` (required) | Inspects one key in detail — type, TTL, size, a sample of its value (truncated at 200 chars), and the keys sharing its namespace — and asks the model to judge whether the key looks healthy |
| `ttl-audit` | `pattern` (optional, defaults to `*`) | Scans the keyspace in bounded batches of 100 keys, groups keys by TTL bucket (no expiry, expiring <1h, <1d, <1w, >1w), lists the soonest-expiring keys and the keys with no expiry, and asks the model to flag what the operator should act on. Only counts plus the 10 soonest keys and the first 20 no-expiry keys are kept, so the prompt stays bounded on a huge keyspace |
| `cleanup-plan` | `pattern` (optional, defaults to `*`) | Inspects the live keyspace in bounded batches of 100 keys (INFO, per-key TTL/type/size) and classifies every key as safe to delete (expires <1h), expiring soon (<1d), risky to delete without confirmation (no expiry), or keep (>1d), and asks the model to produce a concrete cleanup plan with exact `kv_del` calls — risky keys need a human to confirm each delete. Each section keeps only its first 20 keys plus a count of the rest, so the prompt stays bounded on a huge keyspace |
| `keyspace-health` | `pattern` (optional, defaults to `*`) | One-view health report: total keys, type breakdown, keys with no expiry, soonest-expiring keys, largest string keys (by bytes) and largest container keys (by element count), and a short list of recommended actions derived from the data. Scanned in bounded batches of 100 keys; each list keeps only its first 10 keys plus a count of the rest, so the prompt stays bounded on a huge keyspace |
| `write-safety` | `plan` (required) | Audits a proposed write plan against the live keyspace before anything runs: `plan` is a JSON array of kv_batch-shaped ops (at most 50 audited). Each write op is probed live and given a verdict — safe, caution, or risky — flagging overwrites of keys that never expire, overwrites of large keys, SETs that would destroy a list, set, or hash, INCRs that would fail on a non-integer or a container, and EXPIREs with a bad timeout, and asks for a go/no-go per risky op plus the exact safe subset as one kv_batch call. Read ops in the plan are not audited; values are never printed. One honest limit: cinder keeps no per-key access counts, so a hot key cannot be told from a cold one — the audit flags size, permanence, and type instead of hotness |
| `ttl-renewal` | `pattern` (optional, defaults to `*`), `keys` (optional, JSON array of exact key names, overrides `pattern`), `target_ttl` (optional, seconds, defaults to 86400), `max_keys` (optional, safety cap, defaults to 20, at most 100) | Plans TTL renewals: reads live TTLs, proposes one `kv_expire` renewal per key expiring sooner than the target TTL (soonest first) and a first expiry at the target TTL for keys with no expiry, flags keys already expired or missing and never proposes renewing them, and covers at most `max_keys` keys in total — the rest are counted as not covered. Values are never read or printed. One honest limit: renewals run as `kv_expire` (EXPIRE, whole seconds); there is no PEXPIRE tool, so sub-second precision is not available |
| `key-migration` | `pattern` (optional, defaults to `*`), `target_prefix` (required), `max_keys` (optional, safety cap, defaults to 20, at most 100) | Plans migrating keys to a new prefix: audits each key's type, size, and TTL, checks whether the target name already exists and with what type, and lays out the ordered copy steps with the exact `kv_del` call for each source key — ready keys (free target), overwrite keys (target exists, same type), conflicts (target exists, different type), keys that map onto themselves, and keys that expired mid-scan. Values are never read or printed. One honest limit: cinder has no RENAME or COPY, so a migration is a read plus a write, not one atomic move — the plan says to verify the target before deleting the source, and to re-check the TTL with `kv_ttl` just before copying since the audited TTL ticks down |

Fetchable with `prompts/list` and `prompts/get`.

## Demo

`scripts/demo.py` starts a real cinder on port 7777, runs the MCP server
against it, and issues `tools/call` requests over stdio:

```sh
python3 scripts/demo.py
```

## Tests

```sh
make test
```

The suite runs the MCP server against a fake RESP server on a socket:
handshake returns the tool list, a SET-then-GET round trip returns the
value, an unreachable cinder returns a clean JSON-RPC error, and malformed
requests return JSON-RPC errors.

## Streaming the keyspace

`ttl-audit`, `cleanup-plan`, `keyspace-health`, `ttl-renewal`, and
`key-migration` scan the keyspace in bounded batches
of 100 keys (`cinder_mcp/scan.py`), and `kv_keys_scan` exposes the
same walk as a paged tool. The per-key work and the prompt text stay
bounded: the prompts keep only counts plus the 10 soonest-expiring
keys, the first 20 no-expiry keys, and the first 20 keys per cleanup
section, with "... and N more" for the rest. The results are
identical to the old load-everything scan at any batch size — the
tests run the scanning prompts at batch sizes 1, 2, 7 and 100 over the same
keyspace and compare the full prompt text.

The scanner is backed by cinder's real `SCAN` command (cinder
0.26.0): `SCAN cursor [MATCH pattern] [COUNT n]` returns
`[cursor, keys]`, and the walk repeats with the returned cursor
until it comes back `0`. The tools and prompts did not change —
only `cinder_mcp/scan.py` did. Two honest details: `COUNT` is a
hint, so a page can run a few keys over `batch_size` when several
matches share one hash bucket, and real `SCAN` may return a key
twice if the table resizes mid-walk, so the prompt iterator
dedupes against a seen set while `kv_keys_scan` exposes the raw
paged walk, duplicates included. Pages are in `SCAN` order, not
sorted key order.

## Roadmap

- ~~Sampling the cinder INFO output as a `cinder://info` resource~~ (done, v0.3.0)
- ~~Resource (URI) support for reading keys as MCP resources (`cinder://key/<key>`)~~ (done, v0.4.0)
- ~~Prompt support (`prompts/list`, `prompts/get`)~~ (done, v0.5.0)
- ~~Per-key deep-dive prompt (`key-deep-dive`: type, TTL, size, sample value, related keys)~~ (done, v0.6.0)
- ~~TTL audit prompt (`ttl-audit`: TTL buckets, soonest-expiring keys, keys with no expiry)~~ (done, v0.7.0)
- ~~Cleanup-plan prompt (`cleanup-plan`: per-key TTL/type/size sampling, safe / expiring-soon / risky-confirm / keep classification, concrete plan with exact `kv_del` calls)~~ (done, v0.8.0)
- ~~Per-tool latency metrics (call count, mean/p50/p95 latency, error count in memory; exposed in `cinder://info` and as a `cinder://metrics` resource)~~ (done, v0.9.0)
- ~~Latency budgets: per-tool warn/slow thresholds on `cinder://metrics`, so a slow tool is flagged instead of just measured~~ (done, v0.10.0)
- ~~Slow-tool warning in `tools/call`: a `warning` field in the tool result when a call crosses its warn or slow latency budget, so the agent sees it in the moment instead of only in `cinder://metrics`~~ (done, v0.11.0)
- ~~Advertise budgets in `tools/list`: include each tool's warn/slow latency budget in its tool description, so clients know the budgets up front instead of discovering them from a warning~~ (done, v0.12.0)
- ~~Batch tool (`kv_batch`): run several kv ops in one call, in order, with a per-op result/error summary and ok/failed counts; a failed op is recorded and the batch keeps going; at most 100 ops; explicitly not atomic until cinder has MULTI~~ (done, v0.13.0)
- ~~Keyspace watch: a `cinder://changes` resource that reports keys changed since a checkpoint, so an agent can poll for what moved instead of re-listing the whole keyspace~~ (done, v0.14.0)
- ~~Sampling support for long key listings, so `kv_keys` over a huge keyspace returns a bounded deterministic sample (default cap 100 keys, `limit` / `seed` / `full` parameters) plus `total` / `returned` / `sampled` counts instead of every key~~ (done, v0.15.0)
- ~~Streaming the keyspace for prompts, so `ttl-audit` and `cleanup-plan` can scan a huge keyspace without loading every key into memory at once, plus a `kv_keys_scan` tool that walks the keyspace one bounded page at a time with a resume cursor~~ (done, v0.16.0)
- ~~Atomic batches: `kv_batch` with `atomic: true` runs the ops as one `MULTI`/`EXEC` transaction on a single connection, so they execute together with no other client interleaved; ops that fail at EXEC time are recorded in place while the rest still run, and ops that cannot be queued fail the whole call before anything runs~~ (done, v0.17.0)
- ~~Keyspace-health prompt (`keyspace-health`): one-view health report — total keys, type breakdown, keys without TTL, soonest-expiring keys, largest string keys by bytes and largest containers by element count, plus a short list of recommended actions derived from the data, all scanned in bounded batches~~ (done, v0.18.0)
- ~~Write-safety prompt (`write-safety`): audits a proposed write plan (a JSON list of kv_batch-shaped ops) against the live keyspace before it runs — overwrites of keys that never expire, overwrites of large keys, SETs that would destroy a container, INCRs that would fail, EXPIREs with a bad timeout — with a safe / caution / risky verdict per op and the exact safe subset as one kv_batch call; at most 50 ops audited, values never printed~~ (done, v0.19.0)
- ~~TTL renewal prompt (`ttl-renewal`): plans renewing the TTLs of keys expiring sooner than a configurable target TTL (default 1 day) and giving a first expiry to keys with no expiry — live TTLs, soonest first, keys already expired or missing flagged and never proposed for renewal, at most `max_keys` keys covered (default 20, at most 100), values never read or printed~~ (done, v0.20.0)
- ~~Key-migration prompt (`key-migration`): plans migrating keys matching a pattern to a new prefix — live type/size/TTL audit per key, target-name collision check (same-type overwrite vs different-type conflict vs maps-onto-itself), ordered copy steps with the exact `kv_del` call per source key, at most `max_keys` ready keys covered (default 20, at most 100), values never read or printed; honest limit stated in the prompt: cinder has no RENAME or COPY, so a migration is a read plus a write, not one atomic move~~ (done, v0.21.0)
- ~~Hash tools (`kv_hset`, `kv_hget`, `kv_hgetall`): expose cinder's HSET/HGET/HGETALL so agents can work with hashes — `kv_hset` takes a `fields` object and returns the number of newly added fields, `kv_hget` returns null for a missing key or field, `kv_hgetall` returns the whole hash as an object (`{}` when missing); all three are batchable, plain and atomic~~ (done, v0.22.0)
- ~~Sorted-set tools (`kv_zadd`, `kv_zrange`): expose cinder's ZADD/ZRANGE/ZREVRANGE so agents can work with leaderboards and ranked sets — `kv_zadd` takes a `members` object of member names to scores and returns the number of newly added members (plain form only: cinder 0.24.0 has no NX/XX/GT/LT/CH/INCR options), `kv_zrange` returns members in index order with optional `withscores` member/score objects and `rev` for highest-first, at most 1000 members per call; both are batchable, plain and atomic~~ (done, v0.23.0)
- ~~More sorted-set tools (`kv_zcard`, `kv_zscore`, `kv_zrank`, `kv_zrem`, `kv_zincrby`): expose cinder's ZCARD/ZSCORE/ZRANK/ZREM/ZINCRBY — `kv_zcard` counts members (0 for a missing key), `kv_zscore` returns a member's score or null, `kv_zrank` returns a member's rank lowest-score-first or null, `kv_zrem` removes a list of members and counts the ones actually removed, `kv_zincrby` bumps a member's score (creating it when missing) and returns the new score; plus ZADD options from cinder 0.25.0 (`nx`/`xx`/`gt`/`lt`/`ch`/`incr` flags on `kv_zadd`, with conflicting combinations rejected as invalid params and `incr` returning the new score or null) — all batchable, plain and atomic~~ (done, v0.24.0)
- ~~Sorted-set range by score (`kv_zrangebyscore`): expose cinder's ZRANGEBYSCORE/ZREVRANGEBYSCORE — `min`/`max` bounds as numbers or strings with optional `(` exclusivity and `-inf`/`+inf` defaults, `withscores` member/score objects, `rev` for highest-first, `offset`/`count` LIMIT paging, at most 1000 members per call; batchable, plain and atomic~~ (done, v0.25.0)
- ~~Real `SCAN` keyspace scanner: `iter_keys` and `kv_keys_scan` now run cinder's real `SCAN` cursor loop (cinder 0.26.0, `SCAN cursor [MATCH pattern] [COUNT n]`) instead of slicing one `KEYS` reply — bounded batches, `MATCH` filtering, opaque decimal cursors, cursor exhaustion at `0`; the prompt iterator dedupes so a key a table resize returns twice is still covered exactly once, and `kv_keys_scan` exposes the raw paged walk with real `SCAN` caveats. The tools and prompts did not change, only `cinder_mcp/scan.py`~~ (done, v0.26.0)
- ~~More sorted-set tools (`kv_zcount`, `kv_zrevrank`): cinder has neither `ZCOUNT` nor `ZREVRANK`, so both are built honestly on commands it does have — `kv_zcount` counts a score range by fetching it with `ZRANGEBYSCORE` (same bound parsing as `kv_zrangebyscore`: inclusive/exclusive, `-inf`/`+inf`) and counting the members, failing instead of truncating when the range holds more than 1000 members; `kv_zrevrank` reads `ZRANK` and `ZCARD` and returns `ZCARD - 1 - ZRANK`, null for a missing member. Both are batchable, plain and atomic; in an atomic batch `kv_zrevrank` queues its two commands in one transaction~~ (done, v0.27.0)

## Next

- `kv_pexpire` is still blocked: cinder has no `PEXPIRE` yet.
