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
| `kv_keys_scan` | `KEYS pattern` | Walk the matching keys one bounded page at a time, SCAN-style. Returns `{"keys": [...], "cursor": str, "done": bool, "batch_size": n}`: at most `batch_size` keys per page (default 100, max 1000). Pass the returned `cursor` back for the next page; `""` starts over. When `done` is true the cursor is `""` and the walk is finished. Pages are in sorted key order; keys added after the cursor are picked up later, keys deleted or renamed between pages can shift the window — the same caveats real SCAN has. Each page re-runs `KEYS` under the hood, because cinder has no `SCAN` command yet; the page itself stays bounded |
| `kv_incr` | `INCR key` / `INCRBY key n` | `by` defaults to 1 |
| `kv_ttl` | `TTL key` | -1 = no expiry, -2 = missing key |
| `kv_exists` | `EXISTS key` | 1 if the key exists, 0 otherwise |
| `kv_expire` | `EXPIRE key seconds` | 1 if the timeout was set, 0 if the key is missing |
| `kv_batch` | several kv ops in one call | Runs the `ops` list in order and returns one summary: per-op result or error plus `ok` / `failed` counts. A failed op is recorded and the batch keeps going; at most 100 ops. Not atomic — cinder has no `MULTI` yet, so this saves round trips, it is not a transaction. |

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

`ttl-audit` and `cleanup-plan` scan the keyspace in bounded batches
of 100 keys (`cinder_mcp/scan.py`), and `kv_keys_scan` exposes the
same walk as a paged tool. The per-key work and the prompt text stay
bounded: the prompts keep only counts plus the 10 soonest-expiring
keys, the first 20 no-expiry keys, and the first 20 keys per cleanup
section, with "... and N more" for the rest. The results are
identical to the old load-everything scan at any batch size — the
tests run both prompts at batch sizes 1, 2, 7 and 100 over the same
keyspace and compare the full prompt text.

One honest limitation: cinder has no `SCAN` command yet, so the
iterator is backed by one `KEYS` call whose reply is sliced into
batches, and each `kv_keys_scan` page re-runs `KEYS`. The bounded
part today is everything downstream of that reply. When cinder
grows `SCAN`, the iterator switches to cursor batches and the
`KEYS` reply disappears too, with no change to the tools or the
prompts.

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

## Next

- Switch the scanner to real `SCAN` cursor batches once cinder implements `SCAN`, so the `KEYS` reply itself is bounded too; the tools and prompts do not change.
