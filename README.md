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

## Tools

| Tool | Cinder command | Notes |
| --- | --- | --- |
| `kv_get` | `GET key` | Returns `null` when the key is missing |
| `kv_set` | `SET key value [EX s \| PX ms]` | Optional `ex` / `px` TTL |
| `kv_del` | `DEL key` | 1 if the key existed, 0 otherwise |
| `kv_keys` | `KEYS pattern` | Glob `*` and `?`, defaults to `*` |
| `kv_incr` | `INCR key` / `INCRBY key n` | `by` defaults to 1 |
| `kv_ttl` | `TTL key` | -1 = no expiry, -2 = missing key |
| `kv_exists` | `EXISTS key` | 1 if the key exists, 0 otherwise |
| `kv_expire` | `EXPIRE key seconds` | 1 if the timeout was set, 0 if the key is missing |

## Resources

| URI | Cinder command | Notes |
| --- | --- | --- |
| `cinder://info` | `INFO` | Server version, uptime, commands processed, key count |
| `cinder://key/<key>` | `EXISTS` + `GET` / `LLEN` / `SCARD` / `HLEN` | Value and type as JSON; not-found error for missing keys. Non-string values report their type and length instead of a value (cinder has no `TYPE` command, so the type is probed) |

Fetchable with `resources/list` and `resources/read`.

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

## Roadmap

- ~~Sampling the cinder INFO output as a `cinder://info` resource~~ (done, v0.3.0)
- ~~Resource (URI) support for reading keys as MCP resources (`cinder://key/<key>`)~~ (done, v0.4.0)
- Prompt support (`prompts/list`, `prompts/get`)
