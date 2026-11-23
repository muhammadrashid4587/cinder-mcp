"""MCP server over stdio that exposes a running cinder as agent tools.

Protocol: JSON-RPC 2.0, one message per line on stdin/stdout (the MCP
stdio transport). Supported methods: initialize, ping, tools/list,
tools/call, resources/list, resources/read, prompts/list, prompts/get.
Notifications (messages without an id) get no reply.

Run: python3 -m cinder_mcp.server [--host 127.0.0.1] [--port 6379]
Or point it at a cinder with CINDER_HOST / CINDER_PORT.
"""

import argparse
import json
import os
import sys
import time

from .metrics import DEFAULT_SLOW_MS, DEFAULT_WARN_MS, ToolMetrics
from .resp import ConnectionError, RespClient, RespError
from .prompts import PROMPTS, get_prompt
from .resources import RESOURCES, read_resource
from .tools import call_tool, tools_with_budgets
from .watch import KeyspaceWatch

SERVER_NAME = "cinder-mcp"
SERVER_VERSION = "0.17.0"

# The protocol version this server negotiates. The client may request a
# newer one; we answer with the one we speak.
PROTOCOL_VERSION = "2024-11-05"


class MCPServer:
    def __init__(self, client, metrics=None, watch=None):
        self.client = client
        self.metrics = metrics if metrics is not None else ToolMetrics()
        # Per-session keyspace snapshots for cinder://changes; a
        # fresh server starts with no checkpoint.
        self.watch = watch if watch is not None else KeyspaceWatch()

    def handle_message(self, message):
        """Handle one decoded JSON-RPC message. Returns the response dict,
        or None for notifications (no id) which get no reply."""
        if not isinstance(message, dict):
            return self._error(None, -32600, "Invalid Request: expected an object")
        msg_id = message.get("id")
        method = message.get("method")
        if not isinstance(method, str):
            return self._error(msg_id, -32600, "Invalid Request: missing method")
        params = message.get("params") or {}
        is_notification = "id" not in message

        try:
            if method == "initialize":
                response = self._result(msg_id, self._initialize(params))
            elif method == "ping":
                response = self._result(msg_id, {})
            elif method == "tools/list":
                response = self._result(
                    msg_id, {"tools": tools_with_budgets(self.metrics)}
                )
            elif method == "tools/call":
                response = self._result(msg_id, self._tools_call(params))
            elif method == "resources/list":
                response = self._result(msg_id, {"resources": RESOURCES})
            elif method == "resources/read":
                response = self._result(msg_id, self._resources_read(params))
            elif method == "prompts/list":
                response = self._result(msg_id, {"prompts": PROMPTS})
            elif method == "prompts/get":
                response = self._result(msg_id, self._prompts_get(params))
            else:
                response = self._error(msg_id, -32601, "Method not found: %s" % method)
        except (ConnectionError, RespError) as exc:
            # The store is down or rejected the command: a clean
            # JSON-RPC error, not a crash and not a silent null.
            response = self._error(msg_id, -32000, str(exc))
        except (ValueError, KeyError, TypeError) as exc:
            response = self._error(msg_id, -32602, "Invalid params: %s" % exc)
        # Notifications get no reply at all (JSON-RPC 2.0).
        return None if is_notification else response

    def _initialize(self, params):
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }

    def _tools_call(self, params):
        name = params.get("name")
        if not isinstance(name, str):
            raise ValueError("tools/call requires a tool name")
        started = time.monotonic()
        try:
            result = call_tool(self.client, name, params.get("arguments") or {})
        except Exception:
            self.metrics.record(name, (time.monotonic() - started) * 1000, ok=False)
            raise
        latency_ms = (time.monotonic() - started) * 1000
        self.metrics.record(name, latency_ms, ok=True)
        response = {"content": [{"type": "text", "text": _render(result)}]}
        # A call that crossed its latency budget says so inline, in the
        # moment, instead of only showing up later in cinder://metrics.
        warning = self.metrics.classify(name, latency_ms)
        if warning is not None:
            response["warning"] = warning
        return response

    def _resources_read(self, params):
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise ValueError("resources/read requires a resource uri")
        return {"contents": [read_resource(self.client, uri, self.metrics, self.watch)]}

    def _prompts_get(self, params):
        name = params.get("name")
        if not isinstance(name, str):
            raise ValueError("prompts/get requires a prompt name")
        return get_prompt(self.client, name, params.get("arguments") or {})

    @staticmethod
    def _result(msg_id, result):
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    @staticmethod
    def _error(msg_id, code, message):
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": code, "message": message},
        }


def _render(value):
    """Render a tool result as text. null reads as null, lists as JSON."""
    if value is None:
        return "null"
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return str(value)


def _budgets_from_env():
    """Build the ToolMetrics for this process from the environment.

    CINDER_MCP_WARN_MS / CINDER_MCP_SLOW_MS set the default warn/slow
    thresholds in milliseconds; CINDER_MCP_BUDGETS is a JSON object
    mapping tool names to {"warn_ms": ..., "slow_ms": ...} overrides,
    e.g. '{"kv_keys": {"warn_ms": 250, "slow_ms": 1000}}'.
    Raises ValueError on bad input, so a misconfigured server fails
    loudly at startup instead of running with nonsense budgets.
    """
    try:
        warn_ms = float(os.environ.get("CINDER_MCP_WARN_MS", DEFAULT_WARN_MS))
        slow_ms = float(os.environ.get("CINDER_MCP_SLOW_MS", DEFAULT_SLOW_MS))
    except ValueError:
        raise ValueError(
            "CINDER_MCP_WARN_MS / CINDER_MCP_SLOW_MS must be numbers"
        )
    budgets = None
    raw = os.environ.get("CINDER_MCP_BUDGETS")
    if raw:
        try:
            budgets = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("CINDER_MCP_BUDGETS is not valid JSON: %s" % exc)
        if not isinstance(budgets, dict):
            raise ValueError("CINDER_MCP_BUDGETS must be a JSON object")
    return ToolMetrics(
        budgets=budgets, default_warn_ms=warn_ms, default_slow_ms=slow_ms
    )


def serve(client, instream, outstream, metrics=None):
    server = MCPServer(client, metrics=metrics)
    for line in instream:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            response = MCPServer._error(None, -32700, "Parse error")
            outstream.write(json.dumps(response) + "\n")
            outstream.flush()
            continue
        response = server.handle_message(message)
        if response is not None:
            outstream.write(json.dumps(response) + "\n")
            outstream.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description="MCP server for cinder")
    parser.add_argument("--host", default=os.environ.get("CINDER_HOST", "127.0.0.1"))
    parser.add_argument(
        "--port", type=int, default=int(os.environ.get("CINDER_PORT", "6379"))
    )
    args = parser.parse_args(argv)
    try:
        metrics = _budgets_from_env()
    except ValueError as exc:
        print("cinder-mcp: %s" % exc, file=sys.stderr)
        return 2
    serve(RespClient(args.host, args.port), sys.stdin, sys.stdout,
          metrics=metrics)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
