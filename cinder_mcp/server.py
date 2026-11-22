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

from .resp import ConnectionError, RespClient, RespError
from .prompts import PROMPTS, get_prompt
from .resources import RESOURCES, read_resource
from .tools import TOOLS, call_tool

SERVER_NAME = "cinder-mcp"
SERVER_VERSION = "0.5.0"

# The protocol version this server negotiates. The client may request a
# newer one; we answer with the one we speak.
PROTOCOL_VERSION = "2024-11-05"


class MCPServer:
    def __init__(self, client):
        self.client = client

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
                response = self._result(msg_id, {"tools": TOOLS})
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
        result = call_tool(self.client, name, params.get("arguments") or {})
        return {"content": [{"type": "text", "text": _render(result)}]}

    def _resources_read(self, params):
        uri = params.get("uri")
        if not isinstance(uri, str):
            raise ValueError("resources/read requires a resource uri")
        return {"contents": [read_resource(self.client, uri)]}

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


def serve(client, instream, outstream):
    server = MCPServer(client)
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
    serve(RespClient(args.host, args.port), sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
