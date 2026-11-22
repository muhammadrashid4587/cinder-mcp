"""Demo: start a real cinder on a test port, run the MCP server against
it, and issue tools/call requests over stdio.

Usage: python3 scripts/demo.py

Requires the cinder binary (built from ~/workspace/projects/cinder).
Cleans up after itself: shuts cinder down and removes the demo data dir.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CINDER_DIR = os.path.expanduser("~/workspace/projects/cinder")
CINDER_BIN = os.path.join(CINDER_DIR, "cinder")
PORT = 7777
DATA_DIR = "/tmp/cinder-mcp-demo-data"


def wait_for_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def send(proc, message):
    proc.stdin.write(json.dumps(message) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def main():
    if not os.path.exists(CINDER_BIN):
        print("building cinder ...")
        subprocess.run(["make"], cwd=CINDER_DIR, check=True)
    shutil.rmtree(DATA_DIR, ignore_errors=True)

    cinder = subprocess.Popen(
        [CINDER_BIN, "--port", str(PORT), "--data-dir", DATA_DIR],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_for_port(PORT):
            print("cinder did not start")
            return 1
        env = dict(os.environ, CINDER_PORT=str(PORT))
        mcp = subprocess.Popen(
            [sys.executable, "-m", "cinder_mcp.server"],
            cwd=HERE,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        try:
            print("initialize:", send(mcp, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2024-11-05",
                           "capabilities": {}, "clientInfo": {"name": "demo", "version": "0.1.0"}},
            })["result"]["serverInfo"])
            tools = send(mcp, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
            print("tools:", [t["name"] for t in tools["result"]["tools"]])
            resources = send(mcp, {"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
            print("resources:", [r.get("uri") or r.get("uriTemplate")
                                 for r in resources["result"]["resources"]])
            prompts = send(mcp, {"jsonrpc": "2.0", "id": 4, "method": "prompts/list"})
            print("prompts:", [p["name"] for p in prompts["result"]["prompts"]])
            for i, call in enumerate([
                ("kv_set", {"key": "demo:counter", "value": "41"}),
                ("kv_incr", {"key": "demo:counter"}),
                ("kv_get", {"key": "demo:counter"}),
                ("kv_ttl", {"key": "demo:counter"}),
                ("kv_exists", {"key": "demo:counter"}),
                ("kv_expire", {"key": "demo:counter", "seconds": 3600}),
                ("kv_ttl", {"key": "demo:counter"}),
                ("kv_exists", {"key": "demo:missing"}),
            ], start=5):
                reply = send(mcp, {
                    "jsonrpc": "2.0", "id": i, "method": "tools/call",
                    "params": {"name": call[0], "arguments": call[1]},
                })
                print(call[0], "->", reply["result"]["content"][0]["text"])
            for i, uri in enumerate([
                "cinder://info",
                "cinder://key/demo:counter",
                "cinder://key/demo:missing",
            ], start=12):
                reply = send(mcp, {
                    "jsonrpc": "2.0", "id": i, "method": "resources/read",
                    "params": {"uri": uri},
                })
                if "result" in reply:
                    print(uri, "->", reply["result"]["contents"][0]["text"])
                else:
                    print(uri, "-> error", reply["error"]["message"])
            audit = send(mcp, {
                "jsonrpc": "2.0", "id": 15, "method": "prompts/get",
                "params": {"name": "ttl-audit"},
            })
            print("ttl-audit ->")
            print(audit["result"]["messages"][0]["content"]["text"])
            return 0
        finally:
            mcp.stdin.close()
            mcp.wait(timeout=5)
    finally:
        # SHUTDOWN via a raw RESP command, then fall back to terminate.
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=2) as sock:
                sock.sendall(b"*1\r\n$8\r\nSHUTDOWN\r\n")
        except OSError:
            pass
        try:
            cinder.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cinder.terminate()
            cinder.wait(timeout=5)
        shutil.rmtree(DATA_DIR, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
