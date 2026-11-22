"""Tests for cinder-mcp, against a fake RESP server on a socket.

The fake server implements just enough of cinder's surface (PING, SET,
GET, DEL, KEYS, INCR, INCRBY, TTL, EXISTS, EXPIRE) to prove the MCP layer
works: the handshake, the tool list, a SET-then-GET round trip, and clean
JSON-RPC errors when cinder is unreachable or a request is malformed.
"""

import io
import json
import socket
import threading
import time
import unittest

from cinder_mcp.resp import RespClient
from cinder_mcp.server import MCPServer, serve


def _glob_match(pattern, key):
    # Tiny glob: * matches any run, ? matches one character.
    px = kx = 0
    star_p = star_k = -1
    while kx < len(key):
        if px < len(pattern) and pattern[px] in ("?", key[kx]):
            px += 1
            kx += 1
        elif px < len(pattern) and pattern[px] == "*":
            star_p, star_k = px, kx
            px += 1
        elif star_p != -1:
            px, kx = star_p + 1, star_k + 1
            star_k += 1
        else:
            return False
    while px < len(pattern) and pattern[px] == "*":
        px += 1
    return px == len(pattern)


class FakeCinder(threading.Thread):
    """A minimal RESP server on an ephemeral port, speaking cinder's subset."""

    def __init__(self):
        super().__init__(daemon=True)
        self.store = {}  # key -> (value, expires_at or None)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.sock.listen(5)
        self.running = True

    def run(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def stop(self):
        self.running = False
        self.sock.close()

    def _read_line(self, f):
        line = f.readline()
        if not line:
            raise EOFError
        return line.rstrip(b"\r\n")

    def _read_value(self, f):
        line = self._read_line(f)
        kind, rest = line[:1], line[1:]
        if kind == b"$":
            n = int(rest)
            if n == -1:
                return None
            return f.read(n + 2)[:n].decode()
        if kind == b"*":
            return [self._read_value(f) for _ in range(int(rest))]
        if kind == b":":
            return int(rest)
        if kind == b"+":
            return rest.decode()
        raise ValueError("bad RESP prefix %r" % kind)

    def _reply(self, conn, text):
        conn.sendall(text.encode())

    def _bulk(self, value):
        if value is None:
            return "$-1\r\n"
        raw = value.encode()
        return "$%d\r\n%s\r\n" % (len(raw), value)

    def _get(self, key):
        entry = self.store.get(key)
        if entry is None:
            return None
        value, expires = entry
        if expires is not None and expires <= time.time():
            del self.store[key]
            return None
        return value

    def _handle(self, conn):
        f = conn.makefile("rb")
        try:
            while True:
                try:
                    cmd = self._read_value(f)
                except (EOFError, ValueError, OSError):
                    return
                if not isinstance(cmd, list) or not cmd:
                    self._reply(conn, "-ERR empty command\r\n")
                    continue
                name = cmd[0].upper()
                args = cmd[1:]
                if name == "PING":
                    self._reply(conn, "+PONG\r\n")
                elif name == "SET" and len(args) >= 2:
                    key, value = args[0], args[1]
                    expires = None
                    i = 2
                    while i < len(args):
                        opt = args[i].upper()
                        if opt == "EX":
                            expires = time.time() + int(args[i + 1])
                            i += 2
                        elif opt == "PX":
                            expires = time.time() + int(args[i + 1]) / 1000.0
                            i += 2
                        else:
                            i += 1
                    self.store[key] = (value, expires)
                    self._reply(conn, "+OK\r\n")
                elif name == "GET" and len(args) == 1:
                    self._reply(conn, self._bulk(self._get(args[0])))
                elif name == "DEL":
                    n = sum(1 for k in args if self._get(k) is not None)
                    for k in args:
                        self.store.pop(k, None)
                    self._reply(conn, ":%d\r\n" % n)
                elif name == "KEYS":
                    pattern = args[0] if args else "*"
                    keys = [k for k in list(self.store) if self._get(k) is not None
                            and _glob_match(pattern, k)]
                    out = "*%d\r\n" % len(keys) + "".join(self._bulk(k) for k in keys)
                    self._reply(conn, out)
                elif name == "INCR" and len(args) == 1:
                    self._reply(conn, ":%d\r\n" % self._incr(args[0], 1))
                elif name == "INCRBY" and len(args) == 2:
                    self._reply(conn, ":%d\r\n" % self._incr(args[0], int(args[1])))
                elif name == "TTL" and len(args) == 1:
                    entry = self.store.get(args[0])
                    if entry is None or (entry[1] is not None and entry[1] <= time.time()):
                        self.store.pop(args[0], None)
                        self._reply(conn, ":-2\r\n")
                    elif entry[1] is None:
                        self._reply(conn, ":-1\r\n")
                    else:
                        self._reply(conn, ":%d\r\n" % int(entry[1] - time.time()))
                elif name == "EXISTS":
                    n = sum(1 for k in args if self._get(k) is not None)
                    self._reply(conn, ":%d\r\n" % n)
                elif name == "EXPIRE" and len(args) == 2:
                    seconds = int(args[1])
                    if seconds < 0:
                        self._reply(conn, "-ERR invalid expire time in 'expire' command\r\n")
                    elif self._get(args[0]) is None:
                        self._reply(conn, ":0\r\n")
                    else:
                        value, _ = self.store[args[0]]
                        self.store[args[0]] = (value, time.time() + seconds)
                        self._reply(conn, ":1\r\n")
                else:
                    self._reply(conn, "-ERR unknown command\r\n")
        finally:
            conn.close()

    def _incr(self, key, by):
        current = self._get(key)
        value = (int(current) if current is not None else 0) + by
        expires = self.store[key][1] if key in self.store else None
        self.store[key] = (str(value), expires)
        return value


class McpTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeCinder()
        self.fake.start()
        self.server = MCPServer(RespClient("127.0.0.1", self.fake.port))

    def tearDown(self):
        self.fake.stop()

    def _call(self, method, msg_id=1, params=None):
        return self.server.handle_message(
            {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}
        )

    def test_handshake_returns_tool_list(self):
        init = self._call("initialize", 1, {"protocolVersion": "2024-11-05"})
        self.assertEqual(init["result"]["serverInfo"]["name"], "cinder-mcp")
        self.assertIn("tools", init["result"]["capabilities"])
        listed = self._call("tools/list", 2)
        names = [t["name"] for t in listed["result"]["tools"]]
        self.assertEqual(
            names, ["kv_get", "kv_set", "kv_del", "kv_keys", "kv_incr", "kv_ttl",
                    "kv_exists", "kv_expire"]
        )

    def test_tools_call_set_then_get(self):
        set_reply = self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "hello", "value": "world"},
        })
        self.assertEqual(set_reply["result"]["content"][0]["text"], "OK")
        get_reply = self._call("tools/call", 2, {
            "name": "kv_get", "arguments": {"key": "hello"},
        })
        self.assertEqual(get_reply["result"]["content"][0]["text"], "world")
        missing = self._call("tools/call", 3, {
            "name": "kv_get", "arguments": {"key": "nope"},
        })
        self.assertEqual(missing["result"]["content"][0]["text"], "null")

    def test_tools_call_incr_ttl_and_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_incr", "arguments": {"key": "n", "by": 5},
        })
        incr = self._call("tools/call", 2, {
            "name": "kv_incr", "arguments": {"key": "n"},
        })
        self.assertEqual(incr["result"]["content"][0]["text"], "6")
        ttl = self._call("tools/call", 3, {
            "name": "kv_ttl", "arguments": {"key": "n"},
        })
        self.assertEqual(ttl["result"]["content"][0]["text"], "-1")
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "user:1", "value": "a"},
        })
        keys = self._call("tools/call", 5, {
            "name": "kv_keys", "arguments": {"pattern": "user:*"},
        })
        self.assertEqual(keys["result"]["content"][0]["text"], '["user:1"]')

    def test_tools_call_exists_and_expire(self):
        missing = self._call("tools/call", 1, {
            "name": "kv_exists", "arguments": {"key": "ghost"},
        })
        self.assertEqual(missing["result"]["content"][0]["text"], "0")
        no_expire = self._call("tools/call", 2, {
            "name": "kv_expire", "arguments": {"key": "ghost", "seconds": 60},
        })
        self.assertEqual(no_expire["result"]["content"][0]["text"], "0")
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "temp", "value": "v"},
        })
        exists = self._call("tools/call", 4, {
            "name": "kv_exists", "arguments": {"key": "temp"},
        })
        self.assertEqual(exists["result"]["content"][0]["text"], "1")
        expired = self._call("tools/call", 5, {
            "name": "kv_expire", "arguments": {"key": "temp", "seconds": 3600},
        })
        self.assertEqual(expired["result"]["content"][0]["text"], "1")
        ttl = self._call("tools/call", 6, {
            "name": "kv_ttl", "arguments": {"key": "temp"},
        })
        remaining = int(ttl["result"]["content"][0]["text"])
        self.assertTrue(0 < remaining <= 3600)

    def test_unreachable_cinder_returns_clean_jsonrpc_error(self):
        dead = MCPServer(RespClient("127.0.0.1", 1))  # nothing listens here
        reply = dead.handle_message({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "kv_get", "arguments": {"key": "x"}},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32000)
        self.assertIn("not reachable", reply["error"]["message"])

    def test_malformed_request_returns_error(self):
        self.assertEqual(
            self.server.handle_message("not a dict")["error"]["code"], -32600
        )
        self.assertEqual(
            self._call("no/such/method")["error"]["code"], -32601
        )
        # Notifications (no id) get no reply.
        self.assertIsNone(self.server.handle_message(
            {"jsonrpc": "2.0", "method": "tools/list"}))
        # A line that is not JSON at all gets a -32700 parse error via serve().
        out = io.StringIO()
        serve(self.server, io.StringIO("{not json\n"), out)
        self.assertEqual(json.loads(out.getvalue())["error"]["code"], -32700)


if __name__ == "__main__":
    unittest.main()
