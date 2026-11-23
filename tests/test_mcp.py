"""Tests for cinder-mcp, against a fake RESP server on a socket.

The fake server implements just enough of cinder's surface (PING, SET,
GET, DEL, KEYS, INCR, INCRBY, TTL, EXISTS, EXPIRE, LLEN, SCARD, HLEN)
to prove the MCP layer works: the handshake, the tool list, a SET-then-GET round trip, and clean
JSON-RPC errors when cinder is unreachable or a request is malformed.
Keys in the fake store may also hold a list, set, or dict value so the
per-key resource's type probing can be exercised.
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
                    value = self._get(args[0])
                    if value is not None and not isinstance(value, str):
                        self._reply(conn, "-WRONGTYPE Operation against a key holding the wrong kind of value\r\n")
                    else:
                        self._reply(conn, self._bulk(value))
                elif name == "LLEN" and len(args) == 1:
                    self._reply(conn, self._container_len(args[0], list))
                elif name == "SCARD" and len(args) == 1:
                    self._reply(conn, self._container_len(args[0], set))
                elif name == "HLEN" and len(args) == 1:
                    self._reply(conn, self._container_len(args[0], dict))
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
                elif name == "INFO":
                    info = (
                        "# Server\r\n"
                        "cinder_version:0.4.0\r\n"
                        "uptime_in_seconds:42\r\n"
                        "total_commands_processed:7\r\n"
                        "# Keyspace\r\n"
                        "keys:%d\r\n" % len(self.store)
                    )
                    self._reply(conn, self._bulk(info))
                else:
                    self._reply(conn, "-ERR unknown command\r\n")
        finally:
            conn.close()

    def _container_len(self, key, kind):
        value = self._get(key)
        if value is None:
            return ":0\r\n"
        if not isinstance(value, kind):
            return ("-WRONGTYPE Operation against a key holding the "
                    "wrong kind of value\r\n")
        return ":%d\r\n" % len(value)

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
        self.assertIn("resources", init["result"]["capabilities"])
        self.assertIn("prompts", init["result"]["capabilities"])
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

    def test_resources_list_returns_info_metrics_and_key_template(self):
        listed = self._call("resources/list", 1)
        resources = listed["result"]["resources"]
        self.assertEqual(len(resources), 3)
        self.assertEqual(resources[0]["uri"], "cinder://info")
        self.assertEqual(resources[0]["mimeType"], "text/plain")
        self.assertEqual(resources[1]["uri"], "cinder://metrics")
        self.assertEqual(resources[1]["mimeType"], "application/json")
        self.assertEqual(resources[2]["uriTemplate"], "cinder://key/{key}")
        self.assertEqual(resources[2]["mimeType"], "application/json")

    def test_resources_read_key_string_returns_value_and_type(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "hello", "value": "world"},
        })
        reply = self._call("resources/read", 2, {"uri": "cinder://key/hello"})
        contents = reply["result"]["contents"]
        self.assertEqual(len(contents), 1)
        self.assertEqual(contents[0]["uri"], "cinder://key/hello")
        self.assertEqual(contents[0]["mimeType"], "application/json")
        self.assertEqual(json.loads(contents[0]["text"]), {
            "key": "hello", "type": "string", "value": "world",
        })

    def test_resources_read_key_missing_returns_not_found(self):
        reply = self._call("resources/read", 1, {"uri": "cinder://key/ghost"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("key not found: ghost", reply["error"]["message"])

    def test_resources_read_key_list_returns_type_and_length(self):
        self.fake.store["todo"] = (["buy milk", "ship it"], None)
        reply = self._call("resources/read", 1, {"uri": "cinder://key/todo"})
        self.assertEqual(json.loads(reply["result"]["contents"][0]["text"]), {
            "key": "todo", "type": "list", "length": 2,
        })

    def test_resources_read_key_set_and_hash(self):
        self.fake.store["tags"] = ({"a", "b", "c"}, None)
        reply = self._call("resources/read", 1, {"uri": "cinder://key/tags"})
        self.assertEqual(json.loads(reply["result"]["contents"][0]["text"]), {
            "key": "tags", "type": "set", "length": 3,
        })
        self.fake.store["user:1"] = ({"name": "mammu"}, None)
        reply = self._call("resources/read", 2, {"uri": "cinder://key/user:1"})
        self.assertEqual(json.loads(reply["result"]["contents"][0]["text"]), {
            "key": "user:1", "type": "hash", "length": 1,
        })

    def test_resources_read_key_url_decodes_key(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a b", "value": "v"},
        })
        reply = self._call("resources/read", 2, {"uri": "cinder://key/a%20b"})
        self.assertEqual(json.loads(reply["result"]["contents"][0]["text"]), {
            "key": "a b", "type": "string", "value": "v",
        })

    def test_resources_read_key_empty_key_returns_error(self):
        reply = self._call("resources/read", 1, {"uri": "cinder://key/"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)

    def test_resources_read_info_returns_server_info(self):
        reply = self._call("resources/read", 1, {"uri": "cinder://info"})
        contents = reply["result"]["contents"]
        self.assertEqual(len(contents), 1)
        self.assertEqual(contents[0]["uri"], "cinder://info")
        self.assertEqual(contents[0]["mimeType"], "text/plain")
        self.assertIn("cinder_version:0.4.0", contents[0]["text"])
        self.assertIn("keys:0", contents[0]["text"])

    def test_prompts_list_returns_all_four_prompts(self):
        listed = self._call("prompts/list", 1)
        prompts = listed["result"]["prompts"]
        self.assertEqual(len(prompts), 4)
        self.assertEqual(prompts[0]["name"], "keyspace-summary")
        self.assertEqual(prompts[0]["arguments"][0]["name"], "pattern")
        self.assertFalse(prompts[0]["arguments"][0]["required"])
        self.assertEqual(prompts[1]["name"], "key-deep-dive")
        self.assertEqual(prompts[1]["arguments"][0]["name"], "key")
        self.assertTrue(prompts[1]["arguments"][0]["required"])
        self.assertEqual(prompts[2]["name"], "ttl-audit")
        self.assertEqual(prompts[2]["arguments"][0]["name"], "pattern")
        self.assertFalse(prompts[2]["arguments"][0]["required"])
        self.assertEqual(prompts[3]["name"], "cleanup-plan")
        self.assertEqual(prompts[3]["arguments"][0]["name"], "pattern")
        self.assertFalse(prompts[3]["arguments"][0]["required"])

    def test_prompts_get_empty_keyspace(self):
        reply = self._call("prompts/get", 1, {"name": "keyspace-summary"})
        messages = reply["result"]["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        text = messages[0]["content"]["text"]
        self.assertIn("Keys matching '*' (0):", text)
        self.assertIn("(no keys)", text)
        self.assertIn("cinder_version:0.4.0", text)

    def test_prompts_get_lists_live_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "user:1", "value": "a"},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "user:2", "value": "b"},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "cache:x", "value": "c"},
        })
        reply = self._call("prompts/get", 4, {"name": "keyspace-summary"})
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Keys matching '*' (3):", text)
        self.assertIn("- user:1", text)
        self.assertIn("- cache:x", text)
        self.assertIn("kv_ttl", text)

    def test_prompts_get_pattern_filters_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "user:1", "value": "a"},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "cache:x", "value": "c"},
        })
        reply = self._call("prompts/get", 3, {
            "name": "keyspace-summary", "arguments": {"pattern": "user:*"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Keys matching 'user:*' (1):", text)
        self.assertIn("- user:1", text)
        self.assertNotIn("cache:x", text)

    def test_prompts_get_unknown_prompt_returns_error(self):
        reply = self._call("prompts/get", 1, {"name": "nope"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("unknown prompt: nope", reply["error"]["message"])

    def test_prompts_get_deep_dive_string_key(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {
                "key": "user:1", "value": "alice", "ex": 3600},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "user:2", "value": "bob"},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "cache:x", "value": "c"},
        })
        reply = self._call("prompts/get", 4, {
            "name": "key-deep-dive", "arguments": {"key": "user:1"},
        })
        messages = reply["result"]["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        text = messages[0]["content"]["text"]
        self.assertIn("Deep dive on key 'user:1'.", text)
        self.assertIn("Type: string", text)
        self.assertIn("Size: 5 bytes", text)
        self.assertIn("Sample value:\nalice", text)
        ttl_line = [l for l in text.split("\n") if l.startswith("TTL:")][0]
        remaining = int(ttl_line.split()[1])
        self.assertTrue(0 < remaining <= 3600)
        # Only the sibling in the same namespace counts as related.
        self.assertIn("- user:2", text)
        self.assertNotIn("cache:x", text)
        self.assertIn("kv_expire", text)

    def test_prompts_get_deep_dive_string_no_expiry(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "plain", "value": "v"},
        })
        reply = self._call("prompts/get", 2, {
            "name": "key-deep-dive", "arguments": {"key": "plain"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("TTL: no expiry set", text)
        self.assertIn("Size: 1 bytes", text)
        self.assertIn("Related keys (0):", text)
        self.assertIn("(none)", text)

    def test_prompts_get_deep_dive_list_key(self):
        self.fake.store["todo"] = (["buy milk", "ship it"], None)
        reply = self._call("prompts/get", 1, {
            "name": "key-deep-dive", "arguments": {"key": "todo"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Type: list", text)
        self.assertIn("Size: 2 elements", text)
        self.assertNotIn("Sample value:", text)

    def test_prompts_get_deep_dive_truncates_long_value(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "big", "value": "x" * 250},
        })
        reply = self._call("prompts/get", 2, {
            "name": "key-deep-dive", "arguments": {"key": "big"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Size: 250 bytes", text)
        self.assertIn("... (truncated)", text)
        self.assertNotIn("x" * 250, text)

    def test_prompts_get_deep_dive_missing_key_returns_error(self):
        reply = self._call("prompts/get", 1, {
            "name": "key-deep-dive", "arguments": {"key": "ghost"},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("key not found: ghost", reply["error"]["message"])

    def test_prompts_get_deep_dive_requires_key_argument(self):
        reply = self._call("prompts/get", 1, {"name": "key-deep-dive"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("requires a key argument", reply["error"]["message"])

    def test_prompts_get_ttl_audit_empty_keyspace(self):
        reply = self._call("prompts/get", 1, {"name": "ttl-audit"})
        messages = reply["result"]["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        text = messages[0]["content"]["text"]
        self.assertIn("TTL audit of the cinder keyspace (pattern '*').", text)
        self.assertIn("Total keys scanned: 0", text)
        self.assertIn("- no expiry: 0", text)
        self.assertIn("- expiring in under 1 hour: 0", text)
        self.assertIn("- expiring in under 1 day: 0", text)
        self.assertIn("- expiring in under 1 week: 0", text)
        self.assertIn("- expiring in over 1 week: 0", text)
        self.assertIn("Soonest expiring keys (0):", text)
        self.assertIn("(none expiring)", text)
        self.assertIn("Keys with no expiry (0):", text)
        self.assertIn("(none)", text)
        self.assertIn("kv_expire", text)

    def test_prompts_get_ttl_audit_buckets_and_soonest(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "soon", "value": "v", "ex": 30},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "today", "value": "v", "ex": 7200},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "week", "value": "v", "ex": 90000},
        })
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "far", "value": "v", "ex": 900000},
        })
        self._call("tools/call", 5, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        reply = self._call("prompts/get", 6, {"name": "ttl-audit"})
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 5", text)
        self.assertIn("- no expiry: 1", text)
        self.assertIn("- expiring in under 1 hour: 1", text)
        self.assertIn("- expiring in under 1 day: 1", text)
        self.assertIn("- expiring in under 1 week: 1", text)
        self.assertIn("- expiring in over 1 week: 1", text)
        self.assertIn("Soonest expiring keys (4):", text)
        # Soonest first, in ascending TTL order.
        soonest = text.split("Soonest expiring keys (4):\n")[1].split("\n\n")[0]
        self.assertEqual(
            [line.split(" (in ")[0][2:] for line in soonest.split("\n")],
            ["soon", "today", "week", "far"],
        )
        import re
        soon_line = [l for l in text.split("\n") if l.startswith("- soon (in ")][0]
        # A second may elapse between SET EX 30 and the TTL probe.
        self.assertRegex(soon_line, r"^- soon \(in (29|30)s\)$")
        self.assertIn("Keys with no expiry (1):", text)
        self.assertIn("- forever", text)
        self.assertNotIn("expired while scanning", text)

    def test_prompts_get_ttl_audit_pattern_filters_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "user:1", "value": "a", "ex": 60},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "cache:x", "value": "c"},
        })
        reply = self._call("prompts/get", 3, {
            "name": "ttl-audit", "arguments": {"pattern": "user:*"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 1", text)
        self.assertIn("- expiring in under 1 hour: 1", text)
        self.assertIn("- no expiry: 0", text)
        self.assertIn("- user:1 (in ", text)
        self.assertNotIn("cache:x", text)

    def test_prompts_get_cleanup_plan_classification_boundaries(self):
        from cinder_mcp.prompts import _classify_cleanup, _looks_temporary
        self.assertEqual(_classify_cleanup("x", -1), "risky")
        self.assertEqual(_classify_cleanup("x", 1), "safe")
        self.assertEqual(_classify_cleanup("x", 3599), "safe")
        self.assertEqual(_classify_cleanup("x", 3600), "soon")
        self.assertEqual(_classify_cleanup("x", 86399), "soon")
        self.assertEqual(_classify_cleanup("x", 86400), "keep")
        self.assertEqual(_classify_cleanup("x", 10 ** 9), "keep")
        self.assertTrue(_looks_temporary("cache:old"))
        self.assertTrue(_looks_temporary("session:abc"))
        self.assertTrue(_looks_temporary("tmp"))
        self.assertTrue(_looks_temporary("rate:limit"))
        self.assertFalse(_looks_temporary("mycache:x"))
        self.assertFalse(_looks_temporary("tempfile"))
        self.assertFalse(_looks_temporary("user:1"))

    def _section(self, text, header_prefix):
        """The lines of one cleanup-plan section, by its header prefix."""
        lines = text.split("\n")
        start = next(
            i for i, line in enumerate(lines) if line.startswith(header_prefix)
        )
        out = []
        for line in lines[start + 1:]:
            if line == "":
                break
            out.append(line)
        return out

    def test_prompts_get_cleanup_plan_empty_keyspace(self):
        reply = self._call("prompts/get", 1, {"name": "cleanup-plan"})
        messages = reply["result"]["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        text = messages[0]["content"]["text"]
        self.assertIn("Cleanup plan for the cinder keyspace (pattern '*').", text)
        self.assertIn("Total keys scanned: 0", text)
        self.assertIn("cinder_version:0.4.0", text)
        self.assertIn("Safe to delete (0)", text)
        self.assertIn("Expiring soon (0)", text)
        self.assertIn("Risky — confirm before deleting (0)", text)
        self.assertIn("Keep (0)", text)
        self.assertEqual(text.count("(none)"), 4)
        self.assertNotIn("expired while scanning", text)
        self.assertIn("kv_del", text)

    def test_prompts_get_cleanup_plan_classifies_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "soon", "value": "v", "ex": 30},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "today", "value": "v", "ex": 7200},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "far", "value": "v", "ex": 900000},
        })
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        self._call("tools/call", 5, {
            "name": "kv_set", "arguments": {"key": "cache:old", "value": "v"},
        })
        reply = self._call("prompts/get", 6, {"name": "cleanup-plan"})
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 5", text)
        safe = self._section(text, "Safe to delete (1)")
        self.assertEqual(len(safe), 1)
        self.assertTrue(safe[0].startswith("- soon (string, 1 bytes, expires in "))
        self.assertRegex(safe[0], r"expires in (29|30)s\)$")
        soon = self._section(text, "Expiring soon (1)")
        self.assertEqual(len(soon), 1)
        self.assertTrue(soon[0].startswith("- today (string, 1 bytes, expires in "))
        risky = self._section(text, "Risky — confirm before deleting (2)")
        self.assertEqual(len(risky), 2)
        self.assertIn("- forever (string, 1 bytes, no expiry)", risky)
        self.assertIn(
            "- cache:old (string, 1 bytes, no expiry, looks temporary)", risky)
        keep = self._section(text, "Keep (1)")
        self.assertEqual(len(keep), 1)
        self.assertTrue(keep[0].startswith("- far (string, 1 bytes, expires in "))
        # No key appears in two sections.
        listed = safe + soon + risky + keep
        self.assertEqual(len(listed), 5)
        self.assertIn("Do not delete anything yourself", text)

    def test_prompts_get_cleanup_plan_container_key(self):
        self.fake.store["todo"] = (["buy milk", "ship it"], None)
        reply = self._call("prompts/get", 1, {"name": "cleanup-plan"})
        text = reply["result"]["messages"][0]["content"]["text"]
        risky = self._section(text, "Risky — confirm before deleting (1)")
        self.assertEqual(risky, ["- todo (list, 2 elements, no expiry)"])

    def test_prompts_get_cleanup_plan_pattern_filters_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "user:1", "value": "a", "ex": 60},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "cache:x", "value": "c"},
        })
        reply = self._call("prompts/get", 3, {
            "name": "cleanup-plan", "arguments": {"pattern": "user:*"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 1", text)
        self.assertIn("Safe to delete (1)", text)
        self.assertIn("Risky — confirm before deleting (0)", text)
        self.assertIn("- user:1 (string, 1 bytes, expires in ", text)
        self.assertNotIn("cache:x", text)

    def test_metrics_resource_records_tool_calls(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "b", "value": "2"},
        })
        self._call("tools/call", 3, {
            "name": "kv_get", "arguments": {"key": "a"},
        })
        reply = self._call("resources/read", 4, {"uri": "cinder://metrics"})
        contents = reply["result"]["contents"]
        self.assertEqual(len(contents), 1)
        self.assertEqual(contents[0]["uri"], "cinder://metrics")
        self.assertEqual(contents[0]["mimeType"], "application/json")
        data = json.loads(contents[0]["text"])
        self.assertEqual(data["total_calls"], 3)
        self.assertEqual(data["total_errors"], 0)
        self.assertEqual(data["tools"]["kv_set"]["calls"], 2)
        self.assertEqual(data["tools"]["kv_set"]["errors"], 0)
        self.assertEqual(data["tools"]["kv_get"]["calls"], 1)
        for stats in data["tools"].values():
            self.assertGreaterEqual(stats["mean_ms"], 0)
            self.assertGreaterEqual(stats["p50_ms"], 0)
            self.assertGreaterEqual(stats["p95_ms"], 0)
            self.assertGreaterEqual(stats["p95_ms"], stats["p50_ms"])

    def test_metrics_resource_counts_failed_calls(self):
        # Unknown tool: invalid params, recorded as an error.
        reply = self._call("tools/call", 1, {"name": "nope"})
        self.assertIn("error", reply)
        # A cinder-side error (negative EXPIRE) also counts as an error.
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "temp", "value": "v"},
        })
        reply = self._call("tools/call", 3, {
            "name": "kv_expire", "arguments": {"key": "temp", "seconds": -5},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32000)
        data = json.loads(
            self._call("resources/read", 4, {"uri": "cinder://metrics"})
            ["result"]["contents"][0]["text"]
        )
        self.assertEqual(data["total_calls"], 3)
        self.assertEqual(data["total_errors"], 2)
        self.assertEqual(data["tools"]["nope"]["calls"], 1)
        self.assertEqual(data["tools"]["nope"]["errors"], 1)
        self.assertGreaterEqual(data["tools"]["nope"]["mean_ms"], 0)
        self.assertEqual(data["tools"]["kv_expire"]["calls"], 1)
        self.assertEqual(data["tools"]["kv_expire"]["errors"], 1)
        self.assertEqual(data["tools"]["kv_set"]["errors"], 0)

    def test_metrics_resource_empty_session(self):
        data = json.loads(
            self._call("resources/read", 1, {"uri": "cinder://metrics"})
            ["result"]["contents"][0]["text"]
        )
        self.assertEqual(data, {"tools": {}, "total_calls": 0, "total_errors": 0})

    def test_info_resource_includes_metrics_section(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        reply = self._call("resources/read", 2, {"uri": "cinder://info"})
        text = reply["result"]["contents"][0]["text"]
        self.assertIn("cinder_version:0.4.0", text)
        self.assertIn("# Tool metrics (cinder-mcp, this session)", text)
        self.assertIn("tool:kv_set calls:1 errors:0", text)
        self.assertRegex(text, r"mean_ms:\d+\.\d{3} p50_ms:\d+\.\d{3} p95_ms:\d+\.\d{3}")

    def test_info_resource_empty_session_reports_no_calls(self):
        reply = self._call("resources/read", 1, {"uri": "cinder://info"})
        text = reply["result"]["contents"][0]["text"]
        self.assertIn("# Tool metrics (cinder-mcp, this session)", text)
        self.assertIn("(no tool calls yet)", text)

    def test_resources_read_unknown_uri_returns_error(self):
        reply = self._call("resources/read", 1, {"uri": "cinder://nope"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)

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


class MetricsTests(unittest.TestCase):
    def test_percentiles_use_nearest_rank(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        for ms in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10):
            metrics.record("kv_get", ms)
        stats = metrics.snapshot()["tools"]["kv_get"]
        self.assertEqual(stats["calls"], 10)
        self.assertEqual(stats["errors"], 0)
        self.assertEqual(stats["mean_ms"], 5.5)
        self.assertEqual(stats["p50_ms"], 5)   # 5th of 10
        self.assertEqual(stats["p95_ms"], 10)  # 10th of 10

    def test_single_sample_percentiles_equal_the_sample(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        metrics.record("kv_set", 2.5)
        stats = metrics.snapshot()["tools"]["kv_set"]
        self.assertEqual(stats["mean_ms"], 2.5)
        self.assertEqual(stats["p50_ms"], 2.5)
        self.assertEqual(stats["p95_ms"], 2.5)

    def test_errors_do_not_count_as_calls_lost(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        metrics.record("kv_get", 1.0, ok=True)
        metrics.record("kv_get", 3.0, ok=False)
        snapshot = metrics.snapshot()
        self.assertEqual(snapshot["total_calls"], 2)
        self.assertEqual(snapshot["total_errors"], 1)
        self.assertEqual(snapshot["tools"]["kv_get"]["errors"], 1)
        self.assertEqual(snapshot["tools"]["kv_get"]["mean_ms"], 2.0)

    def test_samples_capped_per_tool(self):
        from cinder_mcp.metrics import MAX_SAMPLES_PER_TOOL, ToolMetrics
        metrics = ToolMetrics()
        for i in range(MAX_SAMPLES_PER_TOOL + 5):
            metrics.record("kv_get", float(i))
        entry = metrics._tools["kv_get"]
        self.assertEqual(len(entry["latencies_ms"]), MAX_SAMPLES_PER_TOOL)
        # Oldest samples dropped: the smallest kept latency is 5.
        self.assertEqual(min(entry["latencies_ms"]), 5.0)
        self.assertEqual(entry["calls"], MAX_SAMPLES_PER_TOOL + 5)

    def test_empty_snapshot(self):
        from cinder_mcp.metrics import ToolMetrics
        self.assertEqual(
            ToolMetrics().snapshot(),
            {"tools": {}, "total_calls": 0, "total_errors": 0},
        )
        self.assertIn("(no tool calls yet)", ToolMetrics().render_text())


if __name__ == "__main__":
    unittest.main()
