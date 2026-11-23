"""Tests for cinder-mcp, against a fake RESP server on a socket.

The fake server implements just enough of cinder's surface (PING, SET,
GET, DEL, KEYS, SCAN, INCR, INCRBY, TTL, EXISTS, EXPIRE, LLEN, SCARD, HLEN,
ZCARD, ZSCORE, ZRANK, ZREM, ZINCRBY, LRANGE, SMEMBERS, HSET, HGET, HGETALL, ZADD, ZRANGE, ZREVRANGE,
ZRANGEBYSCORE, ZREVRANGEBYSCORE, MULTI, EXEC, DISCARD)
to prove the MCP layer works: the handshake, the tool list, a SET-then-GET round trip, and clean
JSON-RPC errors when cinder is unreachable or a request is malformed.
Keys in the fake store may also hold a list, set, dict, or sorted-set
value so the per-key resource's type probing can be exercised.
"""

import hashlib
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


class ZSet:
    """A sorted set in the fake store: member names to float scores.
    A plain class, not a dict, so the hash handlers treat it as the
    wrong type, as real cinder does."""

    def __init__(self):
        self.members = {}

    def ordered(self):
        """Members sorted by (score, member), as ZRANGE returns them."""
        return sorted(self.members, key=lambda m: (self.members[m], m))


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
        in_multi = False
        queue = []
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
                if name == "MULTI":
                    if in_multi:
                        self._reply(conn, "-ERR MULTI calls can not be nested\r\n")
                    else:
                        in_multi = True
                        queue = []
                        self._reply(conn, "+OK\r\n")
                elif name == "DISCARD":
                    if not in_multi:
                        self._reply(conn, "-ERR DISCARD without MULTI\r\n")
                    else:
                        in_multi = False
                        queue = []
                        self._reply(conn, "+OK\r\n")
                elif name == "EXEC":
                    if not in_multi:
                        self._reply(conn, "-ERR EXEC without MULTI\r\n")
                    else:
                        in_multi = False
                        queued, queue = queue, []
                        out = "*%d\r\n" % len(queued) + "".join(
                            self._dispatch(c) for c in queued
                        )
                        self._reply(conn, out)
                elif in_multi:
                    queue.append(cmd)
                    self._reply(conn, "+QUEUED\r\n")
                else:
                    self._reply(conn, self._dispatch(cmd))
        finally:
            conn.close()

    def _dispatch(self, cmd):
        """Run one command against the fake store and return its raw
        RESP reply text. Errors are reply text, not exceptions, so an
        EXEC array can carry a failed op in place like real cinder."""
        name = cmd[0].upper()
        args = cmd[1:]
        if name == "PING":
            return "+PONG\r\n"
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
            return "+OK\r\n"
        elif name == "GET" and len(args) == 1:
            value = self._get(args[0])
            if value is not None and not isinstance(value, str):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            return self._bulk(value)
        elif name == "LLEN" and len(args) == 1:
            return self._container_len(args[0], list)
        elif name == "SCARD" and len(args) == 1:
            return self._container_len(args[0], set)
        elif name == "HLEN" and len(args) == 1:
            return self._container_len(args[0], dict)
        elif name == "LRANGE" and len(args) == 3:
            return self._container_items(args[0], list)
        elif name == "SMEMBERS" and len(args) == 1:
            return self._container_items(args[0], set)
        elif name == "HSET" and len(args) >= 3 and len(args) % 2 == 1:
            value = self._get(args[0])
            if value is not None and not isinstance(value, dict):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            if value is None:
                value = {}
                self.store[args[0]] = (value, None)
            added = 0
            for i in range(1, len(args), 2):
                if args[i] not in value:
                    added += 1
                value[args[i]] = args[i + 1]
            return ":%d\r\n" % added
        elif name == "HGET" and len(args) == 2:
            value = self._get(args[0])
            if value is None:
                return self._bulk(None)
            if not isinstance(value, dict):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            return self._bulk(value.get(args[1]))
        elif name == "HGETALL" and len(args) == 1:
            value = self._get(args[0])
            if value is None:
                return "*0\r\n"
            elif not isinstance(value, dict):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            flat = [x for pair in value.items() for x in pair]
            return "*%d\r\n" % len(flat) + "".join(self._bulk(v) for v in flat)
        elif name == "ZADD" and len(args) >= 3:
            # Options come after the key and before the first score,
            # as in cinder 0.25.0: NX | XX | GT | LT | CH | INCR.
            opts = set()
            i = 1
            while i < len(args) and args[i].upper() in (
                "NX", "XX", "GT", "LT", "CH", "INCR"
            ):
                opts.add(args[i].upper())
                i += 1
            if "NX" in opts and "XX" in opts:
                return "-ERR XX and NX options at the same time are not compatible\r\n"
            if ("GT" in opts and "LT" in opts) or (
                "NX" in opts and ("GT" in opts or "LT" in opts)
            ):
                return "-ERR GT, LT, and/or NX options at the same time are not compatible\r\n"
            rest = args[i:]
            if len(rest) < 2 or len(rest) % 2 != 0:
                return "-ERR wrong number of arguments for 'zadd' command\r\n"
            if "INCR" in opts and len(rest) != 2:
                return "-ERR INCR option supports a single increment-element pair\r\n"
            value = self._get(args[0])
            if value is not None and not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            scores = []
            for j in range(0, len(rest), 2):
                try:
                    score = float(rest[j])
                except ValueError:
                    return "-ERR value is not a valid float\r\n"
                if score != score:
                    return "-ERR value is not a valid float\r\n"
                scores.append(score)
            if "INCR" in opts:
                member = rest[1]
                cur = value.members.get(member, 0.0) if value else 0.0
                exists = value is not None and member in value.members
                if ("NX" in opts and exists) or ("XX" in opts and not exists):
                    return self._bulk(None)
                nxt = cur + scores[0]
                if nxt != nxt:
                    return "-ERR resulting score is not a number (NaN)\r\n"
                if exists and (("GT" in opts and nxt <= cur)
                               or ("LT" in opts and nxt >= cur)):
                    return self._bulk(None)
                if value is None:
                    value = ZSet()
                    self.store[args[0]] = (value, None)
                value.members[member] = nxt
                return self._bulk(repr(nxt))
            # The set is created lazily below, only when a pair
            # actually applies: a ZADD whose options skip every pair
            # leaves no key behind, as in real cinder.
            added = 0
            updated = 0
            for j, score in zip(range(1, len(rest), 2), scores):
                member = rest[j]
                exists = value is not None and member in value.members
                if ("NX" in opts and exists) or ("XX" in opts and not exists):
                    continue
                if exists and (("GT" in opts and score <= value.members[member])
                               or ("LT" in opts and score >= value.members[member])):
                    continue
                if exists and score == value.members[member]:
                    # Re-adding with the current score is a no-op:
                    # not counted, even with CH, as in real cinder.
                    continue
                if value is None:
                    value = ZSet()
                    self.store[args[0]] = (value, None)
                if exists:
                    updated += 1
                else:
                    added += 1
                value.members[member] = score
            return ":%d\r\n" % (added + updated if "CH" in opts else added)
        elif name == "ZCARD" and len(args) == 1:
            value = self._get(args[0])
            if value is None:
                return ":0\r\n"
            if not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            return ":%d\r\n" % len(value.members)
        elif name == "ZSCORE" and len(args) == 2:
            value = self._get(args[0])
            if value is None:
                return self._bulk(None)
            if not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            score = value.members.get(args[1])
            return self._bulk(None if score is None else repr(score))
        elif name == "ZRANK" and len(args) == 2:
            value = self._get(args[0])
            if value is None:
                return self._bulk(None)
            if not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            ordered = value.ordered()
            if args[1] not in ordered:
                return self._bulk(None)
            return ":%d\r\n" % ordered.index(args[1])
        elif name == "ZREM" and len(args) >= 2:
            value = self._get(args[0])
            if value is None:
                return ":0\r\n"
            if not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            removed = 0
            for member in args[1:]:
                if member in value.members:
                    del value.members[member]
                    removed += 1
            return ":%d\r\n" % removed
        elif name == "ZINCRBY" and len(args) == 3:
            try:
                incr = float(args[1])
            except ValueError:
                return "-ERR value is not a valid float\r\n"
            if incr != incr:
                return "-ERR value is not a valid float\r\n"
            value = self._get(args[0])
            if value is not None and not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            cur = value.members.get(args[2], 0.0) if value else 0.0
            nxt = cur + incr
            if nxt != nxt:
                return "-ERR resulting score is not a number (NaN)\r\n"
            if value is None:
                value = ZSet()
                self.store[args[0]] = (value, None)
            value.members[args[2]] = nxt
            return self._bulk(repr(nxt))
        elif name in ("ZRANGE", "ZREVRANGE") and len(args) in (3, 4):
            value = self._get(args[0])
            if value is None:
                return "*0\r\n"
            if not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")
            withscores = False
            if len(args) == 4:
                if args[3].upper() != "WITHSCORES":
                    return "-ERR syntax error\r\n"
                withscores = True
            try:
                start, stop = int(args[1]), int(args[2])
            except ValueError:
                return "-ERR value is not an integer or out of range\r\n"
            ordered = value.ordered()
            if name == "ZREVRANGE":
                ordered.reverse()
            n = len(ordered)
            if start < 0:
                start += n
            if stop < 0:
                stop += n
            if start < 0:
                start = 0
            if stop >= n:
                stop = n - 1
            members = ordered[start:stop + 1] if start <= stop else []
            flat = []
            for member in members:
                flat.append(member)
                if withscores:
                    flat.append(repr(value.members[member]))
            return "*%d\r\n" % len(flat) + "".join(self._bulk(v) for v in flat)
        elif name in ("ZRANGEBYSCORE", "ZREVRANGEBYSCORE") and len(args) >= 3:
            # ZREVRANGEBYSCORE takes its bounds max-first, as in
            # cinder; the bound parsing, WITHSCORES and LIMIT handling
            # are otherwise the same as ZRANGEBYSCORE.
            reverse = name == "ZREVRANGEBYSCORE"
            value = self._get(args[0])
            if value is None:
                return "*0\r\n"
            if not isinstance(value, ZSet):
                return ("-WRONGTYPE Operation against a key holding the "
                        "wrong kind of value\r\n")

            def parse_bound(text):
                # Returns (score, exclusive), or None when the bound
                # is not a number: an optional leading '(' makes it
                # exclusive, the rest is a plain double ("-inf",
                # "+inf", "inf" included), NaN rejected.
                excl = False
                if text.startswith("("):
                    excl = True
                    text = text[1:]
                if not text:
                    return None
                try:
                    score = float(text)
                except ValueError:
                    return None
                if score != score:
                    return None
                return score, excl

            if reverse:
                parsed_max = parse_bound(args[1])
                parsed_min = parse_bound(args[2])
            else:
                parsed_min = parse_bound(args[1])
                parsed_max = parse_bound(args[2])
            if parsed_min is None or parsed_max is None:
                return "-ERR value is not a valid float\r\n"
            lo, lo_excl = parsed_min
            hi, hi_excl = parsed_max
            withscores = False
            offset, count = 0, -1
            i = 3
            seen_limit = False
            while i < len(args):
                opt = args[i].upper()
                if opt == "WITHSCORES":
                    withscores = True
                    i += 1
                elif opt == "LIMIT":
                    if seen_limit or i + 2 >= len(args):
                        return "-ERR syntax error\r\n"
                    try:
                        offset, count = int(args[i + 1]), int(args[i + 2])
                    except ValueError:
                        return "-ERR syntax error\r\n"
                    if offset < 0:
                        return "-ERR syntax error\r\n"
                    seen_limit = True
                    i += 3
                else:
                    return "-ERR syntax error\r\n"
            ordered = value.ordered()
            if reverse:
                ordered.reverse()
            matches = [
                m for m in ordered
                if (value.members[m] > lo if lo_excl
                    else value.members[m] >= lo)
                and (value.members[m] < hi if hi_excl
                     else value.members[m] <= hi)
            ]
            if offset >= len(matches):
                matches = []
            else:
                matches = matches[offset:]
                if count >= 0:
                    matches = matches[:count]
            flat = []
            for member in matches:
                flat.append(member)
                if withscores:
                    flat.append(repr(value.members[member]))
            return "*%d\r\n" % len(flat) + "".join(self._bulk(v) for v in flat)
        elif name == "DEL":
            n = sum(1 for k in args if self._get(k) is not None)
            for k in args:
                self.store.pop(k, None)
            return ":%d\r\n" % n
        elif name == "KEYS":
            pattern = args[0] if args else "*"
            keys = [k for k in list(self.store) if self._get(k) is not None
                    and _glob_match(pattern, k)]
            return "*%d\r\n" % len(keys) + "".join(self._bulk(k) for k in keys)
        elif name == "SCAN":
            # Cinder's cursor is a decimal index into the sorted
            # matching keys; "0" starts (and ends) the walk. COUNT
            # is honored exactly here — real cinder may return a
            # few keys over when one hash bucket holds several
            # matches, which the server-side tests do not depend on.
            if not args or not args[0].isdigit():
                return "-ERR invalid cursor\r\n"
            cursor = int(args[0])
            pattern = "*"
            count = 10
            i = 1
            while i < len(args):
                opt = args[i].upper()
                if opt == "MATCH" and i + 1 < len(args):
                    pattern = args[i + 1]
                    i += 2
                elif opt == "COUNT" and i + 1 < len(args):
                    try:
                        count = int(args[i + 1])
                    except ValueError:
                        return ("-ERR value is not an integer or out "
                                "of range\r\n")
                    i += 2
                else:
                    return "-ERR syntax error\r\n"
            keys = sorted(k for k in list(self.store)
                          if self._get(k) is not None
                          and _glob_match(pattern, k))
            page = keys[cursor:cursor + count]
            nxt = cursor + len(page)
            if nxt >= len(keys):
                nxt = 0
            return ("*2\r\n" + self._bulk(str(nxt))
                    + "*%d\r\n" % len(page)
                    + "".join(self._bulk(k) for k in page))
        elif name == "INCR" and len(args) == 1:
            try:
                return ":%d\r\n" % self._incr(args[0], 1)
            except ValueError:
                return "-ERR value is not an integer or out of range\r\n"
        elif name == "INCRBY" and len(args) == 2:
            try:
                return ":%d\r\n" % self._incr(args[0], int(args[1]))
            except ValueError:
                return "-ERR value is not an integer or out of range\r\n"
        elif name == "TTL" and len(args) == 1:
            entry = self.store.get(args[0])
            if entry is None or (entry[1] is not None and entry[1] <= time.time()):
                self.store.pop(args[0], None)
                return ":-2\r\n"
            elif entry[1] is None:
                return ":-1\r\n"
            return ":%d\r\n" % int(entry[1] - time.time())
        elif name == "EXISTS":
            n = sum(1 for k in args if self._get(k) is not None)
            return ":%d\r\n" % n
        elif name == "EXPIRE" and len(args) == 2:
            try:
                seconds = int(args[1])
            except ValueError:
                return "-ERR value is not an integer or out of range\r\n"
            if seconds < 0:
                return "-ERR invalid expire time in 'expire' command\r\n"
            elif self._get(args[0]) is None:
                return ":0\r\n"
            value, _ = self.store[args[0]]
            self.store[args[0]] = (value, time.time() + seconds)
            return ":1\r\n"
        elif name == "INFO":
            info = (
                "# Server\r\n"
                "cinder_version:0.4.0\r\n"
                "uptime_in_seconds:42\r\n"
                "total_commands_processed:7\r\n"
                "# Keyspace\r\n"
                "keys:%d\r\n" % len(self.store)
            )
            return self._bulk(info)
        return "-ERR unknown command\r\n"

    def _container_len(self, key, kind):
        value = self._get(key)
        if value is None:
            return ":0\r\n"
        if not isinstance(value, kind):
            return ("-WRONGTYPE Operation against a key holding the "
                    "wrong kind of value\r\n")
        return ":%d\r\n" % len(value)

    def _container_items(self, key, kind):
        """LRANGE / SMEMBERS: the container's elements as an array.
        LRANGE args are ignored beyond the key — the fake only ever
        reads the whole list, which is what the watch fingerprints."""
        value = self._get(key)
        if value is None:
            return "*0\r\n"
        if not isinstance(value, kind):
            return ("-WRONGTYPE Operation against a key holding the "
                    "wrong kind of value\r\n")
        items = sorted(value) if kind is set else list(value)
        return "*%d\r\n" % len(items) + "".join(self._bulk(v) for v in items)

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
            names, ["kv_get", "kv_set", "kv_del", "kv_keys", "kv_keys_scan",
                    "kv_incr", "kv_ttl", "kv_exists", "kv_expire",
                    "kv_hset", "kv_hget", "kv_hgetall",
                    "kv_zadd", "kv_zrange", "kv_zrangebyscore", "kv_zcard",
                    "kv_zscore",
                    "kv_zrank", "kv_zrem", "kv_zincrby", "kv_batch"]
        )

    def test_tools_list_advertises_default_budgets(self):
        listed = self._call("tools/list", 2)
        for tool in listed["result"]["tools"]:
            self.assertTrue(
                tool["description"].endswith(
                    " Latency budget: warn >100ms, slow >500ms."
                ),
                tool["name"],
            )
        # tools/list must not rewrite the shared TOOLS definitions.
        from cinder_mcp.tools import TOOLS
        self.assertNotIn("Latency budget", TOOLS[0]["description"])

    def test_tools_list_advertises_per_tool_overrides(self):
        from cinder_mcp.metrics import ToolMetrics
        server = MCPServer(
            RespClient("127.0.0.1", self.fake.port),
            metrics=ToolMetrics(
                budgets={"kv_keys": {"warn_ms": 250, "slow_ms": 1000}}
            ),
        )
        listed = server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        )
        by_name = {t["name"]: t for t in listed["result"]["tools"]}
        self.assertTrue(
            by_name["kv_keys"]["description"].endswith(
                " Latency budget: warn >250ms, slow >1000ms."
            )
        )
        self.assertTrue(
            by_name["kv_get"]["description"].endswith(
                " Latency budget: warn >100ms, slow >500ms."
            )
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

    def test_tools_call_batch_set_get_incr(self):
        reply = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_set", "key": "b:count", "value": "10"},
                {"op": "kv_incr", "key": "b:count", "by": 5},
                {"op": "kv_get", "key": "b:count"},
                {"op": "kv_get", "key": "b:missing"},
            ]},
        })
        summary = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 4)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(
            [r["result"] for r in summary["results"]],
            ["OK", 15, "15", None],
        )
        self.assertEqual(
            [r["op"] for r in summary["results"]],
            ["kv_set", "kv_incr", "kv_get", "kv_get"],
        )
        self.assertTrue(all(r["ok"] for r in summary["results"]))

    def test_tools_call_batch_keeps_going_past_a_failed_op(self):
        reply = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_set", "key": "b:one", "value": "1"},
                # EXPIRE with a negative time is rejected by cinder.
                {"op": "kv_expire", "key": "b:one", "seconds": -5},
                {"op": "kv_get", "key": "b:one"},
                # Unknown op name: recorded, not fatal.
                {"op": "kv_nope", "key": "b:one"},
                # Missing required argument: recorded, not fatal.
                {"op": "kv_get"},
            ]},
        })
        summary = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["failed"], 3)
        self.assertEqual(summary["results"][0]["result"], "OK")
        self.assertFalse(summary["results"][1]["ok"])
        self.assertIn("expire", summary["results"][1]["error"].lower())
        self.assertEqual(summary["results"][2]["result"], "1")
        self.assertIn("kv_nope", summary["results"][3]["error"])
        self.assertIn("missing required argument", summary["results"][4]["error"])

    def test_tools_call_batch_rejects_bad_batches(self):
        for bad in ({}, {"ops": "not-a-list"}, {"ops": []},
                    {"ops": [{"op": "kv_get"}] * 101}):
            reply = self._call("tools/call", 1, {
                "name": "kv_batch", "arguments": bad,
            })
            self.assertIn("error", reply, bad)
            self.assertEqual(reply["error"]["code"], -32602, bad)

    def test_tools_call_batch_rejects_nesting(self):
        reply = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_batch", "ops": [{"op": "kv_get", "key": "x"}]},
                {"op": "kv_get", "key": "x"},
            ]},
        })
        summary = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertIn("unbatchable", summary["results"][0]["error"])

    def _batch_summary(self, arguments):
        reply = self._call("tools/call", 1, {
            "name": "kv_batch", "arguments": arguments,
        })
        self.assertNotIn("error", reply, arguments)
        return json.loads(reply["result"]["content"][0]["text"])

    def test_tools_call_atomic_batch_runs_as_one_transaction(self):
        summary = self._batch_summary({"atomic": True, "ops": [
            {"op": "kv_set", "key": "t:count", "value": "10"},
            {"op": "kv_incr", "key": "t:count", "by": 5},
            {"op": "kv_get", "key": "t:count"},
            {"op": "kv_get", "key": "t:missing"},
        ]})
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 4)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(
            [r["result"] for r in summary["results"]],
            ["OK", 15, "15", None],
        )
        # The ops saw each other's effects inside the transaction:
        # the GET read the value the INCR in the same batch wrote.
        get_reply = self._call("tools/call", 2, {
            "name": "kv_get", "arguments": {"key": "t:count"},
        })
        self.assertEqual(get_reply["result"]["content"][0]["text"], "15")

    def test_tools_call_atomic_batch_keeps_going_past_exec_time_error(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "t:str", "value": "abc"},
        })
        summary = self._batch_summary({"atomic": True, "ops": [
            {"op": "kv_set", "key": "t:one", "value": "1"},
            # INCR on a non-integer fails at EXEC time.
            {"op": "kv_incr", "key": "t:str"},
            {"op": "kv_get", "key": "t:one"},
        ]})
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["results"][0]["result"], "OK")
        self.assertFalse(summary["results"][1]["ok"])
        self.assertIn("integer", summary["results"][1]["error"])
        self.assertEqual(summary["results"][2]["result"], "1")

    def test_tools_call_atomic_batch_with_kv_keys_samples_like_standalone(self):
        self._seed_keys(3)
        summary = self._batch_summary({"atomic": True, "ops": [
            {"op": "kv_keys", "pattern": "key:*"},
        ]})
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 1)
        self.assertEqual(summary["results"][0]["result"], {
            "keys": ["key:000", "key:001", "key:002"],
            "total": 3, "returned": 3, "sampled": False,
        })

    def test_tools_call_atomic_batch_rejects_unqueueable_ops_up_front(self):
        # Nothing runs: the SET before the bad op leaves no trace.
        for bad_ops in (
            [{"op": "kv_set", "key": "t:x", "value": "1"},
             {"op": "kv_keys_scan", "batch_size": 2}],
            [{"op": "kv_set", "key": "t:x", "value": "1"},
             {"op": "kv_nope", "key": "t:x"}],
            [{"op": "kv_set", "key": "t:x", "value": "1"},
             {"op": "kv_get"}],
            [{"op": "kv_set", "key": "t:x", "value": "1"},
             {"op": "kv_keys", "limit": 0}],
        ):
            reply = self._call("tools/call", 1, {
                "name": "kv_batch",
                "arguments": {"atomic": True, "ops": bad_ops},
            })
            self.assertIn("error", reply, bad_ops)
            self.assertEqual(reply["error"]["code"], -32602, bad_ops)
        missing = self._call("tools/call", 2, {
            "name": "kv_get", "arguments": {"key": "t:x"},
        })
        self.assertEqual(missing["result"]["content"][0]["text"], "null")

    def test_tools_call_atomic_batch_rejects_non_boolean_atomic(self):
        reply = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"atomic": "yes", "ops": [
                {"op": "kv_get", "key": "x"},
            ]},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)

    def test_tools_call_plain_batch_summary_reports_atomic_false(self):
        summary = self._batch_summary({"ops": [
            {"op": "kv_get", "key": "x"},
        ]})
        self.assertFalse(summary["atomic"])
        self.assertEqual(summary["ok"], 1)

    def test_tools_call_fast_call_has_no_warning(self):
        reply = self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        self.assertEqual(reply["result"]["content"][0]["text"], "OK")
        self.assertNotIn("warning", reply["result"])

    def test_tools_call_slow_call_includes_warning(self):
        # Tiny budgets, so any real round trip breaches slow.
        from cinder_mcp.metrics import ToolMetrics
        server = MCPServer(
            RespClient("127.0.0.1", self.fake.port),
            metrics=ToolMetrics(default_warn_ms=0.001, default_slow_ms=0.002),
        )
        reply = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                       "params": {"name": "kv_set", "arguments": {"key": "a", "value": "1"}}})
        self.assertEqual(reply["result"]["content"][0]["text"], "OK")
        warning = reply["result"]["warning"]
        self.assertEqual(warning["level"], "slow")
        self.assertEqual(warning["tool"], "kv_set")
        self.assertEqual(warning["threshold_ms"], 0.002)
        self.assertGreater(warning["latency_ms"], 0.002)
        self.assertIn("kv_set took", warning["message"])
        self.assertIn("slow budget of 0.002 ms", warning["message"])

    def test_tools_call_warn_call_includes_warn_warning(self):
        # Warn threshold crossed but slow threshold effectively unreachable.
        from cinder_mcp.metrics import ToolMetrics
        server = MCPServer(
            RespClient("127.0.0.1", self.fake.port),
            metrics=ToolMetrics(default_warn_ms=0.001, default_slow_ms=10 ** 9),
        )
        reply = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                       "params": {"name": "kv_get", "arguments": {"key": "x"}}})
        self.assertEqual(reply["result"]["content"][0]["text"], "null")
        warning = reply["result"]["warning"]
        self.assertEqual(warning["level"], "warn")
        self.assertEqual(warning["tool"], "kv_get")
        self.assertEqual(warning["threshold_ms"], 0.001)
        self.assertGreater(warning["latency_ms"], 0.001)
        self.assertIn("warn budget of 0.001 ms", warning["message"])

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
        self.assertEqual(
            json.loads(keys["result"]["content"][0]["text"]),
            {"keys": ["user:1"], "total": 1, "returned": 1, "sampled": False},
        )

    def _seed_keys(self, count, prefix="key"):
        for i in range(count):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "%s:%03d" % (prefix, i), "value": "v"},
            })

    def _keys_result(self, arguments):
        reply = self._call("tools/call", 1, {
            "name": "kv_keys", "arguments": arguments,
        })
        self.assertNotIn("error", reply, arguments)
        return json.loads(reply["result"]["content"][0]["text"])

    def test_kv_keys_small_keyspace_returns_everything_unsampled(self):
        self._seed_keys(3)
        data = self._keys_result({})
        self.assertEqual(data, {
            "keys": ["key:000", "key:001", "key:002"],
            "total": 3, "returned": 3, "sampled": False,
        })

    def test_kv_keys_large_keyspace_returns_bounded_deterministic_sample(self):
        self._seed_keys(150)
        data = self._keys_result({})
        self.assertEqual(data["total"], 150)
        self.assertEqual(data["returned"], 100)
        self.assertTrue(data["sampled"])
        self.assertEqual(len(data["keys"]), 100)
        self.assertEqual(data["keys"], sorted(data["keys"]))
        # Same call again: the identical sample, not a fresh draw.
        again = self._keys_result({})
        self.assertEqual(again, data)
        # The sample is the SHA-256-seeded one, not the first 100 keys.
        all_keys = ["key:%03d" % i for i in range(150)]
        expected = sorted(
            sorted(
                all_keys,
                key=lambda k: hashlib.sha256((":%s" % k).encode()).hexdigest(),
            )[:100]
        )
        self.assertEqual(data["keys"], expected)
        self.assertNotEqual(data["keys"], all_keys[:100])

    def test_kv_keys_explicit_limit_bounds_the_sample(self):
        self._seed_keys(150)
        data = self._keys_result({"limit": 10})
        self.assertEqual(data["total"], 150)
        self.assertEqual(data["returned"], 10)
        self.assertTrue(data["sampled"])
        self.assertEqual(len(data["keys"]), 10)

    def test_kv_keys_full_opt_in_returns_the_whole_keyspace(self):
        self._seed_keys(150)
        data = self._keys_result({"full": True})
        self.assertEqual(data["total"], 150)
        self.assertEqual(data["returned"], 150)
        self.assertFalse(data["sampled"])
        self.assertEqual(
            data["keys"], ["key:%03d" % i for i in range(150)])
        # full wins over a small limit.
        data = self._keys_result({"full": True, "limit": 5})
        self.assertEqual(data["returned"], 150)
        self.assertFalse(data["sampled"])

    def test_kv_keys_seed_changes_the_sample(self):
        self._seed_keys(150)
        default = self._keys_result({"limit": 5})
        other = self._keys_result({"limit": 5, "seed": "audit"})
        self.assertNotEqual(other["keys"], default["keys"])
        # Same seed again: the same sample.
        self.assertEqual(
            self._keys_result({"limit": 5, "seed": "audit"}), other)

    def test_kv_keys_rejects_bad_arguments(self):
        self._seed_keys(2)
        for bad in ({"limit": 0}, {"limit": -1}, {"limit": 10001},
                    {"limit": "ten"}, {"limit": True},
                    {"full": "yes"}, {"seed": 7}):
            reply = self._call("tools/call", 1, {
                "name": "kv_keys", "arguments": bad,
            })
            self.assertIn("error", reply, bad)
            self.assertEqual(reply["error"]["code"], -32602, bad)

    def test_kv_keys_in_batch_returns_the_sampled_form(self):
        self._seed_keys(3)
        reply = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_keys", "pattern": "key:*"},
            ]},
        })
        summary = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 1)
        self.assertEqual(summary["results"][0]["result"], {
            "keys": ["key:000", "key:001", "key:002"],
            "total": 3, "returned": 3, "sampled": False,
        })

    def _scan_result(self, arguments):
        reply = self._call("tools/call", 1, {
            "name": "kv_keys_scan", "arguments": arguments,
        })
        self.assertNotIn("error", reply, arguments)
        return json.loads(reply["result"]["content"][0]["text"])

    def test_kv_keys_scan_pages_through_the_keyspace(self):
        self._seed_keys(250)
        seen = []
        cursor = ""
        pages = 0
        while True:
            data = self._scan_result({"batch_size": 100, "cursor": cursor})
            self.assertEqual(data["batch_size"], 100)
            seen.extend(data["keys"])
            pages += 1
            self.assertLessEqual(pages, 10)
            if data["done"]:
                self.assertEqual(data["cursor"], "")
                break
            # The cursor is cinder's opaque decimal cursor: pass it
            # back verbatim, never read a key out of it.
            self.assertNotEqual(data["cursor"], "")
            self.assertTrue(data["cursor"].isdigit(), data["cursor"])
            cursor = data["cursor"]
        self.assertEqual(pages, 3)
        self.assertEqual(seen, ["key:%03d" % i for i in range(250)])
        # A cursor returned by one page resumes the walk: the first
        # five keys come back, then the next five after it.
        first = self._scan_result({"batch_size": 5})
        self.assertEqual(
            first["keys"], ["key:%03d" % i for i in range(5)])
        self.assertFalse(first["done"])
        second = self._scan_result(
            {"batch_size": 5, "cursor": first["cursor"]})
        self.assertEqual(
            second["keys"], ["key:%03d" % i for i in range(5, 10)])
        self.assertFalse(second["done"])
        # The pattern filters, and a small keyspace finishes in one page.
        data = self._scan_result({"pattern": "key:00*"})
        self.assertEqual(
            data["keys"], ["key:%03d" % i for i in range(10)])
        self.assertTrue(data["done"])
        self.assertEqual(data["cursor"], "")
        # An empty keyspace is done at once, with no keys.
        empty = self._scan_result({"pattern": "nope:*"})
        self.assertEqual(
            empty, {"keys": [], "cursor": "", "done": True, "batch_size": 100})

    def test_kv_keys_scan_rejects_bad_arguments(self):
        self._seed_keys(2)
        for bad in ({"batch_size": 0}, {"batch_size": -1},
                    {"batch_size": 1001}, {"batch_size": "ten"},
                    {"batch_size": True}, {"cursor": 7},
                    {"cursor": "key:099"}, {"cursor": "abc"}):
            reply = self._call("tools/call", 1, {
                "name": "kv_keys_scan", "arguments": bad,
            })
            self.assertIn("error", reply, bad)
            self.assertEqual(reply["error"]["code"], -32602, bad)

    def test_kv_keys_scan_in_batch(self):
        self._seed_keys(3)
        reply = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_keys_scan", "batch_size": 2},
            ]},
        })
        summary = json.loads(reply["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 1)
        self.assertEqual(summary["results"][0]["result"], {
            "keys": ["key:000", "key:001"],
            "cursor": "2",
            "done": False,
            "batch_size": 2,
        })

    def test_iter_keys_yields_bounded_batches_covering_every_key(self):
        from cinder_mcp.scan import iter_keys

        class StubClient:
            """Speaks cinder's SCAN: the cursor is a decimal index
            into the sorted matching keys, COUNT caps the page.
            KEYS is refused outright — iter_keys must not call it."""

            def __init__(self, keys):
                self.keys = sorted(keys)

            def command(self, *args):
                if args[0] == "KEYS":
                    raise AssertionError("iter_keys must use SCAN, not KEYS")
                assert args[0] == "SCAN", args
                cursor = int(args[1])
                pattern = args[args.index("MATCH") + 1]
                count = int(args[args.index("COUNT") + 1])
                matches = [k for k in self.keys
                           if _glob_match(pattern, k)]
                page = matches[cursor:cursor + count]
                nxt = cursor + len(page)
                return [str(0 if nxt >= len(matches) else nxt), page]

        keys = ["key:%03d" % i for i in range(250)]
        batches = list(iter_keys(StubClient(keys), "key:*", batch_size=100))
        self.assertEqual([len(b) for b in batches], [100, 100, 50])
        self.assertEqual([k for b in batches for k in b], keys)
        # A batch size larger than the keyspace is a single batch.
        self.assertEqual(list(iter_keys(StubClient(keys), batch_size=1000)), [keys])
        # An empty keyspace yields no batches at all.
        self.assertEqual(list(iter_keys(StubClient([]))), [])

    def test_iter_keys_dedupes_a_key_scan_returns_twice(self):
        from cinder_mcp.scan import iter_keys

        class ScriptedClient:
            """SCAN returns key "e" on both pages, as a table resize
            mid-walk can: iter_keys must yield it exactly once."""

            def __init__(self):
                self.calls = 0

            def command(self, *args):
                assert args[0] == "SCAN", args
                self.calls += 1
                if self.calls == 1:
                    return ["5", ["a", "b", "c", "d", "e"]]
                return ["0", ["e", "f", "g"]]

        batches = list(iter_keys(ScriptedClient(), "*", batch_size=100))
        self.assertEqual(batches, [["a", "b", "c", "d", "e", "f", "g"]])

    def test_iter_keys_continues_past_an_empty_scan_page(self):
        from cinder_mcp.scan import iter_keys

        class ScriptedClient:
            """One SCAN call returns no keys with a live cursor: the
            walk continues instead of stopping or looping forever."""

            def __init__(self):
                self.calls = 0

            def command(self, *args):
                assert args[0] == "SCAN", args
                self.calls += 1
                if self.calls == 1:
                    return ["3", []]
                return ["0", ["x", "y"]]

        batches = list(iter_keys(ScriptedClient(), "*", batch_size=100))
        self.assertEqual(batches, [["x", "y"]])

    def test_iter_keys_rejects_bad_batch_size(self):
        from cinder_mcp.scan import iter_keys

        class StubClient:
            def command(self, *args):
                return ["a"]

        for bad in (0, -1, 1001, "ten", True):
            with self.assertRaises(ValueError, msg=bad):
                list(iter_keys(StubClient(), batch_size=bad))

    def test_scan_batch_rejects_a_malformed_scan_reply(self):
        from cinder_mcp.scan import scan_batch

        class BadReplyClient:
            def __init__(self, reply):
                self.reply = reply

            def command(self, *args):
                return self.reply

        for bad in (["not-a-cursor", []], ["0", "not-a-list"],
                    ["0"], "keys", None):
            with self.assertRaises(ValueError, msg=bad):
                scan_batch(BadReplyClient(bad))

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

    def test_tools_call_hash_set_get_getall(self):
        added = self._call("tools/call", 1, {
            "name": "kv_hset",
            "arguments": {"key": "user:1",
                          "fields": {"name": "mo", "city": "philly"}},
        })
        self.assertEqual(added["result"]["content"][0]["text"], "2")
        # Setting a new field adds 1; updating an existing one adds 0.
        updated = self._call("tools/call", 2, {
            "name": "kv_hset",
            "arguments": {"key": "user:1",
                          "fields": {"city": "jeddah", "age": "24"}},
        })
        self.assertEqual(updated["result"]["content"][0]["text"], "1")
        field = self._call("tools/call", 3, {
            "name": "kv_hget",
            "arguments": {"key": "user:1", "field": "city"},
        })
        self.assertEqual(field["result"]["content"][0]["text"], "jeddah")
        missing_field = self._call("tools/call", 4, {
            "name": "kv_hget",
            "arguments": {"key": "user:1", "field": "nope"},
        })
        self.assertEqual(missing_field["result"]["content"][0]["text"], "null")
        missing_key = self._call("tools/call", 5, {
            "name": "kv_hget", "arguments": {"key": "ghost", "field": "x"},
        })
        self.assertEqual(missing_key["result"]["content"][0]["text"], "null")
        all_fields = self._call("tools/call", 6, {
            "name": "kv_hgetall", "arguments": {"key": "user:1"},
        })
        self.assertEqual(
            json.loads(all_fields["result"]["content"][0]["text"]),
            {"name": "mo", "city": "jeddah", "age": "24"},
        )
        empty = self._call("tools/call", 7, {
            "name": "kv_hgetall", "arguments": {"key": "ghost"},
        })
        self.assertEqual(empty["result"]["content"][0]["text"], "{}")

    def test_tools_call_hash_rejects_bad_arguments(self):
        empty_fields = self._call("tools/call", 1, {
            "name": "kv_hset",
            "arguments": {"key": "h", "fields": {}},
        })
        self.assertIn("error", empty_fields)
        missing_fields = self._call("tools/call", 2, {
            "name": "kv_hset", "arguments": {"key": "h"},
        })
        self.assertIn("error", missing_fields)
        non_string_value = self._call("tools/call", 3, {
            "name": "kv_hset",
            "arguments": {"key": "h", "fields": {"f": 7}},
        })
        self.assertIn("error", non_string_value)

    def test_tools_call_hash_wrong_type_errors(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "plain", "value": "v"},
        })
        hset = self._call("tools/call", 2, {
            "name": "kv_hset",
            "arguments": {"key": "plain", "fields": {"f": "v"}},
        })
        self.assertIn("error", hset)
        hget = self._call("tools/call", 3, {
            "name": "kv_hget",
            "arguments": {"key": "plain", "field": "f"},
        })
        self.assertIn("error", hget)
        hgetall = self._call("tools/call", 4, {
            "name": "kv_hgetall", "arguments": {"key": "plain"},
        })
        self.assertIn("error", hgetall)

    def test_tools_call_hash_in_plain_and_atomic_batch(self):
        plain = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_hset", "key": "h",
                 "fields": {"a": "1", "b": "2"}},
                {"op": "kv_hget", "key": "h", "field": "a"},
                {"op": "kv_hgetall", "key": "h"},
            ]},
        })
        summary = json.loads(plain["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 3)
        self.assertEqual(summary["results"][0]["result"], 2)
        self.assertEqual(summary["results"][1]["result"], "1")
        self.assertEqual(summary["results"][2]["result"], {"a": "1", "b": "2"})
        atomic = self._call("tools/call", 2, {
            "name": "kv_batch",
            "arguments": {"atomic": True, "ops": [
                {"op": "kv_hset", "key": "h2",
                 "fields": {"x": "9"}},
                {"op": "kv_hgetall", "key": "h2"},
            ]},
        })
        summary = json.loads(atomic["result"]["content"][0]["text"])
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["results"][0]["result"], 1)
        self.assertEqual(summary["results"][1]["result"], {"x": "9"})

    def test_tools_call_zadd_zrange(self):
        added = self._call("tools/call", 1, {
            "name": "kv_zadd",
            "arguments": {"key": "leaderboard",
                          "members": {"amy": 10, "bo": 20, "cy": 15}},
        })
        self.assertEqual(added["result"]["content"][0]["text"], "3")
        # Re-adding a member with its current score adds 0;
        # updating a member's score adds 0 too.
        same = self._call("tools/call", 2, {
            "name": "kv_zadd",
            "arguments": {"key": "leaderboard",
                          "members": {"amy": 10}},
        })
        self.assertEqual(same["result"]["content"][0]["text"], "0")
        updated = self._call("tools/call", 3, {
            "name": "kv_zadd",
            "arguments": {"key": "leaderboard",
                          "members": {"amy": 25, "dan": 5}},
        })
        self.assertEqual(updated["result"]["content"][0]["text"], "1")
        # Lowest score first: dan 5, cy 15, bo 20, amy 25.
        ranged = self._call("tools/call", 4, {
            "name": "kv_zrange",
            "arguments": {"key": "leaderboard"},
        })
        self.assertEqual(
            json.loads(ranged["result"]["content"][0]["text"]),
            ["dan", "cy", "bo", "amy"],
        )
        scored = self._call("tools/call", 5, {
            "name": "kv_zrange",
            "arguments": {"key": "leaderboard", "start": 1, "stop": 2,
                          "withscores": True},
        })
        self.assertEqual(
            json.loads(scored["result"]["content"][0]["text"]),
            [{"member": "cy", "score": 15.0},
             {"member": "bo", "score": 20.0}],
        )
        reversed_ = self._call("tools/call", 6, {
            "name": "kv_zrange",
            "arguments": {"key": "leaderboard", "rev": True},
        })
        self.assertEqual(
            json.loads(reversed_["result"]["content"][0]["text"]),
            ["amy", "bo", "cy", "dan"],
        )
        # Negative indices count from the end.
        tail = self._call("tools/call", 7, {
            "name": "kv_zrange",
            "arguments": {"key": "leaderboard", "start": -2, "stop": -1},
        })
        self.assertEqual(
            json.loads(tail["result"]["content"][0]["text"]),
            ["bo", "amy"],
        )
        missing = self._call("tools/call", 8, {
            "name": "kv_zrange", "arguments": {"key": "ghost"},
        })
        self.assertEqual(missing["result"]["content"][0]["text"], "[]")

    def test_tools_call_zadd_zrange_rejects_bad_arguments(self):
        cases = [
            # kv_zadd: empty members, missing members, non-number score.
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {}}},
            {"name": "kv_zadd", "arguments": {"key": "z"}},
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"m": "high"}}},
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"m": True}}},
            # kv_zrange: bad start/stop/withscores/rev types.
            {"name": "kv_zrange",
             "arguments": {"key": "z", "start": "0"}},
            {"name": "kv_zrange",
             "arguments": {"key": "z", "stop": 1.5}},
            {"name": "kv_zrange",
             "arguments": {"key": "z", "withscores": "yes"}},
            {"name": "kv_zrange",
             "arguments": {"key": "z", "rev": 1}},
            {"name": "kv_zrange", "arguments": {}},
        ]
        for i, call in enumerate(cases):
            reply = self._call("tools/call", i + 1, call)
            self.assertIn("error", reply, call)
            self.assertEqual(reply["error"]["code"], -32602, call)

    def test_tools_call_zrange_rejects_too_wide_a_range(self):
        self._call("tools/call", 1, {
            "name": "kv_zadd",
            "arguments": {"key": "z",
                          "members": {"a": 1, "b": 2, "c": 3}},
        })
        reply = self._call("tools/call", 2, {
            "name": "kv_zrange",
            "arguments": {"key": "z", "start": 0, "stop": 10000},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        # A negative stop over a small set is fine: the window is
        # the set's size, not the raw index span.
        narrow = self._call("tools/call", 3, {
            "name": "kv_zrange",
            "arguments": {"key": "z", "start": 0, "stop": -1},
        })
        self.assertEqual(
            json.loads(narrow["result"]["content"][0]["text"]),
            ["a", "b", "c"],
        )

    def test_tools_call_zadd_zrange_wrong_type_errors(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "plain", "value": "v"},
        })
        zadd = self._call("tools/call", 2, {
            "name": "kv_zadd",
            "arguments": {"key": "plain", "members": {"m": 1}},
        })
        self.assertIn("error", zadd)
        zrange = self._call("tools/call", 3, {
            "name": "kv_zrange", "arguments": {"key": "plain"},
        })
        self.assertIn("error", zrange)

    def test_tools_call_zadd_zrange_in_plain_and_atomic_batch(self):
        plain = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_zadd", "key": "z",
                 "members": {"a": 1, "b": 2}},
                {"op": "kv_zrange", "key": "z"},
                {"op": "kv_zrange", "key": "z", "withscores": True},
            ]},
        })
        summary = json.loads(plain["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 3)
        self.assertEqual(summary["results"][0]["result"], 2)
        self.assertEqual(summary["results"][1]["result"], ["a", "b"])
        self.assertEqual(summary["results"][2]["result"], [
            {"member": "a", "score": 1.0},
            {"member": "b", "score": 2.0},
        ])
        atomic = self._call("tools/call", 2, {
            "name": "kv_batch",
            "arguments": {"atomic": True, "ops": [
                {"op": "kv_zadd", "key": "z2",
                 "members": {"x": 9, "y": 3}},
                {"op": "kv_zrange", "key": "z2", "rev": True,
                 "withscores": True},
            ]},
        })
        summary = json.loads(atomic["result"]["content"][0]["text"])
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["results"][0]["result"], 2)
        self.assertEqual(summary["results"][1]["result"], [
            {"member": "x", "score": 9.0},
            {"member": "y", "score": 3.0},
        ])

    def test_tools_call_zrangebyscore(self):
        self._call("tools/call", 1, {
            "name": "kv_zadd",
            "arguments": {"key": "leaderboard",
                          "members": {"amy": 10, "bo": 20, "cy": 15,
                                      "dan": 5, "eve": 20}},
        })
        # No bounds: the whole set, lowest score first (ties by
        # member name: bo before eve at 20).
        whole = self._call("tools/call", 2, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard"},
        })
        self.assertEqual(
            json.loads(whole["result"]["content"][0]["text"]),
            ["dan", "amy", "cy", "bo", "eve"],
        )
        # Numeric bounds are inclusive by default.
        bounded = self._call("tools/call", 3, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "min": 10, "max": 20},
        })
        self.assertEqual(
            json.loads(bounded["result"]["content"][0]["text"]),
            ["amy", "cy", "bo", "eve"],
        )
        # A leading '(' makes a bound exclusive.
        exclusive = self._call("tools/call", 4, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "min": "(10",
                          "max": "(20"},
        })
        self.assertEqual(
            json.loads(exclusive["result"]["content"][0]["text"]),
            ["cy"],
        )
        # -inf / +inf as strings mean no bound on that side.
        open_ended = self._call("tools/call", 5, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "min": "-inf",
                          "max": "15"},
        })
        self.assertEqual(
            json.loads(open_ended["result"]["content"][0]["text"]),
            ["dan", "amy", "cy"],
        )
        # withscores returns member/score objects.
        scored = self._call("tools/call", 6, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "min": 15,
                          "withscores": True},
        })
        self.assertEqual(
            json.loads(scored["result"]["content"][0]["text"]),
            [{"member": "cy", "score": 15.0},
             {"member": "bo", "score": 20.0},
             {"member": "eve", "score": 20.0}],
        )
        # rev reads highest score first; bounds are still min, max.
        reversed_ = self._call("tools/call", 7, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "rev": True,
                          "max": 15},
        })
        self.assertEqual(
            json.loads(reversed_["result"]["content"][0]["text"]),
            ["cy", "amy", "dan"],
        )
        # LIMIT pages through the matches.
        page = self._call("tools/call", 8, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "offset": 1,
                          "count": 2},
        })
        self.assertEqual(
            json.loads(page["result"]["content"][0]["text"]),
            ["amy", "cy"],
        )
        # A range with no matches, and a missing key, both return [].
        empty = self._call("tools/call", 9, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "leaderboard", "min": 100},
        })
        self.assertEqual(empty["result"]["content"][0]["text"], "[]")
        missing = self._call("tools/call", 10, {
            "name": "kv_zrangebyscore", "arguments": {"key": "ghost"},
        })
        self.assertEqual(missing["result"]["content"][0]["text"], "[]")

    def test_tools_call_zrangebyscore_rejects_bad_arguments(self):
        cases = [
            # Bad bounds: not a number, empty exclusive, NaN, bool.
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "min": "high"}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "min": "("}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "min": "nan"}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "min": float("nan")}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "max": True}},
            # Bad flags and paging: wrong types, negative offset,
            # count below -1, count over the 1000-member cap.
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "withscores": "yes"}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "rev": 1}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "offset": -1}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "offset": "1"}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "count": 1.5}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "count": -2}},
            {"name": "kv_zrangebyscore",
             "arguments": {"key": "z", "count": 1001}},
            {"name": "kv_zrangebyscore", "arguments": {}},
        ]
        for i, call in enumerate(cases):
            reply = self._call("tools/call", i + 1, call)
            self.assertIn("error", reply, call)
            self.assertEqual(reply["error"]["code"], -32602, call)

    def test_tools_call_zrangebyscore_rejects_too_wide_a_range(self):
        self._call("tools/call", 1, {
            "name": "kv_zadd",
            "arguments": {"key": "big",
                          "members": {"m%04d" % i: i
                                      for i in range(1001)}},
        })
        # No limit over 1001 matches fails instead of truncating.
        reply = self._call("tools/call", 2, {
            "name": "kv_zrangebyscore", "arguments": {"key": "big"},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        # The same range with an explicit count inside the cap works.
        page = self._call("tools/call", 3, {
            "name": "kv_zrangebyscore",
            "arguments": {"key": "big", "count": 1000},
        })
        self.assertEqual(
            len(json.loads(page["result"]["content"][0]["text"])), 1000,
        )

    def test_tools_call_zrangebyscore_wrong_type_errors(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "plain", "value": "v"},
        })
        reply = self._call("tools/call", 2, {
            "name": "kv_zrangebyscore", "arguments": {"key": "plain"},
        })
        self.assertIn("error", reply)

    def test_tools_call_zrangebyscore_in_plain_and_atomic_batch(self):
        plain = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_zadd", "key": "z",
                 "members": {"a": 1, "b": 2, "c": 3}},
                {"op": "kv_zrangebyscore", "key": "z",
                 "min": 2},
                {"op": "kv_zrangebyscore", "key": "z",
                 "min": "(1", "max": 3, "withscores": True},
                {"op": "kv_zrangebyscore", "key": "z",
                 "offset": 1, "count": 1},
            ]},
        })
        summary = json.loads(plain["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 4)
        self.assertEqual(summary["results"][0]["result"], 3)
        self.assertEqual(summary["results"][1]["result"], ["b", "c"])
        self.assertEqual(summary["results"][2]["result"], [
            {"member": "b", "score": 2.0},
            {"member": "c", "score": 3.0},
        ])
        self.assertEqual(summary["results"][3]["result"], ["b"])
        atomic = self._call("tools/call", 2, {
            "name": "kv_batch",
            "arguments": {"atomic": True, "ops": [
                {"op": "kv_zadd", "key": "z2",
                 "members": {"x": 9, "y": 3}},
                {"op": "kv_zrangebyscore", "key": "z2", "rev": True,
                 "withscores": True},
            ]},
        })
        summary = json.loads(atomic["result"]["content"][0]["text"])
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["results"][0]["result"], 2)
        self.assertEqual(summary["results"][1]["result"], [
            {"member": "x", "score": 9.0},
            {"member": "y", "score": 3.0},
        ])
        # A too-wide range inside an atomic batch is recorded as
        # that op's error in place, while the rest still run.
        wide = self._call("tools/call", 3, {
            "name": "kv_batch",
            "arguments": {"atomic": True, "ops": [
                {"op": "kv_zadd", "key": "big",
                 "members": {"m%04d" % i: i for i in range(1001)}},
                {"op": "kv_zrangebyscore", "key": "big"},
                {"op": "kv_zcard", "key": "big"},
            ]},
        })
        summary = json.loads(wide["result"]["content"][0]["text"])
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 2)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["results"][0]["result"], 1001)
        self.assertFalse(summary["results"][1]["ok"])
        self.assertIn("1000", summary["results"][1]["error"])
        self.assertEqual(summary["results"][2]["result"], 1001)

    def test_tools_call_zcard_zscore_zrank_zrem_zincrby(self):
        self._call("tools/call", 1, {
            "name": "kv_zadd",
            "arguments": {"key": "leaderboard",
                          "members": {"amy": 10, "bo": 20, "cy": 15}},
        })
        card = self._call("tools/call", 2, {
            "name": "kv_zcard", "arguments": {"key": "leaderboard"},
        })
        self.assertEqual(card["result"]["content"][0]["text"], "3")
        ghost_card = self._call("tools/call", 3, {
            "name": "kv_zcard", "arguments": {"key": "ghost"},
        })
        self.assertEqual(ghost_card["result"]["content"][0]["text"], "0")
        score = self._call("tools/call", 4, {
            "name": "kv_zscore",
            "arguments": {"key": "leaderboard", "member": "cy"},
        })
        self.assertEqual(score["result"]["content"][0]["text"], "15.0")
        # A missing member — or a missing key — scores null.
        missing_member = self._call("tools/call", 5, {
            "name": "kv_zscore",
            "arguments": {"key": "leaderboard", "member": "dan"},
        })
        self.assertEqual(missing_member["result"]["content"][0]["text"], "null")
        missing_key = self._call("tools/call", 6, {
            "name": "kv_zscore",
            "arguments": {"key": "ghost", "member": "dan"},
        })
        self.assertEqual(missing_key["result"]["content"][0]["text"], "null")
        # Lowest score first: amy 0, cy 1, bo 2.
        for i, (member, rank) in enumerate(
            [("amy", "0"), ("cy", "1"), ("bo", "2")]
        ):
            ranked = self._call("tools/call", 7 + i, {
                "name": "kv_zrank",
                "arguments": {"key": "leaderboard", "member": member},
            })
            self.assertEqual(ranked["result"]["content"][0]["text"], rank)
        ghost_rank = self._call("tools/call", 10, {
            "name": "kv_zrank",
            "arguments": {"key": "leaderboard", "member": "dan"},
        })
        self.assertEqual(ghost_rank["result"]["content"][0]["text"], "null")
        # ZINCRBY bumps an existing member and creates a new one.
        bumped = self._call("tools/call", 11, {
            "name": "kv_zincrby",
            "arguments": {"key": "leaderboard", "increment": 5,
                          "member": "amy"},
        })
        self.assertEqual(bumped["result"]["content"][0]["text"], "15.0")
        created = self._call("tools/call", 12, {
            "name": "kv_zincrby",
            "arguments": {"key": "leaderboard", "increment": 7,
                          "member": "dan"},
        })
        self.assertEqual(created["result"]["content"][0]["text"], "7.0")
        # The bump reorders the ranks: dan 7, amy 15, cy 15, bo 20.
        reranked = self._call("tools/call", 13, {
            "name": "kv_zrank",
            "arguments": {"key": "leaderboard", "member": "amy"},
        })
        self.assertEqual(reranked["result"]["content"][0]["text"], "1")
        # ZREM removes several at once and counts only the ones there.
        removed = self._call("tools/call", 14, {
            "name": "kv_zrem",
            "arguments": {"key": "leaderboard",
                          "members": ["amy", "dan", "ghost"]},
        })
        self.assertEqual(removed["result"]["content"][0]["text"], "2")
        card_after = self._call("tools/call", 15, {
            "name": "kv_zcard", "arguments": {"key": "leaderboard"},
        })
        self.assertEqual(card_after["result"]["content"][0]["text"], "2")
        removed_none = self._call("tools/call", 16, {
            "name": "kv_zrem",
            "arguments": {"key": "leaderboard", "members": ["ghost"]},
        })
        self.assertEqual(removed_none["result"]["content"][0]["text"], "0")

    def test_tools_call_zset_new_tools_reject_bad_arguments(self):
        cases = [
            # Missing required arguments.
            {"name": "kv_zcard", "arguments": {}},
            {"name": "kv_zscore", "arguments": {"key": "z"}},
            {"name": "kv_zscore", "arguments": {"member": "m"}},
            {"name": "kv_zrank", "arguments": {"key": "z"}},
            {"name": "kv_zrem", "arguments": {"key": "z"}},
            {"name": "kv_zincrby", "arguments": {"key": "z", "member": "m"}},
            {"name": "kv_zincrby",
             "arguments": {"key": "z", "increment": 1}},
            # kv_zrem: members must be a non-empty list of strings.
            {"name": "kv_zrem",
             "arguments": {"key": "z", "members": []}},
            {"name": "kv_zrem",
             "arguments": {"key": "z", "members": "m"}},
            {"name": "kv_zrem",
             "arguments": {"key": "z", "members": [1]}},
            # kv_zincrby: the increment must be a number, never NaN.
            {"name": "kv_zincrby",
             "arguments": {"key": "z", "increment": "1", "member": "m"}},
            {"name": "kv_zincrby",
             "arguments": {"key": "z", "increment": True, "member": "m"}},
            {"name": "kv_zincrby",
             "arguments": {"key": "z", "increment": float("nan"),
                           "member": "m"}},
            # kv_zadd options: conflicting flags, a non-boolean flag,
            # and INCR with more than one member.
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"a": 1},
                           "nx": True, "xx": True}},
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"a": 1},
                           "gt": True, "lt": True}},
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"a": 1},
                           "nx": True, "gt": True}},
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"a": 1},
                           "nx": "yes"}},
            {"name": "kv_zadd",
             "arguments": {"key": "z", "members": {"a": 1, "b": 2},
                           "incr": True}},
        ]
        for i, call in enumerate(cases):
            reply = self._call("tools/call", i + 1, call)
            self.assertIn("error", reply, call)
            self.assertEqual(reply["error"]["code"], -32602, call)

    def test_tools_call_zadd_options(self):
        self._call("tools/call", 1, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 1, "b": 2}},
        })
        # NX adds only members not already present.
        nx = self._call("tools/call", 2, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 5, "c": 3},
                          "nx": True},
        })
        self.assertEqual(nx["result"]["content"][0]["text"], "1")
        score_a = self._call("tools/call", 3, {
            "name": "kv_zscore", "arguments": {"key": "z", "member": "a"},
        })
        self.assertEqual(score_a["result"]["content"][0]["text"], "1.0")
        # XX updates only members already present.
        xx = self._call("tools/call", 4, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 5, "d": 4},
                          "xx": True},
        })
        self.assertEqual(xx["result"]["content"][0]["text"], "0")
        score_a = self._call("tools/call", 5, {
            "name": "kv_zscore", "arguments": {"key": "z", "member": "a"},
        })
        self.assertEqual(score_a["result"]["content"][0]["text"], "5.0")
        ghost = self._call("tools/call", 6, {
            "name": "kv_zscore", "arguments": {"key": "z", "member": "d"},
        })
        self.assertEqual(ghost["result"]["content"][0]["text"], "null")
        # GT only moves a score up, LT only moves it down.
        gt_skip = self._call("tools/call", 7, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 3}, "gt": True},
        })
        self.assertEqual(gt_skip["result"]["content"][0]["text"], "0")
        gt_apply = self._call("tools/call", 8, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 9}, "gt": True},
        })
        self.assertEqual(gt_apply["result"]["content"][0]["text"], "0")
        score_a = self._call("tools/call", 9, {
            "name": "kv_zscore", "arguments": {"key": "z", "member": "a"},
        })
        self.assertEqual(score_a["result"]["content"][0]["text"], "9.0")
        lt_skip = self._call("tools/call", 10, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 20}, "lt": True},
        })
        self.assertEqual(lt_skip["result"]["content"][0]["text"], "0")
        lt_apply = self._call("tools/call", 11, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 1}, "lt": True},
        })
        self.assertEqual(lt_apply["result"]["content"][0]["text"], "0")
        score_a = self._call("tools/call", 12, {
            "name": "kv_zscore", "arguments": {"key": "z", "member": "a"},
        })
        self.assertEqual(score_a["result"]["content"][0]["text"], "1.0")
        # CH counts updates as well as additions.
        ch = self._call("tools/call", 13, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 5, "e": 2},
                          "ch": True},
        })
        self.assertEqual(ch["result"]["content"][0]["text"], "2")
        plain = self._call("tools/call", 14, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 5, "e": 2}},
        })
        self.assertEqual(plain["result"]["content"][0]["text"], "0")
        # INCR returns the member's new score as a number.
        incr = self._call("tools/call", 15, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 10},
                          "incr": True},
        })
        self.assertEqual(incr["result"]["content"][0]["text"], "15.0")
        # INCR with a condition that rejects the update returns null.
        incr_nx = self._call("tools/call", 16, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": 1},
                          "incr": True, "nx": True},
        })
        self.assertEqual(incr_nx["result"]["content"][0]["text"], "null")
        incr_xx = self._call("tools/call", 17, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"missing": 1},
                          "incr": True, "xx": True},
        })
        self.assertEqual(incr_xx["result"]["content"][0]["text"], "null")
        # INCR with GT that the result fails also returns null.
        incr_gt = self._call("tools/call", 18, {
            "name": "kv_zadd",
            "arguments": {"key": "z", "members": {"a": -5},
                          "incr": True, "gt": True},
        })
        self.assertEqual(incr_gt["result"]["content"][0]["text"], "null")
        score_a = self._call("tools/call", 19, {
            "name": "kv_zscore", "arguments": {"key": "z", "member": "a"},
        })
        self.assertEqual(score_a["result"]["content"][0]["text"], "15.0")

    def test_tools_call_zset_new_tools_wrong_type_errors(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "plain", "value": "v"},
        })
        for i, call in enumerate([
            {"name": "kv_zcard", "arguments": {"key": "plain"}},
            {"name": "kv_zscore",
             "arguments": {"key": "plain", "member": "m"}},
            {"name": "kv_zrank",
             "arguments": {"key": "plain", "member": "m"}},
            {"name": "kv_zrem",
             "arguments": {"key": "plain", "members": ["m"]}},
            {"name": "kv_zincrby",
             "arguments": {"key": "plain", "increment": 1, "member": "m"}},
        ]):
            reply = self._call("tools/call", i + 2, call)
            self.assertIn("error", reply, call)
            self.assertEqual(reply["error"]["code"], -32000, call)

    def test_tools_call_zset_new_tools_in_plain_and_atomic_batch(self):
        plain = self._call("tools/call", 1, {
            "name": "kv_batch",
            "arguments": {"ops": [
                {"op": "kv_zadd", "key": "z",
                 "members": {"a": 1, "b": 2}},
                {"op": "kv_zcard", "key": "z"},
                {"op": "kv_zscore", "key": "z", "member": "b"},
                {"op": "kv_zrank", "key": "z", "member": "a"},
                {"op": "kv_zincrby", "key": "z", "increment": 5,
                 "member": "a"},
                {"op": "kv_zrem", "key": "z", "members": ["b"]},
                {"op": "kv_zcard", "key": "z"},
            ]},
        })
        summary = json.loads(plain["result"]["content"][0]["text"])
        self.assertEqual(summary["ok"], 7)
        self.assertEqual(summary["results"][0]["result"], 2)
        self.assertEqual(summary["results"][1]["result"], 2)
        self.assertEqual(summary["results"][2]["result"], 2.0)
        self.assertEqual(summary["results"][3]["result"], 0)
        self.assertEqual(summary["results"][4]["result"], 6.0)
        self.assertEqual(summary["results"][5]["result"], 1)
        self.assertEqual(summary["results"][6]["result"], 1)
        atomic = self._call("tools/call", 2, {
            "name": "kv_batch",
            "arguments": {"atomic": True, "ops": [
                {"op": "kv_zadd", "key": "z2",
                 "members": {"x": 9, "y": 3}},
                {"op": "kv_zcard", "key": "z2"},
                {"op": "kv_zscore", "key": "z2", "member": "x"},
                {"op": "kv_zrank", "key": "z2", "member": "x"},
                {"op": "kv_zincrby", "key": "z2", "increment": 1,
                 "member": "y"},
                {"op": "kv_zrem", "key": "z2", "members": ["y"]},
                {"op": "kv_zadd", "key": "z3", "members": {"m": 2},
                 "incr": True},
                {"op": "kv_zadd", "key": "z3", "members": {"n": 4},
                 "nx": True},
            ]},
        })
        summary = json.loads(atomic["result"]["content"][0]["text"])
        self.assertTrue(summary["atomic"])
        self.assertEqual(summary["ok"], 8)
        self.assertEqual(summary["results"][0]["result"], 2)
        self.assertEqual(summary["results"][1]["result"], 2)
        self.assertEqual(summary["results"][2]["result"], 9.0)
        self.assertEqual(summary["results"][3]["result"], 1)
        self.assertEqual(summary["results"][4]["result"], 4.0)
        self.assertEqual(summary["results"][5]["result"], 1)
        self.assertEqual(summary["results"][6]["result"], 2.0)
        self.assertEqual(summary["results"][7]["result"], 1)
        # An op that cannot be queued fails an atomic batch up front.
        bad_atomic = self._call("tools/call", 3, {
            "name": "kv_batch",
            "arguments": {"atomic": True, "ops": [
                {"op": "kv_zadd", "key": "z4",
                 "members": {"a": 1}},
                {"op": "kv_zrem", "key": "z4", "members": []},
            ]},
        })
        self.assertIn("error", bad_atomic)
        self.assertEqual(bad_atomic["error"]["code"], -32602)
        # And nothing ran: the set was never created.
        card = self._call("tools/call", 4, {
            "name": "kv_zcard", "arguments": {"key": "z4"},
        })
        self.assertEqual(card["result"]["content"][0]["text"], "0")

    def test_resources_list_returns_info_metrics_changes_and_key_template(self):
        listed = self._call("resources/list", 1)
        resources = listed["result"]["resources"]
        self.assertEqual(len(resources), 4)
        self.assertEqual(resources[0]["uri"], "cinder://info")
        self.assertEqual(resources[0]["mimeType"], "text/plain")
        self.assertEqual(resources[1]["uri"], "cinder://metrics")
        self.assertEqual(resources[1]["mimeType"], "application/json")
        self.assertEqual(resources[2]["uri"], "cinder://changes")
        self.assertEqual(resources[2]["mimeType"], "application/json")
        self.assertEqual(resources[3]["uriTemplate"], "cinder://key/{key}")
        self.assertEqual(resources[3]["mimeType"], "application/json")

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

    def test_prompts_list_returns_all_eight_prompts(self):
        listed = self._call("prompts/list", 1)
        prompts = listed["result"]["prompts"]
        self.assertEqual(len(prompts), 8)
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
        self.assertEqual(prompts[4]["name"], "keyspace-health")
        self.assertEqual(prompts[4]["arguments"][0]["name"], "pattern")
        self.assertFalse(prompts[4]["arguments"][0]["required"])
        self.assertEqual(prompts[5]["name"], "write-safety")
        self.assertEqual(prompts[5]["arguments"][0]["name"], "plan")
        self.assertTrue(prompts[5]["arguments"][0]["required"])
        self.assertEqual(prompts[6]["name"], "ttl-renewal")
        self.assertEqual(
            [a["name"] for a in prompts[6]["arguments"]],
            ["pattern", "keys", "target_ttl", "max_keys"],
        )
        self.assertTrue(
            all(not a["required"] for a in prompts[6]["arguments"])
        )
        self.assertEqual(prompts[7]["name"], "key-migration")
        self.assertEqual(
            [a["name"] for a in prompts[7]["arguments"]],
            ["pattern", "target_prefix", "max_keys"],
        )
        self.assertFalse(prompts[7]["arguments"][0]["required"])
        self.assertTrue(prompts[7]["arguments"][1]["required"])
        self.assertFalse(prompts[7]["arguments"][2]["required"])

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

    def _prompt_text(self, name, arguments=None, batch_size=None):
        """One prompt's text, with the scan batch size overridden
        for the call so streaming behaviour can be compared."""
        import cinder_mcp.prompts as prompts
        old = prompts.PROMPT_SCAN_BATCH_SIZE
        try:
            if batch_size is not None:
                prompts.PROMPT_SCAN_BATCH_SIZE = batch_size
            reply = self._call(
                "prompts/get", 1,
                {"name": name, "arguments": arguments or {}},
            )
        finally:
            prompts.PROMPT_SCAN_BATCH_SIZE = old
        self.assertNotIn("error", reply)
        return reply["result"]["messages"][0]["content"]["text"]

    def test_prompts_ttl_audit_same_result_at_any_batch_size(self):
        # TTLs are spaced 1000s apart, far from any bucket or
        # rendering boundary, so a second of clock drift between
        # runs cannot reorder or reword anything.
        for i in range(60):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "perm:%03d" % i, "value": "v"},
            })
        for i in range(60):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "exp:%03d" % i, "value": "v",
                              "ex": 100000 + i * 1000},
            })
        baseline = self._prompt_text("ttl-audit", batch_size=100)
        self.assertIn("Total keys scanned: 120", baseline)
        self.assertIn("Soonest expiring keys (60):", baseline)
        self.assertIn("... and 50 more", baseline)
        for size in (1, 2, 7):
            self.assertEqual(
                self._prompt_text("ttl-audit", batch_size=size), baseline,
                "batch_size=%d" % size,
            )

    def test_prompts_cleanup_plan_same_result_at_any_batch_size(self):
        # TTLs sit mid-bucket and mid-rendering-unit, so a second of
        # drift between runs cannot reclassify or reword a key.
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "safe:%03d" % i, "value": "v",
                              "ex": 1900 + i * 10},
            })
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "soon:%03d" % i, "value": "v",
                              "ex": 40000 + i * 1000},
            })
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "keep:%03d" % i, "value": "v",
                              "ex": 200000 + i * 1000},
            })
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "risky:%03d" % i, "value": "v"},
            })
        baseline = self._prompt_text("cleanup-plan", batch_size=100)
        self.assertIn("Total keys scanned: 120", baseline)
        for size in (1, 2, 7):
            self.assertEqual(
                self._prompt_text("cleanup-plan", batch_size=size), baseline,
                "batch_size=%d" % size,
            )

    def test_prompts_bounded_lists_on_a_large_keyspace(self):
        self._seed_keys(250, prefix="perm")
        text = self._prompt_text("ttl-audit")
        self.assertIn("Total keys scanned: 250", text)
        self.assertIn("Keys with no expiry (250):", text)
        self.assertIn("... and 230 more", text)
        listed = [l for l in text.split("\n") if l.startswith("- perm:")]
        self.assertEqual(len(listed), 20)
        plan = self._prompt_text("cleanup-plan")
        risky = self._section(plan, "Risky — confirm before deleting (250)")
        self.assertEqual(len(risky), 21)
        self.assertEqual(risky[-1], "... and 230 more")

    def test_prompts_get_keyspace_health_empty_keyspace(self):
        reply = self._call("prompts/get", 1, {"name": "keyspace-health"})
        messages = reply["result"]["messages"]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["role"], "user")
        text = messages[0]["content"]["text"]
        self.assertIn("Keyspace health report (pattern '*').", text)
        self.assertIn("Total keys scanned: 0", text)
        self.assertIn("cinder_version:0.4.0", text)
        self.assertIn("- string: 0", text)
        self.assertIn("- list: 0", text)
        self.assertIn("- set: 0", text)
        self.assertIn("- hash: 0", text)
        self.assertIn("Keys with no expiry (0):", text)
        self.assertIn("Soonest expiring keys (0):", text)
        self.assertIn("(none expiring)", text)
        self.assertIn("Largest string keys (by bytes):", text)
        self.assertIn("Largest container keys (by element count):", text)
        self.assertIn("Nothing to do: the keyspace is empty.", text)
        self.assertNotIn("expired while scanning", text)

    def test_prompts_get_keyspace_health_mixed_keyspace(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "soon", "value": "v", "ex": 1905},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "today", "value": "v", "ex": 40000},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "far", "value": "v", "ex": 200000},
        })
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        self._call("tools/call", 5, {
            "name": "kv_set", "arguments": {"key": "cache:old", "value": "v"},
        })
        self._call("tools/call", 6, {
            "name": "kv_set", "arguments": {"key": "big", "value": "x" * 2000},
        })
        self.fake.store["todo"] = (["buy milk", "ship it", "call"], None)
        self.fake.store["tags"] = ({"a", "b"}, None)
        self.fake.store["meta"] = ({"f": "v"}, None)
        reply = self._call("prompts/get", 7, {"name": "keyspace-health"})
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 9", text)
        self.assertIn("- string: 6", text)
        self.assertIn("- list: 1", text)
        self.assertIn("- set: 1", text)
        self.assertIn("- hash: 1", text)
        self.assertIn("Keys with no expiry (6):", text)
        self.assertIn("- big", text)
        self.assertIn("- cache:old", text)
        self.assertIn("- forever", text)
        self.assertIn("Soonest expiring keys (3):", text)
        soonest = text.split("Soonest expiring keys (3):\n")[1].split("\n\n")[0]
        self.assertEqual(
            [line.split(" (in ")[0][2:] for line in soonest.split("\n")],
            ["soon", "today", "far"],
        )
        # Largest string first, then the 1-byte strings in key order.
        largest = text.split("Largest string keys (by bytes):\n")[1].split("\n\n")[0]
        self.assertEqual(largest.split("\n")[0], "- big (2000 bytes)")
        self.assertIn("- cache:old (1 bytes)", largest)
        largest_containers = text.split(
            "Largest container keys (by element count):\n")[1].split("\n\n")[0]
        self.assertEqual(
            largest_containers.split("\n"),
            ["- todo (3 elements)", "- tags (2 elements)", "- meta (1 elements)"],
        )
        # Recommended actions are derived from the data.
        actions = text.split("Recommended actions:\n")[1].split("\n\n")[0]
        self.assertIn(
            "Give the 6 key(s) with no expiry a TTL with kv_expire, "
            "starting with the temporary-looking ones: cache:old.",
            actions,
        )
        self.assertIn(
            "Decide on the 1 key(s) expiring within the hour: renew "
            "them with kv_expire or let them go.",
            actions,
        )
        self.assertIn(
            "Inspect the largest string key 'big' (2000 bytes) with "
            "key-deep-dive or cinder://key/big",
            actions,
        )
        # No dominance action: strings are 6 of 9, under 80%.
        self.assertNotIn("check that matches what this cinder", actions)
        self.assertIn("kv_expire", text)

    def test_prompts_get_keyspace_health_pattern_filters_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "user:1", "value": "a", "ex": 60},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "cache:x", "value": "c"},
        })
        reply = self._call("prompts/get", 3, {
            "name": "keyspace-health", "arguments": {"pattern": "user:*"},
        })
        text = reply["result"]["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 1", text)
        self.assertIn("- string: 1", text)
        self.assertIn("Keys with no expiry (0):", text)
        self.assertIn("- user:1 (in ", text)
        self.assertNotIn("cache:x", text)

    def test_prompts_keyspace_health_same_result_at_any_batch_size(self):
        # TTLs sit mid-rendering-unit, so a second of clock drift
        # between runs cannot reorder or reword anything.
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "perm:%03d" % i, "value": "v"},
            })
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "exp:%03d" % i, "value": "v",
                              "ex": 100000 + i * 1000},
            })
        for i in range(10):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "soon:%03d" % i, "value": "v",
                              "ex": 1930 + i * 10},
            })
        self._call("tools/call", 1, {
            "name": "kv_set",
            "arguments": {"key": "big", "value": "x" * 2000},
        })
        for i in range(5):
            self.fake.store["l:%d" % i] = (["x"] * (i + 1), None)
        baseline = self._prompt_text("keyspace-health", batch_size=100)
        self.assertIn("Total keys scanned: 76", baseline)
        self.assertIn("- big (2000 bytes)", baseline)
        self.assertIn("- l:4 (5 elements)", baseline)
        for size in (1, 2, 7):
            self.assertEqual(
                self._prompt_text("keyspace-health", batch_size=size), baseline,
                "batch_size=%d" % size,
            )

    def _write_safety_text(self, plan):
        return self._prompt_text(
            "write-safety", {"plan": json.dumps(plan)})

    def test_prompts_get_write_safety_requires_plan(self):
        reply = self._call("prompts/get", 1, {"name": "write-safety"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("requires a plan argument", reply["error"]["message"])

    def test_prompts_get_write_safety_rejects_bad_plan(self):
        reply = self._call("prompts/get", 1, {
            "name": "write-safety", "arguments": {"plan": "not json"},
        })
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("must be a JSON array of ops", reply["error"]["message"])
        reply = self._call("prompts/get", 2, {
            "name": "write-safety", "arguments": {"plan": '{"op": "kv_get"}'},
        })
        self.assertIn("error", reply)
        self.assertIn("must be a JSON array of ops", reply["error"]["message"])

    def test_prompts_get_write_safety_flags_overwrites(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {
                "key": "soon", "value": "v", "ex": 3600},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "big", "value": "x" * 2000},
        })
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "name", "value": "alice"},
        })
        self._call("tools/call", 5, {
            "name": "kv_set", "arguments": {"key": "count", "value": "41"},
        })
        self.fake.store["todo"] = (["buy milk", "ship it"], None)
        plan = [
            {"op": "kv_set", "key": "forever", "value": "new"},
            {"op": "kv_set", "key": "soon", "value": "new"},
            {"op": "kv_set", "key": "big", "value": "new"},
            {"op": "kv_set", "key": "todo", "value": "new"},
            {"op": "kv_set", "key": "brand-new", "value": "new"},
            {"op": "kv_set", "key": "brand-new-ttl", "value": "new", "ex": 3600},
            {"op": "kv_del", "key": "forever"},
            {"op": "kv_del", "key": "ghost"},
            {"op": "kv_incr", "key": "name"},
            {"op": "kv_incr", "key": "count"},
            {"op": "kv_incr", "key": "todo"},
            {"op": "kv_incr", "key": "fresh-counter"},
            {"op": "kv_expire", "key": "forever", "seconds": 60},
            {"op": "kv_expire", "key": "ghost", "seconds": 60},
            {"op": "kv_expire", "key": "forever", "seconds": -5},
        ]
        text = self._write_safety_text(plan)
        self.assertIn("Plan: 15 op(s), 15 audited, 0 not audited.", text)
        risky = text.split("Risky (")[1].split("\n\n")[0]
        self.assertIn(
            "op 0: kv_set 'forever' — overwrites a key that never expires",
            risky,
        )
        self.assertIn(
            "op 2: kv_set 'big' — overwrites a key that never expires; "
            "overwrites a large key (2000 bytes)",
            risky,
        )
        self.assertIn(
            "op 3: kv_set 'todo' — would replace a list of 2 elements "
            "with a string, destroying its contents; overwrites a key "
            "that never expires",
            risky,
        )
        self.assertIn(
            "op 6: kv_del 'forever' — deletes a key that never expires",
            risky,
        )
        self.assertIn(
            "op 8: kv_incr 'name' — would fail: the current value is "
            "not an integer",
            risky,
        )
        self.assertIn(
            "op 10: kv_incr 'todo' — would fail with WRONGTYPE: the "
            "key is a list of 2 elements",
            risky,
        )
        self.assertIn(
            "op 14: kv_expire 'forever' — would fail: invalid expire "
            "time -5",
            risky,
        )
        caution = text.split("Caution (")[1].split("\n\n")[0]
        self.assertIn(
            "op 1: kv_set 'soon' — overwrites a string of 1 bytes that "
            "expires in ",
            caution,
        )
        self.assertIn(
            "op 4: kv_set 'brand-new' — creates a new key with no expiry",
            caution,
        )
        safe = text.split("Safe (")[1].split("\n\n")[0]
        self.assertIn(
            "op 5: kv_set 'brand-new-ttl' — creates a new key expiring "
            "in 1h 0m",
            safe,
        )
        self.assertIn(
            "op 7: kv_del 'ghost' — no-op, the key does not exist", safe)
        self.assertIn(
            "op 9: kv_incr 'count' — increments a counter currently "
            "at 41",
            safe,
        )
        self.assertIn(
            "op 11: kv_incr 'fresh-counter' — creates a counter "
            "starting at 1",
            safe,
        )
        self.assertIn(
            "op 12: kv_expire 'forever' — sets a string of 1 bytes "
            "that currently has no expiry to expire in 1m",
            safe,
        )
        self.assertIn(
            "op 13: kv_expire 'ghost' — no-op, the key does not exist",
            safe,
        )
        self.assertIn("kv_batch", text)
        self.assertIn("nothing in this audit changed the keyspace", text)

    def test_prompts_get_write_safety_read_ops_not_audited(self):
        plan = [
            {"op": "kv_get", "key": "a"},
            {"op": "kv_set", "key": "a", "value": "v"},
            {"op": "kv_keys_scan", "pattern": "*"},
            {"op": "nope", "key": "a"},
            {"op": "kv_set"},
        ]
        text = self._write_safety_text(plan)
        self.assertIn("Plan: 5 op(s), 1 audited, 4 not audited.", text)
        self.assertIn("op 0: kv_get is a read, not a write", text)
        self.assertIn("op 2: not a write op: kv_keys_scan", text)
        self.assertIn("op 3: not a write op: nope", text)
        self.assertIn("op 4: op is missing a key", text)

    def test_prompts_get_write_safety_caps_at_fifty_ops(self):
        plan = [
            {"op": "kv_set", "key": "k%d" % i, "value": "v"} for i in range(55)
        ]
        text = self._write_safety_text(plan)
        self.assertIn("Plan: 55 op(s), 50 audited, 5 not audited.", text)
        self.assertIn("op 50: past the 50-op audit cap", text)
        self.assertIn("op 54: past the 50-op audit cap", text)
        self.assertNotIn("op 49: past the 50-op audit cap", text)

    def test_prompts_get_write_safety_never_prints_values(self):
        plan = [
            {"op": "kv_set", "key": "secret", "value": "hunter2-dont-print"},
            {"op": "kv_set", "key": "other", "value": "hunter2-dont-print"},
        ]
        text = self._write_safety_text(plan)
        self.assertNotIn("hunter2-dont-print", text)
        self.assertIn("op 0: kv_set 'secret'", text)

    def _renewal_text(self, arguments=None, batch_size=None):
        return self._prompt_text("ttl-renewal", arguments, batch_size)

    def test_prompts_get_ttl_renewal_empty_keyspace(self):
        text = self._renewal_text()
        self.assertIn("TTL renewal plan (pattern '*', renew to 1d 0h).", text)
        self.assertIn("Total keys scanned: 0", text)
        self.assertIn("Plan covers 0 key(s); 0 more need renewal", text)
        self.assertIn("Renew (0)", text)
        self.assertIn("Give a first expiry (0)", text)
        self.assertIn("Already fine (0)", text)
        self.assertIn("Missing or expired (0)", text)
        self.assertEqual(text.count("(none)"), 4)
        self.assertIn("kv_expire", text)

    def test_prompts_get_ttl_renewal_classifies_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "soon", "value": "v", "ex": 30},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "mid", "value": "v", "ex": 40000},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "far", "value": "v", "ex": 200000},
        })
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        text = self._renewal_text()
        self.assertIn("Total keys scanned: 4", text)
        self.assertIn("Plan covers 3 key(s); 0 more need renewal", text)
        renew = self._section(text, "Renew (2)")
        self.assertEqual(len(renew), 2)
        self.assertRegex(renew[0], r"^- soon \(expires in (29|30)s, renew to 1d 0h with kv_expire 'soon' 86400\)$")
        self.assertTrue(renew[1].startswith(
            "- mid (expires in 11h 6m, renew to 1d 0h with kv_expire 'mid' 86400)"))
        first_expiry = self._section(text, "Give a first expiry (1)")
        self.assertEqual(first_expiry, [
            "- forever (no expiry, set to 1d 0h with kv_expire 'forever' 86400)",
        ])
        already = self._section(text, "Already fine (1)")
        self.assertEqual(len(already), 1)
        self.assertTrue(already[0].startswith("- far (expires in 2d 7h)"))
        self.assertIn("Missing or expired (0)", text)
        self.assertIn("Do not renew the missing or expired keys", text)
        self.assertIn("no PEXPIRE tool", text)

    def test_prompts_get_ttl_renewal_target_ttl_argument(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "mid", "value": "v", "ex": 40000},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "far", "value": "v", "ex": 200000},
        })
        # Target 100000s: mid renews, far is already fine.
        text = self._renewal_text({"target_ttl": "100000"})
        self.assertIn("renew to 1d 3h", text)
        renew = self._section(text, "Renew (1)")
        self.assertTrue(renew[0].startswith("- mid (expires in "))
        self.assertIn("kv_expire 'mid' 100000", renew[0])
        self.assertIn("Already fine (1)", text)
        # Target 300000s: both renew.
        text = self._renewal_text({"target_ttl": "300000"})
        self.assertIn("Plan covers 2 key(s)", text)
        renew = self._section(text, "Renew (2)")
        self.assertEqual(
            [line.split(" (")[0][2:] for line in renew], ["mid", "far"])

    def test_prompts_get_ttl_renewal_explicit_keys_flags_missing(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "soon", "value": "v", "ex": 30},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        text = self._renewal_text({
            "keys": json.dumps(["soon", "ghost", "forever"]),
        })
        self.assertIn(
            "TTL renewal plan (keys ['soon', 'ghost', 'forever'], renew to 1d 0h).",
            text,
        )
        self.assertIn("Total keys scanned: 3", text)
        self.assertIn("Plan covers 2 key(s); 0 more need renewal", text)
        missing = self._section(text, "Missing or expired (1)")
        self.assertEqual(missing, ["- ghost"])

    def test_prompts_get_ttl_renewal_max_keys_caps_the_plan(self):
        for i in range(5):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "exp:%d" % i, "value": "v",
                              "ex": 100 + i * 100},
            })
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "forever", "value": "v"},
        })
        # Cap 2: the two soonest renewals, no first expiry, 4 uncovered.
        text = self._renewal_text({"max_keys": "2"})
        self.assertIn("Plan covers 2 key(s); 4 more need renewal", text)
        renew = self._section(text, "Renew (2)")
        self.assertEqual(
            [line.split(" (")[0][2:] for line in renew[:2]],
            ["exp:0", "exp:1"],
        )
        self.assertIn(
            "... and 3 more expiring keys not covered by the cap", renew)
        self.assertIn("Give a first expiry (0)", text)
        self.assertIn(
            "... and 1 more no-expiry keys not covered by the cap", text)

    def test_prompts_get_ttl_renewal_rejects_bad_arguments(self):
        for arguments in (
            {"target_ttl": "soon"},
            {"target_ttl": "0"},
            {"target_ttl": "-5"},
            {"max_keys": "many"},
            {"max_keys": "0"},
            {"max_keys": "101"},
            {"keys": "not json"},
            {"keys": '{"op": "kv_get"}'},
            {"keys": '["a", 1]'},
        ):
            reply = self._call("prompts/get", 1, {
                "name": "ttl-renewal", "arguments": arguments,
            })
            self.assertIn("error", reply, arguments)
            self.assertEqual(reply["error"]["code"], -32602, arguments)

    def test_prompts_get_ttl_renewal_never_prints_values(self):
        self._call("tools/call", 1, {
            "name": "kv_set",
            "arguments": {"key": "soon", "value": "hunter2-dont-print", "ex": 30},
        })
        text = self._renewal_text()
        self.assertNotIn("hunter2-dont-print", text)
        self.assertIn("- soon (expires in ", text)

    def test_prompts_ttl_renewal_same_result_at_any_batch_size(self):
        # TTLs sit mid-rendering-unit, so a second of clock drift
        # between runs cannot reorder or reword anything.
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "perm:%03d" % i, "value": "v"},
            })
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "exp:%03d" % i, "value": "v",
                              "ex": 100000 + i * 1000},
            })
        for i in range(10):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "soon:%03d" % i, "value": "v",
                              "ex": 1930 + i * 10},
            })
        baseline = self._renewal_text(batch_size=100)
        self.assertIn("Total keys scanned: 70", baseline)
        self.assertIn("Plan covers 20 key(s); 20 more need renewal", baseline)
        for size in (1, 2, 7):
            self.assertEqual(
                self._renewal_text(batch_size=size), baseline,
                "batch_size=%d" % size,
            )

    def _migration_text(self, arguments=None, batch_size=None):
        return self._prompt_text("key-migration", arguments, batch_size)

    def test_prompts_get_key_migration_empty_keyspace(self):
        text = self._migration_text({"target_prefix": "new:"})
        self.assertIn(
            "Key migration plan (pattern '*' → prefix 'new:').", text)
        self.assertIn("Total keys scanned: 0", text)
        self.assertIn("Plan covers 0 ready key(s); 0 more ready keys", text)
        self.assertIn("Ready (0)", text)
        self.assertIn("Overwrite (0)", text)
        self.assertIn("Conflict (0)", text)
        self.assertIn("Maps onto itself (0)", text)
        self.assertIn("Missing or expired (0)", text)
        self.assertEqual(text.count("(none)"), 5)
        self.assertIn("kv_del", text)
        self.assertIn("no RENAME or COPY command", text)

    def test_prompts_get_key_migration_classifies_keys(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {
                "key": "old:a", "value": "v", "ex": 3570},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {
                "key": "old:big", "value": "x" * 2000},
        })
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "old:keep", "value": "v"},
        })
        self._call("tools/call", 4, {
            "name": "kv_set", "arguments": {"key": "new:keep", "value": "w"},
        })
        self._call("tools/call", 5, {
            "name": "kv_set", "arguments": {"key": "old:clash", "value": "v"},
        })
        self.fake.store["new:clash"] = (["x"], None)
        self.fake.store["old:todo"] = (["buy milk", "ship it"], None)
        text = self._migration_text(
            {"pattern": "old:*", "target_prefix": "new:"})
        self.assertIn("Total keys scanned: 5", text)
        self.assertIn("Plan covers 3 ready key(s); 0 more ready keys", text)
        ready = self._section(text, "Ready (3)")
        self.assertEqual(len(ready), 3)
        self.assertIn(
            "- old:a → new:a (string, 1 bytes, expires in 59m; delete "
            "the source with kv_del 'old:a' after verifying the copy)",
            ready)
        self.assertIn(
            "- old:big → new:big (string, 2000 bytes, no expiry, large "
            "— copy one at a time; delete the source with kv_del "
            "'old:big' after verifying the copy)",
            ready)
        self.assertIn(
            "- old:todo → new:todo (list, 2 elements, no expiry; delete "
            "the source with kv_del 'old:todo' after verifying the "
            "copy)",
            ready)
        overwrite = self._section(text, "Overwrite (1)")
        self.assertEqual(overwrite, [
            "- old:keep → new:keep (source: string, 1 bytes, no expiry; "
            "target exists: string, 1 bytes, no expiry)",
        ])
        conflict = self._section(text, "Conflict (1)")
        self.assertEqual(conflict, [
            "- old:clash → new:clash (source: string, 1 bytes, no "
            "expiry; target exists: list, 1 elements, no expiry)",
        ])
        self.assertIn("Maps onto itself (0)", text)
        self.assertIn("Missing or expired (0)", text)
        # No key appears in two sections.
        listed = ready + overwrite + conflict
        self.assertEqual(len(listed), 5)
        self.assertIn("Do not run anything yourself", text)
        self.assertIn("re-check the source TTL with kv_ttl", text)

    def test_prompts_get_key_migration_self_mapping(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "same:1", "value": "v"},
        })
        text = self._migration_text(
            {"pattern": "same:*", "target_prefix": "same:"})
        self.assertIn("Total keys scanned: 1", text)
        self.assertIn("Plan covers 0 ready key(s)", text)
        self_mapped = self._section(text, "Maps onto itself (1)")
        self.assertEqual(self_mapped, [
            "- same:1 → same:1 (string, 1 bytes, no expiry; the target "
            "is the key itself)",
        ])

    def test_prompts_get_key_migration_rejects_bad_arguments(self):
        for arguments in (
            {},
            {"target_prefix": ""},
            {"target_prefix": "new:*"},
            {"target_prefix": "new:?"},
            {"target_prefix": "new:", "max_keys": "many"},
            {"target_prefix": "new:", "max_keys": "0"},
            {"target_prefix": "new:", "max_keys": "101"},
        ):
            reply = self._call("prompts/get", 1, {
                "name": "key-migration", "arguments": arguments,
            })
            self.assertIn("error", reply, arguments)
            self.assertEqual(reply["error"]["code"], -32602, arguments)

    def test_prompts_get_key_migration_max_keys_caps_the_plan(self):
        for i in range(5):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "old:%d" % i, "value": "v"},
            })
        text = self._migration_text(
            {"pattern": "old:*", "target_prefix": "new:", "max_keys": "2"})
        self.assertIn("Plan covers 2 ready key(s); 3 more ready keys", text)
        ready = self._section(text, "Ready (2)")
        self.assertEqual(
            [line.split(" ")[1] for line in ready[:2]],
            ["old:0", "old:1"],
        )
        self.assertIn(
            "... and 3 more ready keys not covered by the cap", ready)

    def test_prompts_get_key_migration_never_prints_values(self):
        self._call("tools/call", 1, {
            "name": "kv_set",
            "arguments": {"key": "old:secret", "value": "hunter2-dont-print"},
        })
        text = self._migration_text(
            {"pattern": "old:*", "target_prefix": "new:"})
        self.assertNotIn("hunter2-dont-print", text)
        self.assertIn("- old:secret → new:secret (string, 18 bytes", text)

    def test_prompts_get_key_migration_reports_key_expired_mid_scan(self):
        # A stub client whose SCAN reply includes a key that is
        # already gone by the TTL probe: the real fake server can
        # only expire a key between the two calls by timing, so the
        # prompt is called directly with the expiry faked.
        from cinder_mcp import prompts

        class StubClient:
            def command(self, *args):
                if args[0] == "SCAN":
                    return ["0", ["gone", "ok"]]
                if args[0] == "TTL":
                    return -2 if args[1] == "gone" else -1
                if args[0] == "GET":
                    return "v"
                if args[0] == "EXISTS":
                    return 0
                raise AssertionError(args)

        result = prompts.get_prompt(
            StubClient(), "key-migration", {"target_prefix": "new:"})
        text = result["messages"][0]["content"]["text"]
        self.assertIn("Total keys scanned: 2", text)
        self.assertIn("Plan covers 1 ready key(s)", text)
        missing = self._section(text, "Missing or expired (1)")
        self.assertEqual(missing, ["- gone"])
        ready = self._section(text, "Ready (1)")
        self.assertEqual(len(ready), 1)
        self.assertTrue(ready[0].startswith("- ok → new:ok (string, 1 bytes"))

    def test_prompts_key_migration_same_result_at_any_batch_size(self):
        # TTLs sit mid-rendering-unit, so a second of clock drift
        # between runs cannot reorder or reword anything.
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "perm:%03d" % i, "value": "v"},
            })
        for i in range(30):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "exp:%03d" % i, "value": "v",
                              "ex": 100000 + i * 1000},
            })
        for i in range(10):
            self._call("tools/call", 1, {
                "name": "kv_set",
                "arguments": {"key": "soon:%03d" % i, "value": "v",
                              "ex": 1930 + i * 10},
            })
        baseline = self._migration_text(
            {"target_prefix": "new:"}, batch_size=100)
        self.assertIn("Total keys scanned: 70", baseline)
        self.assertIn("Plan covers 20 ready key(s); 50 more ready keys",
                      baseline)
        for size in (1, 2, 7):
            self.assertEqual(
                self._migration_text({"target_prefix": "new:"},
                                     batch_size=size),
                baseline,
                "batch_size=%d" % size,
            )

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
        self.assertEqual(data, {
            "tools": {}, "total_calls": 0, "total_errors": 0,
            "budget_breaches": {"warn": [], "slow": []},
        })

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

    def test_metrics_resource_flags_slow_tool_live(self):
        # Tiny budgets, so any real round trip breaches slow.
        from cinder_mcp.metrics import ToolMetrics
        server = MCPServer(
            RespClient("127.0.0.1", self.fake.port),
            metrics=ToolMetrics(default_warn_ms=0.001, default_slow_ms=0.002),
        )
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": "kv_set", "arguments": {"key": "a", "value": "1"}}})
        data = json.loads(server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "resources/read",
             "params": {"uri": "cinder://metrics"}}
        )["result"]["contents"][0]["text"])
        stats = data["tools"]["kv_set"]
        self.assertEqual(stats["status"], "slow")
        self.assertEqual(stats["warn_ms"], 0.001)
        self.assertEqual(stats["slow_ms"], 0.002)
        self.assertGreaterEqual(stats["slow_breaches"], 1)
        self.assertEqual(data["budget_breaches"], {"warn": [], "slow": ["kv_set"]})
        info = server.handle_message(
            {"jsonrpc": "2.0", "id": 3, "method": "resources/read",
             "params": {"uri": "cinder://info"}}
        )["result"]["contents"][0]["text"]
        self.assertIn("status:slow", info)
        self.assertIn(
            "# Latency budget breaches: warn: (none); slow: kv_set", info)

    def _changes(self, uri="cinder://changes"):
        reply = self._call("resources/read", 1, {"uri": uri})
        self.assertNotIn("error", reply, uri)
        contents = reply["result"]["contents"]
        self.assertEqual(len(contents), 1)
        self.assertEqual(contents[0]["uri"], uri)
        self.assertEqual(contents[0]["mimeType"], "application/json")
        return json.loads(contents[0]["text"])

    def test_resources_read_changes_baselines_empty_keyspace(self):
        data = self._changes()
        self.assertEqual(data, {
            "checkpoint": 1, "since": None,
            "added": [], "changed": [], "removed": [], "total_keys": 0,
        })

    def test_resources_read_changes_baseline_lists_all_keys_as_added(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "b", "value": "2"},
        })
        data = self._changes()
        self.assertEqual(data["checkpoint"], 1)
        self.assertIsNone(data["since"])
        self.assertEqual(data["added"], ["a", "b"])
        self.assertEqual(data["changed"], [])
        self.assertEqual(data["removed"], [])
        self.assertEqual(data["total_keys"], 2)

    def test_resources_read_changes_reports_added_changed_removed(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        self._call("tools/call", 2, {
            "name": "kv_set", "arguments": {"key": "b", "value": "2"},
        })
        first = self._changes()
        self.assertEqual(first["checkpoint"], 1)
        # Change a, delete b, add c.
        self._call("tools/call", 3, {
            "name": "kv_set", "arguments": {"key": "a", "value": "9"},
        })
        self._call("tools/call", 4, {
            "name": "kv_del", "arguments": {"key": "b"},
        })
        self._call("tools/call", 5, {
            "name": "kv_set", "arguments": {"key": "c", "value": "3"},
        })
        data = self._changes("cinder://changes?since=1")
        self.assertEqual(data, {
            "checkpoint": 2, "since": 1,
            "added": ["c"], "changed": ["a"], "removed": ["b"],
            "total_keys": 2,
        })

    def test_resources_read_changes_empty_poll_when_nothing_moved(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        self._changes()
        data = self._changes("cinder://changes?since=1")
        self.assertEqual(data["added"], [])
        self.assertEqual(data["changed"], [])
        self.assertEqual(data["removed"], [])
        self.assertEqual(data["total_keys"], 1)
        self.assertEqual(data["checkpoint"], 2)
        # Same checkpoint again: the same (empty) diff, not an error.
        again = self._changes("cinder://changes?since=1")
        self.assertEqual(again["added"], [])
        self.assertEqual(again["changed"], [])
        self.assertEqual(again["removed"], [])
        self.assertEqual(again["checkpoint"], 3)

    def test_resources_read_changes_unknown_checkpoint_errors(self):
        self._changes()
        reply = self._call("resources/read", 1,
                           {"uri": "cinder://changes?since=99"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("unknown checkpoint: 99", reply["error"]["message"])
        self.assertIn("re-baseline", reply["error"]["message"])

    def test_resources_read_changes_bad_since_errors(self):
        for bad in ("cinder://changes?since=abc",
                    "cinder://changes?since=0",
                    "cinder://changes?since=-3"):
            reply = self._call("resources/read", 1, {"uri": bad})
            self.assertIn("error", reply, bad)
            self.assertEqual(reply["error"]["code"], -32602, bad)

    def test_resources_read_changes_detects_container_member_change(self):
        # Same length, different member: content hashing must catch it.
        self.fake.store["todo"] = (["buy milk"], None)
        self.fake.store["tags"] = ({"a", "b"}, None)
        self._changes()
        self.fake.store["todo"] = (["ship it"], None)
        self.fake.store["tags"] = ({"a", "c"}, None)
        data = self._changes("cinder://changes?since=1")
        self.assertEqual(data["added"], [])
        self.assertEqual(data["changed"], ["tags", "todo"])
        self.assertEqual(data["removed"], [])

    def test_resources_read_changes_reports_expired_key_as_removed(self):
        self._call("tools/call", 1, {
            "name": "kv_set",
            "arguments": {"key": "temp", "value": "v", "ex": 1},
        })
        self._changes()
        time.sleep(1.2)
        data = self._changes("cinder://changes?since=1")
        self.assertEqual(data["removed"], ["temp"])
        self.assertEqual(data["total_keys"], 0)

    def test_resources_read_changes_ttl_only_change_is_not_a_change(self):
        self._call("tools/call", 1, {
            "name": "kv_set", "arguments": {"key": "a", "value": "1"},
        })
        self._changes()
        self._call("tools/call", 2, {
            "name": "kv_expire", "arguments": {"key": "a", "seconds": 3600},
        })
        data = self._changes("cinder://changes?since=1")
        self.assertEqual(data["added"], [])
        self.assertEqual(data["changed"], [])
        self.assertEqual(data["removed"], [])

    def test_resources_read_changes_forgets_old_checkpoints(self):
        from cinder_mcp.watch import MAX_CHECKPOINTS
        for _ in range(MAX_CHECKPOINTS + 1):
            self._changes()
        reply = self._call("resources/read", 1,
                           {"uri": "cinder://changes?since=1"})
        self.assertIn("error", reply)
        self.assertEqual(reply["error"]["code"], -32602)
        self.assertIn("unknown checkpoint: 1", reply["error"]["message"])
        # The newest checkpoint still works.
        data = self._changes(
            "cinder://changes?since=%d" % (MAX_CHECKPOINTS + 1))
        self.assertEqual(data["added"], [])

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
            {
                "tools": {}, "total_calls": 0, "total_errors": 0,
                "budget_breaches": {"warn": [], "slow": []},
            },
        )
        self.assertIn("(no tool calls yet)", ToolMetrics().render_text())


class BudgetTests(unittest.TestCase):
    def test_classify_returns_warning_levels(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        # Within budget: no warning.
        self.assertIsNone(metrics.classify("kv_get", 50.0))
        # Exactly at the warn threshold: not over, so no warning.
        self.assertIsNone(metrics.classify("kv_get", 100.0))
        # Over warn, under slow.
        warn = metrics.classify("kv_get", 150.0)
        self.assertEqual(warn, {
            "level": "warn",
            "tool": "kv_get",
            "latency_ms": 150.0,
            "threshold_ms": 100.0,
            "message": "kv_get took 150.000 ms, over its warn budget of 100.000 ms",
        })
        # Over slow.
        slow = metrics.classify("kv_get", 600.0)
        self.assertEqual(slow["level"], "slow")
        self.assertEqual(slow["threshold_ms"], 500.0)
        self.assertEqual(
            slow["message"],
            "kv_get took 600.000 ms, over its slow budget of 500.000 ms",
        )
        # Per-tool override thresholds apply.
        metrics.set_budget("kv_keys", 10, 20)
        self.assertEqual(
            metrics.classify("kv_keys", 15.0)["level"], "warn")
        self.assertEqual(
            metrics.classify("kv_keys", 25.0)["level"], "slow")
        self.assertIsNone(metrics.classify("kv_keys", 5.0))

    def test_default_budget_in_snapshot(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        metrics.record("kv_get", 2.0)
        stats = metrics.snapshot()["tools"]["kv_get"]
        self.assertEqual(stats["warn_ms"], 100.0)
        self.assertEqual(stats["slow_ms"], 500.0)
        self.assertEqual(stats["status"], "ok")
        self.assertEqual(stats["warn_breaches"], 0)
        self.assertEqual(stats["slow_breaches"], 0)
        self.assertEqual(
            metrics.snapshot()["budget_breaches"], {"warn": [], "slow": []}
        )

    def test_custom_per_tool_budget_overrides_defaults(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics(
            budgets={"kv_keys": {"warn_ms": 10, "slow_ms": 20}}
        )
        for ms in (1, 5, 11, 12, 13, 14, 15, 16, 17, 18):
            metrics.record("kv_keys", ms)
        for ms in (1, 5, 11, 12, 13, 14, 15, 16, 17, 18):
            metrics.record("kv_get", ms)
        snapshot = metrics.snapshot()
        keyed = snapshot["tools"]["kv_keys"]
        self.assertEqual(keyed["warn_ms"], 10)
        self.assertEqual(keyed["slow_ms"], 20)
        # p95 is 18: over the 10ms warn threshold, under slow.
        self.assertEqual(keyed["status"], "warn")
        self.assertEqual(keyed["warn_breaches"], 8)  # 11..18
        self.assertEqual(keyed["slow_breaches"], 0)
        # Same samples, default budget: still ok.
        self.assertEqual(snapshot["tools"]["kv_get"]["status"], "ok")
        self.assertEqual(
            snapshot["budget_breaches"], {"warn": ["kv_keys"], "slow": []}
        )

    def test_status_slow_and_breach_counts(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        metrics.record("kv_get", 1.0)
        metrics.record("kv_get", 600.0)
        stats = metrics.snapshot()["tools"]["kv_get"]
        # p95 is 600: over both thresholds.
        self.assertEqual(stats["status"], "slow")
        self.assertEqual(stats["warn_breaches"], 1)
        self.assertEqual(stats["slow_breaches"], 1)
        self.assertEqual(
            metrics.snapshot()["budget_breaches"],
            {"warn": [], "slow": ["kv_get"]},
        )

    def test_render_text_flags_breaches_and_summarizes(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        metrics.record("kv_get", 1.0)
        metrics.record("kv_get", 600.0)
        metrics.record("kv_set", 2.0)
        text = metrics.render_text()
        self.assertIn("tool:kv_get", text)
        self.assertIn("status:slow", text)
        self.assertIn("warn_breaches:1", text)
        self.assertIn("slow_breaches:1", text)
        self.assertIn("tool:kv_set", text)
        self.assertIn("status:ok", text)
        self.assertIn(
            "# Latency budget breaches: warn: (none); slow: kv_get", text
        )

    def test_budget_validation_rejects_bad_thresholds(self):
        from cinder_mcp.metrics import ToolMetrics
        metrics = ToolMetrics()
        with self.assertRaises(ValueError):
            metrics.set_budget("kv_get", 500, 100)  # slow below warn
        with self.assertRaises(ValueError):
            metrics.set_budget("kv_get", 100, 100)  # equal
        with self.assertRaises(ValueError):
            metrics.set_budget("kv_get", 0, 100)  # not positive
        with self.assertRaises(ValueError):
            ToolMetrics(default_warn_ms=500, default_slow_ms=100)
        # Partial override inherits the other default and validates.
        metrics = ToolMetrics(budgets={"kv_get": {"warn_ms": 50}})
        self.assertEqual(metrics.budget_for("kv_get"), (50.0, 500.0))
        with self.assertRaises(ValueError):
            ToolMetrics(budgets={"kv_get": {"slow_ms": 50}})  # below default warn

    def test_budgets_from_env(self):
        import os
        from unittest.mock import patch

        from cinder_mcp.server import _budgets_from_env
        with patch.dict(os.environ, {}, clear=True):
            metrics = _budgets_from_env()
            self.assertEqual(metrics.budget_for("kv_get"), (100.0, 500.0))
        with patch.dict(os.environ, {
            "CINDER_MCP_WARN_MS": "25",
            "CINDER_MCP_SLOW_MS": "250",
            "CINDER_MCP_BUDGETS": '{"kv_keys": {"warn_ms": 10, "slow_ms": 40}}',
        }, clear=True):
            metrics = _budgets_from_env()
            self.assertEqual(metrics.budget_for("kv_get"), (25.0, 250.0))
            self.assertEqual(metrics.budget_for("kv_keys"), (10.0, 40.0))
        with patch.dict(os.environ, {
            "CINDER_MCP_BUDGETS": "{not json",
        }, clear=True):
            with self.assertRaises(ValueError):
                _budgets_from_env()
        with patch.dict(os.environ, {"CINDER_MCP_WARN_MS": "fast"}, clear=True):
            with self.assertRaises(ValueError):
                _budgets_from_env()
        with patch.dict(os.environ, {
            "CINDER_MCP_BUDGETS": '{"kv_get": {"warn_ms": 900, "slow_ms": 100}}',
        }, clear=True):
            with self.assertRaises(ValueError):
                _budgets_from_env()

if __name__ == "__main__":
    unittest.main()
