"""Minimal RESP client for talking to cinder over a plain socket.

No external dependencies: commands are encoded as arrays of bulk strings
and replies are parsed by hand. Only the reply types cinder sends are
supported: simple strings (+), errors (-), integers (:), bulk strings ($)
and arrays (*).
"""

import socket


class RespError(Exception):
    """An error reply (-ERR ...) from the server."""


class ConnectionError(Exception):
    """The server could not be reached or the connection broke."""


def encode_command(*args):
    """Encode a command as a RESP array of bulk strings."""
    parts = ["*%d\r\n" % len(args)]
    for arg in args:
        raw = arg if isinstance(arg, bytes) else str(arg).encode("utf-8")
        parts.append("$%d\r\n" % len(raw))
        parts.append(raw.decode("latin-1"))
        parts.append("\r\n")
    return "".join(parts).encode("latin-1")


class RespClient:
    """A short-lived RESP connection: one command per call, reconnecting
    as needed. Each call opens a fresh socket so a dropped connection
    never leaves the client in a half-open state."""

    def __init__(self, host="127.0.0.1", port=6379, timeout=5.0):
        self.host = host
        self.port = port
        self.timeout = timeout

    def command(self, *args):
        try:
            sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )
        except OSError as exc:
            raise ConnectionError(
                "cinder is not reachable at %s:%d (%s)"
                % (self.host, self.port, exc)
            ) from exc
        try:
            sock.sendall(encode_command(*args))
            return self._read_reply(sock.makefile("rb"))
        except OSError as exc:
            raise ConnectionError("connection to cinder broke: %s" % exc) from exc
        finally:
            sock.close()

    def ping(self):
        return self.command("PING") == "PONG"

    def _read_reply(self, reader):
        line = reader.readline()
        if not line:
            raise ConnectionError("cinder closed the connection")
        prefix, rest = line[:1], line[1:].rstrip(b"\r\n")
        if prefix == b"+":
            return rest.decode("utf-8", "replace")
        if prefix == b"-":
            raise RespError(rest.decode("utf-8", "replace"))
        if prefix == b":":
            return int(rest)
        if prefix == b"$":
            length = int(rest)
            if length == -1:
                return None
            data = reader.read(length + 2)[:length]
            return data.decode("utf-8", "replace")
        if prefix == b"*":
            count = int(rest)
            if count == -1:
                return None
            return [self._read_reply(reader) for _ in range(count)]
        raise ConnectionError("unexpected RESP reply prefix: %r" % prefix)
