"""Resource definitions for cinder-mcp.

Resources are read-only URIs an MCP client can fetch, as opposed to
tools which are actions. Each resource maps to a cinder command whose
output is returned as text. cinder://info samples cinder's INFO output;
cinder://key/<key> exposes one key's value and type as JSON.

Cinder has no TYPE command, so the key resource works out the type by
probing: GET succeeds for strings, otherwise LLEN / SCARD / HLEN are
tried in turn and the first one that does not answer WRONGTYPE names
the type. A missing key is a not-found error, not an empty resource.
"""

import json
from urllib.parse import parse_qs, unquote, urlparse

from .metrics import ToolMetrics
from .resp import RespError
from .watch import KeyspaceWatch

INFO_URI = "cinder://info"
METRICS_URI = "cinder://metrics"
CHANGES_URI = "cinder://changes"
KEY_URI_PREFIX = "cinder://key/"

RESOURCES = [
    {
        "uri": INFO_URI,
        "name": "Server info",
        "description": (
            "Cinder server info: version, uptime, commands processed, "
            "key count, and AOF fsync policy. Appends this server's "
            "per-tool latency metrics for the current session."
        ),
        "mimeType": "text/plain",
    },
    {
        "uri": METRICS_URI,
        "name": "Tool metrics",
        "description": (
            "Per-tool call counts, error counts and mean/p50/p95 "
            "latency in milliseconds for this server session, as JSON, "
            "with each tool's warn/slow latency budget, its warn/slow/"
            "ok status, and how many samples crossed each threshold."
        ),
        "mimeType": "application/json",
    },
    {
        "uri": CHANGES_URI,
        "name": "Keyspace changes",
        "description": (
            "Keys added, changed or removed since a checkpoint, as "
            "JSON. The first read (no since query) reports every "
            "current key as added and returns a checkpoint; poll "
            "again as cinder://changes?since=<checkpoint> to get only "
            "what moved. Checkpoints older than the last 16 reads "
            "are forgotten — then re-read without since to re-baseline. "
            "A key whose TTL changed but whose value did not is not "
            "reported as changed."
        ),
        "mimeType": "application/json",
    },
    {
        "uriTemplate": KEY_URI_PREFIX + "{key}",
        "name": "Key value",
        "description": (
            "The value and type of a single key, as JSON. "
            "Returns a not-found error when the key does not exist."
        ),
        "mimeType": "application/json",
    },
]


def read_resource(client, uri, metrics=None, watch=None):
    """Read one resource from cinder. Returns a content dict with uri,
    mimeType and text, as the MCP spec requires for resources/read.
    The watch is the server's per-session KeyspaceWatch; a fresh one
    is created when none is given, so a bare read still works but
    only ever baselines."""
    if uri == INFO_URI:
        text = client.command("INFO")
        if text is None:
            raise ValueError("cinder returned no INFO output")
        if metrics is None:
            metrics = ToolMetrics()
        text = text.rstrip("\r\n") + "\r\n" + metrics.render_text() + "\r\n"
        return {"uri": uri, "mimeType": "text/plain", "text": text}
    if uri == METRICS_URI:
        if metrics is None:
            metrics = ToolMetrics()
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(metrics.snapshot()),
        }
    if uri == CHANGES_URI or uri.startswith(CHANGES_URI + "?"):
        if watch is None:
            watch = KeyspaceWatch()
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(watch.read(client, _changes_since(uri))),
        }
    if uri.startswith(KEY_URI_PREFIX):
        return _read_key_resource(client, uri)
    raise ValueError("unknown resource: %s" % uri)


def _changes_since(uri):
    """The checkpoint from a cinder://changes?since=<n> URI, or None
    for a plain cinder://changes read (baseline)."""
    query = urlparse(uri).query
    raw = parse_qs(query).get("since")
    if not raw:
        return None
    try:
        since = int(raw[0])
    except ValueError:
        raise ValueError("cinder://changes since must be a number: %s" % raw[0])
    if since < 1:
        raise ValueError("cinder://changes since must be at least 1")
    return since


def _read_key_resource(client, uri):
    key = unquote(uri[len(KEY_URI_PREFIX):])
    if not key:
        raise ValueError("cinder://key/ requires a key")
    if client.command("EXISTS", key) == 0:
        raise ValueError("key not found: %s" % key)
    try:
        value = client.command("GET", key)
    except RespError:
        # Not a string: probe the container types. The first command
        # that does not answer WRONGTYPE names the type.
        for probe, kind in (("LLEN", "list"), ("SCARD", "set"), ("HLEN", "hash")):
            try:
                length = client.command(probe, key)
            except RespError:
                continue
            return _key_content(uri, key, kind, None, length)
        raise ValueError("key has an unreadable type: %s" % key)
    if value is None:
        # The key expired between EXISTS and GET.
        raise ValueError("key not found: %s" % key)
    return _key_content(uri, key, "string", value)


def _key_content(uri, key, kind, value, length=None):
    payload = {"key": key, "type": kind}
    if kind == "string":
        payload["value"] = value
    else:
        # Non-string values are not readable as a single resource
        # value; report the size instead.
        payload["length"] = length
    return {
        "uri": uri,
        "mimeType": "application/json",
        "text": json.dumps(payload),
    }
