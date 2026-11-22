"""Resource definitions for cinder-mcp.

Resources are read-only URIs an MCP client can fetch, as opposed to
tools which are actions. Each resource maps to a cinder command whose
output is returned as text. The only resource so far is cinder://info,
which samples cinder's INFO output (version, uptime, key count).
"""

INFO_URI = "cinder://info"

RESOURCES = [
    {
        "uri": INFO_URI,
        "name": "Server info",
        "description": (
            "Cinder server info: version, uptime, commands processed, "
            "key count, and AOF fsync policy."
        ),
        "mimeType": "text/plain",
    },
]


def read_resource(client, uri):
    """Read one resource from cinder. Returns a content dict with uri,
    mimeType and text, as the MCP spec requires for resources/read."""
    if uri == INFO_URI:
        text = client.command("INFO")
        if text is None:
            raise ValueError("cinder returned no INFO output")
        return {"uri": uri, "mimeType": "text/plain", "text": text}
    raise ValueError("unknown resource: %s" % uri)
