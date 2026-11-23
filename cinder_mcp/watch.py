"""Keyspace watch: report which keys changed since a checkpoint.

Cinder has no keyspace notifications, so the watch is a diff, not a
push feed: the server snapshots the keyspace (KEYS plus a fingerprint
per key) and keeps the last few snapshots, and `cinder://changes`
returns the keys added, changed or removed since a checkpoint the
client hands back as `?since=<n>`. A read with no `since` baselines:
every current key is reported as added and the returned checkpoint
is the one to poll with next.

A fingerprint is the value's SHA-256 for strings, or the SHA-256
of the container's contents for lists, sets and hashes (cinder has
no TYPE command, so the type is probed the same way
`cinder://key/<key>` probes it). A key whose TTL changed but whose
value did not is not reported as changed, and a key that expired
between the KEYS listing and its fingerprint read is treated as
gone.
"""

import hashlib

from .resp import RespError

MAX_CHECKPOINTS = 16


class KeyspaceWatch:
    """Per-session keyspace snapshots, keyed by checkpoint number."""

    def __init__(self):
        self._snapshots = {}  # checkpoint -> {key: fingerprint}
        self._next_checkpoint = 1

    def read(self, client, since=None):
        """Diff the live keyspace against the snapshot at `since`.

        `since` is None for a first read (baseline: everything is
        added). Returns {"checkpoint", "since", "added", "changed",
        "removed", "total_keys"}. Raises ValueError for an unknown
        or evicted checkpoint; the client then re-baselines by
        reading without `since`."""
        if since is not None and since not in self._snapshots:
            raise ValueError(
                "unknown checkpoint: %s (checkpoints older than the "
                "last %d reads are forgotten; read cinder://changes "
                "without a since query to re-baseline)"
                % (since, MAX_CHECKPOINTS)
            )
        base = self._snapshots.get(since, {})
        current = _snapshot(client)
        checkpoint = self._next_checkpoint
        self._next_checkpoint += 1
        self._snapshots[checkpoint] = current
        while len(self._snapshots) > MAX_CHECKPOINTS:
            del self._snapshots[min(self._snapshots)]
        return {
            "checkpoint": checkpoint,
            "since": since,
            "added": sorted(k for k in current if k not in base),
            "changed": sorted(
                k for k in current if k in base and current[k] != base[k]
            ),
            "removed": sorted(k for k in base if k not in current),
            "total_keys": len(current),
        }


def _snapshot(client):
    """The live keyspace as {key: fingerprint}."""
    keys = client.command("KEYS", "*") or []
    snapshot = {}
    for key in keys:
        fingerprint = _fingerprint(client, key)
        if fingerprint is not None:
            snapshot[key] = fingerprint
    return snapshot


def _fingerprint(client, key):
    """A short digest of a key's current value, or None if the key
    vanished while being fingerprinted (expired between KEYS and GET)."""
    try:
        value = client.command("GET", key)
    except RespError:
        # Not a string: probe the container types. The first command
        # that does not answer WRONGTYPE names the type; the
        # fingerprint is then a hash of the container's contents,
        # so any member change shows up, not just a size change.
        for probe, kind in (("LLEN", "list"), ("SCARD", "set"), ("HLEN", "hash")):
            try:
                client.command(probe, key)
            except RespError:
                continue
            return _container_fingerprint(client, key, kind)
        return None
    if value is None:
        return None
    return "string:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _container_fingerprint(client, key, kind):
    """Hash a container's contents: list elements in order, set
    members sorted (order-independent), hash fields and values in
    order."""
    if kind == "list":
        items = client.command("LRANGE", key, 0, -1) or []
    elif kind == "set":
        items = sorted(client.command("SMEMBERS", key) or [])
    else:  # hash
        items = client.command("HGETALL", key) or []
    joined = "\x00".join(str(item) for item in items)
    return "%s:%s" % (
        kind, hashlib.sha256(joined.encode("utf-8")).hexdigest()
    )
