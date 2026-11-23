"""Per-tool latency metrics for cinder-mcp, kept in memory.

Every tools/call records one sample: the tool name, how long the
cinder round trip took, and whether it succeeded. The samples back
the cinder://metrics resource and the metrics section appended to
cinder://info, so an agent can see which tools are slow or failing
without any extra instrumentation on cinder itself.

Samples are per process and reset when the server restarts; nothing
is written to disk. At most MAX_SAMPLES_PER_TOOL latencies are kept
per tool (oldest dropped first), so a long-lived session cannot grow
unboundedly and the percentiles always describe recent calls.
"""

import math

MAX_SAMPLES_PER_TOOL = 1000


def _percentile(sorted_values, pct):
    """Nearest-rank percentile of an already sorted list, or None."""
    if not sorted_values:
        return None
    rank = math.ceil(pct / 100.0 * len(sorted_values))
    return sorted_values[max(0, min(rank, len(sorted_values)) - 1)]


class ToolMetrics:
    """In-memory per-tool call counts, latencies and error counts."""

    def __init__(self):
        # tool name -> {"calls": int, "errors": int, "latencies_ms": [float]}
        self._tools = {}

    def record(self, name, latency_ms, ok=True):
        """Record one completed tool call."""
        entry = self._tools.setdefault(
            name, {"calls": 0, "errors": 0, "latencies_ms": []}
        )
        entry["calls"] += 1
        if not ok:
            entry["errors"] += 1
        latencies = entry["latencies_ms"]
        latencies.append(latency_ms)
        if len(latencies) > MAX_SAMPLES_PER_TOOL:
            del latencies[: len(latencies) - MAX_SAMPLES_PER_TOOL]

    def snapshot(self):
        """Per-tool stats as plain data: calls, errors, mean/p50/p95 ms."""
        tools = {}
        for name in sorted(self._tools):
            entry = self._tools[name]
            latencies = sorted(entry["latencies_ms"])
            n = len(latencies)
            tools[name] = {
                "calls": entry["calls"],
                "errors": entry["errors"],
                "mean_ms": round(sum(latencies) / n, 3) if n else None,
                "p50_ms": (
                    round(_percentile(latencies, 50), 3) if n else None
                ),
                "p95_ms": (
                    round(_percentile(latencies, 95), 3) if n else None
                ),
            }
        return {
            "tools": tools,
            "total_calls": sum(t["calls"] for t in tools.values()),
            "total_errors": sum(t["errors"] for t in tools.values()),
        }

    def render_text(self):
        """The metrics section appended to the cinder://info output."""
        lines = ["# Tool metrics (cinder-mcp, this session)"]
        snapshot = self.snapshot()
        if not snapshot["tools"]:
            lines.append("(no tool calls yet)")
            return "\n".join(lines)
        for name, stats in snapshot["tools"].items():
            lines.append(
                "tool:%s calls:%d errors:%d mean_ms:%.3f p50_ms:%.3f p95_ms:%.3f"
                % (
                    name,
                    stats["calls"],
                    stats["errors"],
                    stats["mean_ms"],
                    stats["p50_ms"],
                    stats["p95_ms"],
                )
            )
        return "\n".join(lines)
