"""Per-tool latency metrics for cinder-mcp, kept in memory.

Every tools/call records one sample: the tool name, how long the
cinder round trip took, and whether it succeeded. The samples back
the cinder://metrics resource and the metrics section appended to
cinder://info, so an agent can see which tools are slow or failing
without any extra instrumentation on cinder itself.

Each tool also has a latency budget: a warn threshold and a slow
threshold in milliseconds. The defaults are WARN_MS / SLOW_MS and
individual tools can override them (see ToolMetrics and
server._budgets_from_env). A tool whose p95 latency is over its warn
threshold is flagged "warn"; over its slow threshold it is "slow".
The snapshot also counts, per tool, how many individual samples
crossed each threshold, so a single slow call is visible even when
the p95 is still fine.

Samples are per process and reset when the server restarts; nothing
is written to disk. At most MAX_SAMPLES_PER_TOOL latencies are kept
per tool (oldest dropped first), so a long-lived session cannot grow
unboundedly and the percentiles always describe recent calls.
"""

import math

MAX_SAMPLES_PER_TOOL = 1000

# Default latency budgets, in milliseconds. Local cinder round trips
# are normally well under a millisecond, so 100ms is already slow
# enough to notice and 500ms is slow enough to investigate.
DEFAULT_WARN_MS = 100.0
DEFAULT_SLOW_MS = 500.0

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_SLOW = "slow"


def _percentile(sorted_values, pct):
    """Nearest-rank percentile of an already sorted list, or None."""
    if not sorted_values:
        return None
    rank = math.ceil(pct / 100.0 * len(sorted_values))
    return sorted_values[max(0, min(rank, len(sorted_values)) - 1)]


def _check_budget(warn_ms, slow_ms):
    """Validate one warn/slow pair; raises ValueError on bad values."""
    if not isinstance(warn_ms, (int, float)) or not isinstance(
        slow_ms, (int, float)
    ):
        raise ValueError("latency budgets must be numbers")
    if warn_ms <= 0 or slow_ms <= 0:
        raise ValueError("latency budgets must be positive")
    if slow_ms <= warn_ms:
        raise ValueError(
            "slow threshold (%.3f ms) must be above warn threshold (%.3f ms)"
            % (slow_ms, warn_ms)
        )


class ToolMetrics:
    """In-memory per-tool call counts, latencies and error counts."""

    def __init__(self, budgets=None, default_warn_ms=DEFAULT_WARN_MS,
                 default_slow_ms=DEFAULT_SLOW_MS):
        # tool name -> {"calls": int, "errors": int, "latencies_ms": [float]}
        self._tools = {}
        _check_budget(default_warn_ms, default_slow_ms)
        self._default_warn_ms = float(default_warn_ms)
        self._default_slow_ms = float(default_slow_ms)
        # tool name -> (warn_ms, slow_ms) overrides; anything not listed
        # here uses the defaults.
        self._budgets = {}
        for name, budget in (budgets or {}).items():
            if not isinstance(budget, dict):
                raise ValueError("budget for %r must be an object" % name)
            warn_ms = budget.get("warn_ms", self._default_warn_ms)
            slow_ms = budget.get("slow_ms", self._default_slow_ms)
            _check_budget(warn_ms, slow_ms)
            self._budgets[name] = (float(warn_ms), float(slow_ms))

    def set_budget(self, name, warn_ms, slow_ms):
        """Set (or replace) the latency budget for one tool."""
        _check_budget(warn_ms, slow_ms)
        self._budgets[name] = (float(warn_ms), float(slow_ms))

    def budget_for(self, name):
        """The (warn_ms, slow_ms) budget for a tool, defaults included."""
        return self._budgets.get(
            name, (self._default_warn_ms, self._default_slow_ms)
        )

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

    @staticmethod
    def _status(p95_ms, warn_ms, slow_ms):
        if p95_ms is None:
            return STATUS_OK
        if p95_ms > slow_ms:
            return STATUS_SLOW
        if p95_ms > warn_ms:
            return STATUS_WARN
        return STATUS_OK

    def classify(self, name, latency_ms):
        """The latency warning for one completed call, or None.

        A call over the slow threshold is "slow", over warn (but not
        slow) is "warn"; a call at or under warn gets no warning. The
        warning carries the level, the tool, the measured latency and
        the threshold it crossed, so a tools/call result can surface
        it inline instead of only in cinder://metrics.
        """
        warn_ms, slow_ms = self.budget_for(name)
        if latency_ms > slow_ms:
            level, threshold = STATUS_SLOW, slow_ms
        elif latency_ms > warn_ms:
            level, threshold = STATUS_WARN, warn_ms
        else:
            return None
        return {
            "level": level,
            "tool": name,
            "latency_ms": round(latency_ms, 3),
            "threshold_ms": round(threshold, 3),
            "message": "%s took %.3f ms, over its %s budget of %.3f ms"
            % (name, latency_ms, level, threshold),
        }

    def snapshot(self):
        """Per-tool stats as plain data: calls, errors, mean/p50/p95 ms,
        the tool's latency budget, its warn/slow status, and how many
        samples crossed each threshold. Plus a budget_breaches summary
        listing the tools currently over each threshold."""
        tools = {}
        warn_tools = []
        slow_tools = []
        for name in sorted(self._tools):
            entry = self._tools[name]
            latencies = sorted(entry["latencies_ms"])
            n = len(latencies)
            warn_ms, slow_ms = self.budget_for(name)
            p50 = _percentile(latencies, 50) if n else None
            p95 = _percentile(latencies, 95) if n else None
            status = self._status(p95, warn_ms, slow_ms)
            if status == STATUS_SLOW:
                slow_tools.append(name)
            elif status == STATUS_WARN:
                warn_tools.append(name)
            tools[name] = {
                "calls": entry["calls"],
                "errors": entry["errors"],
                "mean_ms": round(sum(latencies) / n, 3) if n else None,
                "p50_ms": round(p50, 3) if n else None,
                "p95_ms": round(p95, 3) if n else None,
                "warn_ms": round(warn_ms, 3),
                "slow_ms": round(slow_ms, 3),
                "status": status,
                "warn_breaches": sum(1 for ms in latencies if ms > warn_ms),
                "slow_breaches": sum(1 for ms in latencies if ms > slow_ms),
            }
        return {
            "tools": tools,
            "total_calls": sum(t["calls"] for t in tools.values()),
            "total_errors": sum(t["errors"] for t in tools.values()),
            "budget_breaches": {"warn": warn_tools, "slow": slow_tools},
        }

    def render_text(self):
        """The metrics section appended to the cinder://info output."""
        lines = ["# Tool metrics (cinder-mcp, this session)"]
        snapshot = self.snapshot()
        if not snapshot["tools"]:
            lines.append("(no tool calls yet)")
            return "\n".join(lines)
        for name, stats in snapshot["tools"].items():
            line = (
                "tool:%s calls:%d errors:%d mean_ms:%.3f p50_ms:%.3f "
                "p95_ms:%.3f status:%s"
                % (
                    name,
                    stats["calls"],
                    stats["errors"],
                    stats["mean_ms"],
                    stats["p50_ms"],
                    stats["p95_ms"],
                    stats["status"],
                )
            )
            if stats["warn_breaches"]:
                line += " warn_breaches:%d" % stats["warn_breaches"]
            if stats["slow_breaches"]:
                line += " slow_breaches:%d" % stats["slow_breaches"]
            lines.append(line)
        breaches = snapshot["budget_breaches"]
        lines.append(
            "# Latency budget breaches: warn: %s; slow: %s"
            % (
                ", ".join(breaches["warn"]) if breaches["warn"] else "(none)",
                ", ".join(breaches["slow"]) if breaches["slow"] else "(none)",
            )
        )
        return "\n".join(lines)
