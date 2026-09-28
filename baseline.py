import math


class Baseliner:
    """
    Process-specific adaptive baseline using Welford's algorithm.

    CPU/RAM anomaly policy:
    Only unusually HIGH values generate findings.
    Tiny absolute fluctuations are ignored.
    """

    def __init__(self, config, storage):
        self.config = config
        self.storage = storage

    def update(self, name, metric, value):
        """Update process/metric baseline."""

        if value is None:
            return

        try:
            value = float(value)
        except (TypeError, ValueError):
            return

        row = self.storage.get_baseline(name, metric)

        if row is None:
            count = 0
            mean = 0.0
            m2 = 0.0
        else:
            if hasattr(row, "keys"):
                count = int(row["count"])
                mean = float(row["mean"])
                m2 = float(row["m2"])
            else:
                count = int(row[0])
                mean = float(row[1])
                m2 = float(row[2])

        count += 1

        delta = value - mean
        mean += delta / count
        delta2 = value - mean
        m2 += delta * delta2

        self.storage.upsert_baseline(
            name=name,
            metric=metric,
            count=count,
            mean=mean,
            m2=m2,
        )

    def stats(self, name, metric):
        """Return baseline statistics."""

        row = self.storage.get_baseline(name, metric)

        if row is None:
            return None

        if hasattr(row, "keys"):
            count = int(row["count"])
            mean = float(row["mean"])
            m2 = float(row["m2"])
        else:
            count = int(row[0])
            mean = float(row[1])
            m2 = float(row[2])

        if count > 1:
            variance = m2 / (count - 1)
            stddev = math.sqrt(max(variance, 0.0))
        else:
            stddev = 0.0

        return {
            "count": count,
            "mean": mean,
            "stddev": stddev,
        }

    def deviation(self, name, metric, value):
        """Calculate z-score against learned baseline."""

        stats = self.stats(name, metric)

        if stats is None:
            return None

        min_samples = int(
            self.config.get("baseline_min_samples", 20)
        )

        if stats["count"] < min_samples:
            return None

        mean = stats["mean"]
        stddev = stats["stddev"]

        if stddev <= 0:
            return 0.0

        try:
            value = float(value)
        except (TypeError, ValueError):
            return None

        return (value - mean) / stddev

    def anomaly_finding(self, name, metric, value):
        """
        Generate a finding only for unusually HIGH
        CPU/RAM relative to the learned baseline.

        Tiny absolute changes are ignored so that
        near-zero variance does not create false alerts.
        """

        try:
            v = float(value)
        except (TypeError, ValueError):
            return None

        stats = self.stats(name, metric)

        if stats is None:
            return None

        z = self.deviation(name, metric, v)

        if z is None:
            return None

        # Ignore unusually LOW CPU/RAM.
        if metric in ("cpu", "mem") and z <= 0:
            return None

        # Ignore tiny absolute changes.
        min_abs = float(
            self.config.get(
                "baseline_min_abs_value",
                1.0,
            )
        )

        # Low-utilization regime guard: for processes whose baseline mean is
        # already small (e.g. python3 idling at ~1.6% CPU), tiny statistical
        # deviations produce a large z-score even though the absolute change
        # is practically noise. Require a stronger absolute delta in that
        # regime, without touching sensitivity for normal/high-baseline
        # processes.
        low_util_mean = float(
            self.config.get(
                "baseline_low_utilization_mean",
                5.0,
            )
        )
        low_util_abs = float(
            self.config.get(
                "baseline_low_utilization_abs_delta",
                3.0,
            )
        )

        if metric in ("cpu", "mem") and stats["mean"] < low_util_mean:
            min_abs = max(min_abs, low_util_abs)

        if metric in ("cpu", "mem"):
            if abs(v - stats["mean"]) < min_abs:
                return None

        warn_z = float(
            self.config.get(
                "baseline_z_warn",
                2.5,
            )
        )

        critical_z = float(
            self.config.get(
                "baseline_z_critical",
                4.0,
            )
        )

        if z >= critical_z:
            severity = "critical"
        elif z >= warn_z:
            severity = "warn"
        else:
            return None

        return {
            "severity": severity,
            "name": name,
            "metric": metric,
            "value": v,
            "mean": stats["mean"],
            "stddev": stats["stddev"],
            "z": z,
            "message": (
                f"{name}: {metric.upper()} deviates from this "
                f"process's own baseline: "
                f"{v:.1f}% vs normal ~"
                f"{stats['mean']:.1f}% (z={z:.1f})"
            ),
        }
