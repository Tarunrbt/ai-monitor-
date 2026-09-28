"""
analyzer.py

Turns raw samples into findings:

    - sustained high CPU/memory
    - process-specific baseline deviations
    - rising CPU/memory trends
    - restart/crash-loop indicators
    - long-running processes

The Analyzer reads from Storage and Collector state.
It does not execute recovery actions itself.
"""

import statistics
import time


class Finding:
    def __init__(
        self,
        scope: str,
        severity: str,
        message: str,
        evidence: dict,
    ):
        self.scope = scope
        self.severity = severity
        self.message = message
        self.evidence = evidence

    def __repr__(self):
        return (
            f"[{self.severity.upper()}] "
            f"{self.scope}: {self.message}"
        )


class Analyzer:

    def __init__(self, config: dict, storage):
        self.config = config
        self.storage = storage

    def _severity_for(
        self,
        value: float,
        warn: float,
        critical: float,
    ) -> str:

        if value >= critical:
            return "critical"

        if value >= warn:
            return "warn"

        return "info"

    def _is_ignored(self, name: str) -> bool:
        """Match ignore_names using case-insensitive substring matching."""
        name_lower = (name or "unknown").lower()
        return any(
            str(token).lower() in name_lower
            for token in self.config.get("ignore_names", [])
        )

    def analyze_process(
        self,
        name: str,
        window_sec: int,
    ) -> list:
        """
        Analyze recent samples for one process.
        """

        cutoff = (
            time.time()
            - window_sec
        )

        rows = self.storage.recent_samples(
            name,
            cutoff,
        )

        if not rows:
            return []

        findings = []

        # Expected Storage row layout:
        # row[1] = CPU
        # row[2] = memory
        cpu_vals = [
            r[1]
            for r in rows
            if r[1] is not None
        ]

        mem_vals = [
            r[2]
            for r in rows
            if r[2] is not None
        ]

        # ---------------------------------------------------------
        # CPU
        # ---------------------------------------------------------

        if cpu_vals:

            avg_cpu = statistics.mean(
                cpu_vals
            )

            max_cpu = max(
                cpu_vals
            )

            severity = self._severity_for(
                avg_cpu,
                self.config[
                    "cpu_percent_warn"
                ],
                self.config[
                    "cpu_percent_critical"
                ],
            )

            if severity != "info":

                findings.append(
                    Finding(
                        scope=name,
                        severity=severity,
                        message=(
                            "Sustained high CPU usage: "
                            f"avg {avg_cpu:.1f}%, "
                            f"peak {max_cpu:.1f}% "
                            f"over last "
                            f"{window_sec // 60} min"
                        ),
                        evidence={
                            "avg_cpu": avg_cpu,
                            "max_cpu": max_cpu,
                            "samples": len(
                                cpu_vals
                            ),
                        },
                    )
                )

            findings.extend(
                self._trend_finding(
                    name,
                    "cpu",
                    cpu_vals,
                )
            )

        # ---------------------------------------------------------
        # Memory
        # ---------------------------------------------------------

        if mem_vals:

            avg_mem = statistics.mean(
                mem_vals
            )

            max_mem = max(
                mem_vals
            )

            severity = self._severity_for(
                avg_mem,
                self.config[
                    "mem_percent_warn"
                ],
                self.config[
                    "mem_percent_critical"
                ],
            )

            if severity != "info":

                findings.append(
                    Finding(
                        scope=name,
                        severity=severity,
                        message=(
                            "Sustained high memory usage: "
                            f"avg {avg_mem:.1f}%, "
                            f"peak {max_mem:.1f}% "
                            f"over last "
                            f"{window_sec // 60} min"
                        ),
                        evidence={
                            "avg_mem": avg_mem,
                            "max_mem": max_mem,
                            "samples": len(
                                mem_vals
                            ),
                        },
                    )
                )

            findings.extend(
                self._trend_finding(
                    name,
                    "mem",
                    mem_vals,
                )
            )

        return findings

    def _trend_finding(
        self,
        name: str,
        metric: str,
        values: list,
    ) -> list:
        """
        Detect sustained upward movement.

        Compares the first third with the last third
        of the available samples.
        """

        if len(values) < 9:
            return []

        third = len(values) // 3

        first_values = values[
            :third
        ]

        last_values = values[
            -third:
        ]

        first_avg = statistics.mean(
            first_values
        )

        last_avg = statistics.mean(
            last_values
        )

        if first_avg <= 0:
            return []

        growth = (
            (last_avg - first_avg)
            / max(first_avg, 1e-6)
        )

        # Configurable thresholds with safe defaults.
        growth_threshold = self.config.get(
            "trend_growth_warn",
            0.50,
        )

        absolute_threshold = self.config.get(
            "trend_absolute_warn",
            20.0,
        )

        if (
            growth > growth_threshold
            and last_avg > absolute_threshold
        ):

            return [
                Finding(
                    scope=name,
                    severity="warn",
                    message=(
                        f"{metric.upper()} usage trending "
                        f"up (+{growth * 100:.0f}%) — "
                        "possible leak or unbounded growth"
                    ),
                    evidence={
                        "metric": metric,
                        "first_avg": first_avg,
                        "last_avg": last_avg,
                        "growth_ratio": growth,
                    },
                )
            ]

        return []

    def analyze_crash_loops(
        self,
        collector,
    ) -> list:
        """
        Detect excessive process starts within a short window.

        Note:
            The Collector currently tracks START events.
            Therefore this is technically a restart/churn indicator,
            not definitive proof that every termination was a crash.
        """

        findings = []

        threshold = self.config[
            "crash_loop_threshold"
        ]

        window_sec = self.config.get(
            "crash_loop_window_sec",
            300,
        )


        for name in list(
            collector._start_counts.keys()
        ):
            if self._is_ignored(name):
                continue

            if name in self.config.get("crash_loop_ignore_names", []):
                continue

            count = collector.crash_loop_count(
                name,
                window_sec=window_sec,
            )

            if count >= threshold:

                findings.append(
                    Finding(
                        scope=name,
                        severity="critical",
                        message=(
                            "Possible crash/restart loop: "
                            f"{count} starts in the last "
                            f"{window_sec // 60} min"
                        ),
                        evidence={
                            "start_count": count,
                            "window_sec": window_sec,
                            "classification": (
                                "restart_churn_indicator"
                            ),
                        },
                    )
                )

        return findings

    def analyze_long_running(
        self,
        collector,
    ) -> list:
        """
        Identify processes that have exceeded the configured
        runtime threshold.

        This is informational only and must NOT trigger
        automatic recovery by itself.
        """

        findings = []

        now = time.time()

        threshold = self.config[
            "long_running_threshold_sec"
        ]

        for pid, meta in (
            collector._known_pids.items()
        ):
            if self._is_ignored(meta["name"]):
                continue

            if meta["name"] in self.config.get("long_running_ignore_names", []):
                continue

            # The monitoring agent itself is always long-running by design;
            # flagging it is pure noise. Other python3 processes stay monitored.
            import os as _os
            if pid == _os.getpid():
                continue

            age = (
                now
                - meta["start_ts"]
            )

            if age >= threshold:
                # Report each long-running PID once, then only again after
                # long_running_repeat_sec (default 6h), not every analysis cycle.
                last_map = self.__dict__.setdefault("_long_running_last", {})
                repeat_sec = float(self.config.get("long_running_repeat_sec", 21600))
                if now - last_map.get(pid, 0.0) < repeat_sec:
                    continue
                last_map[pid] = now

                findings.append(
                    Finding(
                        scope=meta["name"],
                        severity="info",
                        message=(
                            f"Long-running process "
                            f"(pid {pid}) alive "
                            f"{age / 3600:.1f}h — "
                            "confirm this is expected"
                        ),
                        evidence={
                            "pid": pid,
                            "age_sec": age,
                        },
                    )
                )

        return findings

    def baseline_findings(
        self,
        baseliner,
        sample: dict,
    ) -> tuple:
        """
        Compare a fresh sample against the process-specific
        learned baseline.

        Returns:
            findings: Finding objects for reporting
            anomaly_metrics: metric names whose baseline update
                must be skipped for this cycle
        """

        findings = []
        anomaly_metrics = set()

        name = sample["name"]

        # Use the same ignore_names matching semantics as collector.py.
        if self._is_ignored(name):
            return findings, anomaly_metrics

        metrics = (
            ("cpu", "cpu_percent"),
            ("mem", "mem_percent"),
        )

        for metric, key in metrics:
            value = sample.get(key)

            if value is None:
                continue

            result = baseliner.anomaly_finding(
                name,
                metric,
                value,
            )

            if result is None:
                continue

            # This metric is anomalous, so do not train its
            # baseline with the anomalous value.
            anomaly_metrics.add(metric)

            severity = result["severity"]
            z = result["z"]
            mean = result["mean"]

            findings.append(
                Finding(
                    scope=name,
                    severity=severity,
                    message=(
                        f"{metric.upper()} deviates "
                        "from this process's own baseline: "
                        f"{value:.1f}% vs normal "
                        f"~{mean:.1f}% "
                        f"(z={z:.1f})"
                    ),
                    evidence={
                        "metric": metric,
                        "value": value,
                        "baseline_mean": mean,
                        "z": z,
                    },
                )
            )

        return findings, anomaly_metrics

    def analyze_all(
        self,
        collector,
        window_sec: int = None,
    ) -> list:
        """
        Run all periodic analysis checks.
        """

        if window_sec is None:

            window_sec = (
                self.config[
                    "sample_interval_sec"
                ]
                * self.config[
                    "history_window"
                ]
            )

        findings = []

        process_names = (
            self.storage.distinct_process_names(
                time.time()
                - window_sec
            )
        )

        for name in process_names:

            findings.extend(
                self.analyze_process(
                    name,
                    window_sec,
                )
            )

        findings.extend(
            self.analyze_crash_loops(
                collector
            )
        )

        findings.extend(
            self.analyze_long_running(
                collector
            )
        )

        return findings
