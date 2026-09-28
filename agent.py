"""
agent.py
Main orchestrator for the AI Monitoring Agent.

Pipeline per cycle:
  1. Collector takes a snapshot of all processes.
  2. Baseliner checks each sample against that process's learned normal
     BEFORE updating the baseline, so the anomaly does not blunt itself.
  3. Every ~1 min, Analyzer runs fixed-threshold, trend, crash-loop and
     long-running checks over the rolling window.
  4. SuggestionEngine turns findings into actionable advice.
  5. Notifier sends real-time alerts with cooldown/dedup handled by Notifier.
  6. RecoveryManager handles policy-controlled recovery. Recovery must remain
     disabled by default and must enforce its own allowlist/safety checks.

Run:
    python3 agent.py
    python3 agent.py --once
    python3 agent.py --report
    python3 agent.py --recovery-log
"""

import argparse
import sys
import time

from config import load_config
from storage import Storage
from collector import Collector
from analyzer import Analyzer
from baseline import Baseliner
from notifier import Notifier
from recovery import RecoveryManager
import suggestion_engine as se


# Example: 12 samples × 5 seconds = approximately 60 seconds.
ANALYSIS_EVERY_N_SAMPLES = 12


def print_findings(findings, suggestions):
    """Print actionable suggestions for current findings."""

    if not findings:
        return

    print(
        f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} | "
        f"{len(findings)} finding(s) ---"
    )

    for suggestion in suggestions:
        icon = {
            "critical": "🔴",
            "warn": "🟡",
            "info": "🔵",
        }.get(
            suggestion.get("severity"),
            "•",
        )

        print(
            f"{icon} "
            f"{suggestion.get('scope', 'unknown')}: "
            f"{suggestion.get('message', '')}"
        )


class Pipeline:
    """Wire together the monitoring components."""

    def __init__(self, config):
        self.config = config

        self.storage = Storage(config["db_path"])

        self.collector = Collector(
            config,
            self.storage,
        )

        self.analyzer = Analyzer(
            config,
            self.storage,
        )

        self.baseliner = Baseliner(
            config,
            self.storage,
        )

        self.notifier = Notifier(
            config,
            self.storage,
        )

        self.recovery = RecoveryManager(
            config,
            self.storage,
            self.notifier,
        )

    def sample_and_baseline(self):
        """
        Collect one sample and evaluate it against the existing baseline.

        The current value is checked BEFORE being added to the baseline.
        Anomalous metrics are not used to train their own baseline.
        """

        samples = self.collector.sample_once()

        baseline_findings = []

        for sample in samples:
            self.storage.insert_sample(sample)

            # Check BEFORE updating baseline.
            sample_findings, anomaly_metrics = (
                self.analyzer.baseline_findings(
                    self.baseliner,
                    sample,
                )
            )

            baseline_findings.extend(sample_findings)

            name = sample["name"]

            # Freeze only the anomalous metric.
            if "cpu" not in anomaly_metrics:
                self.baseliner.update(
                    name,
                    "cpu",
                    sample["cpu_percent"],
                )

            if "mem" not in anomaly_metrics:
                self.baseliner.update(
                    name,
                    "mem",
                    sample["mem_percent"],
                )

        return samples, baseline_findings

    def handle_findings(self, findings):
        """Notify and optionally recover from current findings."""

        if not findings:
            return

        suggestions = se.generate_rule_based_suggestions(
            findings,
            self.storage,
        )

        print_findings(
            findings,
            suggestions,
        )

        # Prevent multiple recovery attempts for the same process
        # during a single analysis cycle.
        recovery_scopes = set()

        for finding in findings:

            scope = getattr(
                finding,
                "scope",
                None,
            )

            severity = getattr(
                finding,
                "severity",
                "info",
            )

            message = getattr(
                finding,
                "message",
                "",
            )

            # Notification system handles its own configured
            # severity threshold and cooldown/deduplication.
            self.notifier.notify(
                scope,
                severity,
                message,
            )

            # RecoveryManager must independently enforce:
            # - enable_auto_recovery
            # - CRITICAL-only policy
            # - process allowlist
            # - restart limits
            # - cooldown
            # - platform compatibility
            #
            # We additionally avoid asking it repeatedly for the
            # same scope during this cycle.
            if scope not in recovery_scopes:

                recovery_scopes.add(scope)

                self.recovery.handle_finding(
                    finding,
                    self.collector,
                )

        # Optional LLM pass.
        #
        # The LLM should receive findings/evidence only. It should NOT
        # receive unrestricted system-command execution capability.
        if (
            self.config.get(
                "enable_llm_suggestions",
                False,
            )
            and findings
        ):

            print("\n--- Deeper LLM analysis ---")

            print(
                se.generate_llm_suggestions(
                    findings,
                    self.config,
                )
            )


def run_once(config):
    """
    Single sample + immediate analysis.

    Useful for cron/Termux:Tasker.
    """

    pipe = Pipeline(config)

    # psutil cpu_percent() needs a first call to establish its
    # measurement interval.
    pipe.collector.sample_once()

    time.sleep(1)

    samples, baseline_findings = (
        pipe.sample_and_baseline()
    )

    findings = pipe.analyzer.analyze_all(
        pipe.collector
    )

    findings.extend(
        baseline_findings
    )

    pipe.handle_findings(
        findings
    )


def run_report(config):
    """Print recent stored suggestions without sampling."""

    storage = Storage(
        config["db_path"]
    )

    rows = storage.recent_suggestions(
        limit=30
    )

    if not rows:
        print(
            "No suggestions logged yet. "
            "Run the agent first."
        )
        return

    for ts, scope, severity, message in rows:

        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(ts),
        )

        icon = {
            "critical": "🔴",
            "warn": "🟡",
            "info": "🔵",
        }.get(
            severity,
            "•",
        )

        print(
            f"{icon} [{timestamp}] "
            f"{scope}: {message}"
        )


def run_recovery_log(config):
    """Print recent recovery attempts."""

    storage = Storage(
        config["db_path"]
    )

    rows = storage.recent_recovery_actions(
        limit=30
    )

    if not rows:
        print(
            "No recovery actions logged yet."
        )
        return

    for (
        ts,
        scope,
        strategy,
        outcome,
        detail,
    ) in rows:

        timestamp = time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(ts),
        )

        icon = {
            "success": "✅",
            "failed": "❌",
        }.get(
            outcome,
            "⏭️",
        )

        print(
            f"{icon} [{timestamp}] "
            f"{scope} ({strategy}): "
            f"{outcome} — {detail}"
        )


def run_continuous(config):
    """Run the monitoring agent continuously."""

    pipe = Pipeline(config)

    interval = config[
        "sample_interval_sec"
    ]

    recovery_enabled = config.get(
        "enable_auto_recovery",
        False,
    )

    print(
        "AI Monitoring Agent started. "
        f"Sampling every {interval}s. "
        f"Auto-recovery: "
        f"{'ON' if recovery_enabled else 'off'}. "
        "Ctrl+C to stop."
    )

    # Warm up psutil CPU measurements.
    pipe.collector.sample_once()

    tick = 0

    try:

        while True:

            time.sleep(interval)

            (
                samples,
                baseline_findings,
            ) = pipe.sample_and_baseline()

            tick += 1

            # Baseline checks happen every cycle.
            findings = list(
                baseline_findings
            )

            # Rolling-window analysis happens periodically.
            if (
                tick
                % ANALYSIS_EVERY_N_SAMPLES
                == 0
            ):

                findings.extend(
                    pipe.analyzer.analyze_all(
                        pipe.collector
                    )
                )

            pipe.handle_findings(
                findings
            )

    except KeyboardInterrupt:

        print(
            "\nStopped."
        )


def main():

    parser = argparse.ArgumentParser(
        description="AI Monitoring Agent"
    )

    parser.add_argument(
        "--once",
        action="store_true",
        help="Single sample + analysis pass",
    )

    parser.add_argument(
        "--report",
        action="store_true",
        help="Print recent suggestions",
    )

    parser.add_argument(
        "--recovery-log",
        action="store_true",
        help="Print recent recovery actions",
    )

    parser.add_argument(
        "--config",
        type=str,
        default=None,
        help="Path to config.json override",
    )

    args = parser.parse_args()

    config = load_config(
        args.config
    )

    if args.report:

        run_report(config)

    elif args.recovery_log:

        run_recovery_log(config)

    elif args.once:

        run_once(config)

    else:

        run_continuous(config)


if __name__ == "__main__":

    sys.exit(
        main()
    )
