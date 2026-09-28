"""
config.py
Central configuration for the AI Monitoring Agent.
Edit values here or override via environment variables / a config.json file.
"""

import json
import os

DEFAULT_CONFIG = {
    # How often (seconds) the collector samples running processes
    "sample_interval_sec": 5,

    # How many samples to keep in memory per process before summarizing
    "history_window": 60,          # 60 samples * 5s = 5 minutes rolling window

    # Thresholds that trigger an "alert" level finding
    "cpu_percent_warn": 70.0,
    "cpu_percent_critical": 90.0,
    "mem_percent_warn": 70.0,
    "mem_percent_critical": 90.0,

    # A process is flagged as "long running / possibly stuck" after this many seconds
    "long_running_threshold_sec": 3600,

    # Interactive shell processes can legitimately remain alive for hours.
    # Excluded from long-running detection ONLY; CPU/mem/baseline monitoring
    # remains active for these processes.
    "long_running_ignore_names": ["bash", "sh", "zsh", "dash"],

    # A process is flagged if it respawns/crashes more than N times in the window
    "crash_loop_threshold": 3,
    "crash_loop_window_sec": 300,
    "crash_loop_max_lifetime_sec": 60,

    # Process names shared across many unrelated, independent invocations
    # (interactive shells, common short-lived tools) -- for these, "N starts
    # in a window" does NOT mean "the same service crashed N times", it just
    # means N unrelated commands ran. Excluded from crash-loop detection ONLY
    # (CPU/mem/baseline monitoring for these names is unaffected).
    "crash_loop_ignore_names": ["bash", "sh", "zsh", "dash"],

    # ---------------- Trend detection ----------------
    # A metric is flagged as "trending up" (leak/degradation signature) when it
    # grows by more than this fraction AND its recent average exceeds the
    # absolute floor below (avoids flagging noise on near-zero values).
    "trend_growth_warn": 0.50,
    "trend_absolute_warn": 20.0,

    # SQLite DB file for persisted metrics + suggestions log
    "db_path": os.path.join(os.path.dirname(__file__), "monitoring.db"),

    # Only track processes matching these name substrings (empty list = track all)
    "watch_only": [],

    # Never track/report these (privacy / noise reduction)
    # runsv/svlogd/runsvdir are Termux's own runit service-supervision daemons —
    # they restart repeatedly by design (supervising whether a service is enabled),
    # which looks like a crash-loop but isn't. Ignored here on Termux specifically.
    "ignore_names": ["kworker", "ksoftirqd", "migration", "rcu_", "runsv", "svlogd", "runsvdir", "crond"],

    # Optional: hook for an LLM-based suggestion pass (off by default).
    # If enabled, the agent will call generate_llm_suggestions() in
    # suggestion_engine.py using the Anthropic API for deeper, qualitative advice.
    "enable_llm_suggestions": False,
    "llm_model": "claude-sonnet-4-6",

    # ---------------- Baselining ----------------
    # Minimum samples before a process gets a trusted baseline (avoids false
    # alarms on brand-new/short-lived processes)
    "baseline_min_samples": 20,
    # How many standard deviations from the learned baseline counts as anomalous
    "baseline_z_warn": 2.5,
    "baseline_z_critical": 4.0,
    "baseline_min_abs_value": 1.0,
    "baseline_low_utilization_mean": 5.0,
    "baseline_low_utilization_abs_delta": 3.0,
   
    # ---------------- Real-time alerting ----------------
    "notify_console": True,
    "notify_min_severity": "warn",      # 'info' | 'warn' | 'critical'
    "notify_webhook_url": None,          # generic HTTP POST (Slack/Discord/Zapier/Make webhook, etc.)
    "notify_termux": False,              # use termux-notification if running under Termux
    "notify_cooldown_sec": 300,          # don't re-notify same scope+message within this window
    "notify_email": {                    # optional SMTP alerting; leave host empty to disable
        "enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "username": "",
        "password": "",
        "from_addr": "",
        "to_addr": "",
    },

    # ---------------- Auto-recovery (self-healing) ----------------
    # SAFETY: disabled by default. Auto-restarting the wrong process can cause
    # data loss or outages, so this only ever acts on processes explicitly
    # listed in "auto_recover" below — never on unlisted/system processes.
    "enable_auto_recovery": False,
    "recovery_max_per_hour": 3,          # circuit breaker: stop auto-restarting after N attempts/hour
    "recovery_cooldown_sec": 60,         # minimum gap between two recovery actions on the same process
    # Map of process name -> recovery spec. Only these names are ever touched.
    #   "strategy": "command"  -> kill the process then run "restart_command"
    #   "strategy": "relaunch" -> kill the process then relaunch its last known
    #                             command line (captured from psutil at crash time)
    "auto_recover": {
        # "my_worker.py": {"strategy": "command", "restart_command": "python3 /path/my_worker.py"},
    },
}


def load_config(path: str = None) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    path = path or os.path.join(os.path.dirname(__file__), "config.json")
    if os.path.exists(path):
        with open(path, "r") as f:
            user_cfg = json.load(f)
        cfg.update(user_cfg)
    return cfg
