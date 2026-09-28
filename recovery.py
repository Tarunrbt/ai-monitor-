"""
recovery.py
Fully-automated self-healing: on a critical finding (crash-loop, or a
process that has vanished when it shouldn't have), attempt to restart the
affected process.

SAFETY DESIGN (read before enabling `enable_auto_recovery`):
  1. Whitelist-only — this NEVER touches a process unless it is explicitly
     listed in config["auto_recover"] by name. Unlisted/system processes are
     never killed or restarted, no matter how critical the finding.
  2. Cooldown — won't attempt a second recovery on the same process within
     config["recovery_cooldown_sec"].
  3. Circuit breaker — stops attempting after config["recovery_max_per_hour"]
     successful restarts in the last hour, to avoid infinite restart storms
     on a process that's fundamentally broken (needs a human at that point).
  4. Every attempt — success, failure, or skip — is logged to the
     `recovery_actions` table with the reason, for a full audit trail.
"""

import subprocess
import time

import psutil


class RecoveryManager:
    def __init__(self, config: dict, storage, notifier):
        self.config = config
        self.storage = storage
        self.notifier = notifier

    def _is_whitelisted(self, name: str) -> bool:
        return name in (self.config.get("auto_recover") or {})

    def _within_limits(self, name: str) -> tuple:
        """Returns (ok: bool, reason: str)."""
        cooldown = self.config.get("recovery_cooldown_sec", 60)
        last_ts = self.storage.last_recovery_ts(name)
        if last_ts and (time.time() - last_ts) < cooldown:
            return False, "skipped_cooldown"

        max_per_hour = self.config.get("recovery_max_per_hour", 3)
        attempts = self.storage.recovery_attempts_since(name, time.time() - 3600)
        if attempts >= max_per_hour:
            return False, "skipped_limit"

        return True, ""

    def _kill(self, name: str, collector) -> list:
        """Terminate all currently-known live pids for this process name. Returns pids killed."""
        killed = []
        for pid in collector.pids_for_name(name):
            try:
                p = psutil.Process(pid)
                p.terminate()
                try:
                    p.wait(timeout=5)
                except psutil.TimeoutExpired:
                    p.kill()
                killed.append(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return killed

    def _restart(self, name: str, spec: dict, collector) -> tuple:
        """Executes the configured recovery strategy. Returns (ok: bool, detail: str)."""
        strategy = spec.get("strategy", "command")

        if strategy == "command":
            cmd = spec.get("restart_command")
            if not cmd:
                return False, "no restart_command configured"
            try:
                subprocess.Popen(
                    cmd, shell=isinstance(cmd, str),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                return True, f"launched: {cmd}"
            except Exception as e:
                return False, f"launch failed: {e}"

        if strategy == "relaunch":
            cmdline = collector.last_cmdline_for(name)
            if not cmdline:
                return False, "no known cmdline to relaunch"
            try:
                subprocess.Popen(cmdline, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return True, f"relaunched: {' '.join(cmdline)}"
            except Exception as e:
                return False, f"relaunch failed: {e}"

        return False, f"unknown strategy '{strategy}'"

    def handle_finding(self, finding, collector):
        """
        Entry point called by the agent loop for each finding. Only acts on
        'critical' severity findings for whitelisted process names.
        """
        if not self.config.get("enable_auto_recovery"):
            return
        if finding.severity != "critical":
            return

        name = finding.scope
        if not self._is_whitelisted(name):
            return  # hard safety boundary — never act on unlisted processes

        ok, skip_reason = self._within_limits(name)
        if not ok:
            self.storage.log_recovery(name, finding.message, "n/a", skip_reason)
            return

        spec = self.config["auto_recover"][name]

        # Kill first (covers both "still alive but broken" and "already crashed" cases)
        self._kill(name, collector)
        time.sleep(1)

        success, detail = self._restart(name, spec, collector)
        outcome = "success" if success else "failed"
        self.storage.log_recovery(name, finding.message, spec.get("strategy", "command"), outcome, detail)

        sev = "info" if success else "critical"
        msg = (f"Auto-recovery {'succeeded' if success else 'FAILED'} for {name}: {detail}")
        self.notifier.notify(name, sev, msg)
