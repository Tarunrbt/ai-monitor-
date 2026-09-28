"""
notifier.py
Real-time alert notifications for findings. Supports multiple channels:
console (always available), a generic webhook (Slack/Discord/Make/Zapier —
anything that accepts a JSON POST), Termux local notifications (for your
Android/Termux workflow), and optional SMTP email.

Cooldown/dedup: the same scope+KIND-of-message (numbers stripped) won't be
re-sent within config["notify_cooldown_sec"] so a stuck process doesn't spam
every cycle even as its live reading changes.
"""

import json
import re
import shutil
import subprocess
import time
import urllib.request

_SEVERITY_ORDER = {"info": 0, "warn": 1, "critical": 2}
_NUM_RE = re.compile(r"[-+]?\d+\.?\d*")


def _dedup_key(message: str) -> str:
    return _NUM_RE.sub("N", message)


class Notifier:
    def __init__(self, config: dict, storage):
        self.config = config
        self.storage = storage

    def _should_send(self, scope: str, severity: str, message: str) -> bool:
        min_sev = self.config.get("notify_min_severity", "warn")
        if _SEVERITY_ORDER.get(severity, 0) < _SEVERITY_ORDER.get(min_sev, 1):
            return False
        last = self.storage.last_alert_ts(scope, _dedup_key(message))
        cooldown = self.config.get("notify_cooldown_sec", 300)
        return (time.time() - last) >= cooldown

    def notify(self, scope: str, severity: str, message: str):
        if not self._should_send(scope, severity, message):
            return

        if self.config.get("notify_console", True):
            self._send_console(scope, severity, message)

        url = self.config.get("notify_webhook_url")
        if url:
            self._send_webhook(url, scope, severity, message)

        if self.config.get("notify_termux") and shutil.which("termux-notification"):
            self._send_termux(scope, severity, message)

        email_cfg = self.config.get("notify_email") or {}
        if email_cfg.get("enabled") and email_cfg.get("smtp_host"):
            self._send_email(email_cfg, scope, severity, message)

    def _send_console(self, scope, severity, message):
        icon = {"critical": "🔴", "warn": "🟡", "info": "🔵"}.get(severity, "•")
        print(f"{icon} ALERT [{severity.upper()}] {scope}: {message}")
        self.storage.log_alert(scope, severity, message, "console", _dedup_key(message))

    def _send_webhook(self, url, scope, severity, message):
        payload = json.dumps({
            "text": f"[{severity.upper()}] {scope}: {message}",
            "scope": scope, "severity": severity, "message": message,
            "ts": time.time(),
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, headers={"Content-Type": "application/json"}
        )
        try:
            urllib.request.urlopen(req, timeout=5)
            self.storage.log_alert(scope, severity, message, "webhook", _dedup_key(message))
        except Exception as e:
            print(f"[notifier] webhook send failed: {e}")

    def _send_termux(self, scope, severity, message):
        try:
            subprocess.run(
                ["termux-notification", "--title", f"[{severity.upper()}] {scope}",
                 "--content", message],
                check=False, timeout=5,
            )
            self.storage.log_alert(scope, severity, message, "termux", _dedup_key(message))
        except Exception as e:
            print(f"[notifier] termux-notification failed: {e}")

    def _send_email(self, email_cfg, scope, severity, message):
        import smtplib
        from email.mime.text import MIMEText
        try:
            msg = MIMEText(message)
            msg["Subject"] = f"[Monitoring Agent] [{severity.upper()}] {scope}"
            msg["From"] = email_cfg["from_addr"]
            msg["To"] = email_cfg["to_addr"]
            with smtplib.SMTP(email_cfg["smtp_host"], email_cfg.get("smtp_port", 587)) as s:
                s.starttls()
                s.login(email_cfg["username"], email_cfg["password"])
                s.send_message(msg)
            self.storage.log_alert(scope, severity, message, "email", _dedup_key(message))
        except Exception as e:
            print(f"[notifier] email send failed: {e}")
