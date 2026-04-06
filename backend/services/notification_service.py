"""
Notification Service
====================
Supports Slack, email (SMTP), and generic webhook alerts.
All methods fail silently with logging — notifications must never block scans.
"""

import os
import json
import logging
import smtplib
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy.orm import Session
from database import models

logger = logging.getLogger(__name__)


class NotificationService:
    """
    Sends notifications via Slack, email, or generic HTTP webhook.
    Configuration is loaded from NotificationConfig records in the DB.
    """

    # ── Slack ──────────────────────────────────────────────────────────────────

    def send_slack(self, webhook_url: str, message: str, blocks: list = None) -> bool:
        """Post a message to a Slack incoming webhook."""
        payload = {"text": message}
        if blocks:
            payload["blocks"] = blocks
        try:
            r = requests.post(
                webhook_url,
                json=payload,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )
            if r.status_code == 200:
                logger.info("Slack notification sent.")
                return True
            logger.warning("Slack webhook returned %s: %s", r.status_code, r.text[:100])
        except Exception as e:
            logger.error("Slack notification failed: %s", e)
        return False

    # ── Email ──────────────────────────────────────────────────────────────────

    def send_email(self, to: str, subject: str, body_html: str) -> bool:
        """Send email via configured SMTP server."""
        smtp_host = os.getenv("SMTP_HOST", "")
        smtp_port = int(os.getenv("SMTP_PORT", "587"))
        smtp_user = os.getenv("SMTP_USER", "")
        smtp_pass = os.getenv("SMTP_PASS", "")
        from_addr = os.getenv("SMTP_FROM", smtp_user)

        if not smtp_host or not smtp_user:
            logger.warning("Email not configured (SMTP_HOST / SMTP_USER missing). Skipping.")
            return False

        msg                          = MIMEMultipart("alternative")
        msg["Subject"]               = subject
        msg["From"]                  = from_addr
        msg["To"]                    = to
        msg.attach(MIMEText(body_html, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(from_addr, [to], msg.as_string())
            logger.info("Email sent to %s: %s", to, subject)
            return True
        except Exception as e:
            logger.error("Email send failed to %s: %s", to, e)
        return False

    # ── Webhook ────────────────────────────────────────────────────────────────

    def send_webhook(self, url: str, payload: dict) -> bool:
        """POST a JSON payload to an arbitrary webhook URL."""
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code < 300:
                logger.info("Webhook %s → %s", url[:50], r.status_code)
                return True
            logger.warning("Webhook %s returned %s", url[:50], r.status_code)
        except Exception as e:
            logger.error("Webhook delivery failed for %s: %s", url[:50], e)
        return False

    # ── Orchestrated Notify ────────────────────────────────────────────────────

    def notify_scan_complete(
        self,
        job_id: str,
        target: str,
        scan_type: str,
        critical_count: int,
        high_count: int,
        total_vulns: int,
        db: Session,
    ):
        """
        Dispatch notifications for all active configs that match the
        'scan_complete' trigger (or 'critical_found' if criticals > 0).
        """
        configs = db.query(models.NotificationConfig).filter_by(is_active=True).all()
        if not configs:
            return

        summary_text = (
            f"🔍 SwitchGuard Scan Complete\n"
            f"Target: {target} | Type: {scan_type.upper()}\n"
            f"Findings: {total_vulns} total | 🔴 Critical: {critical_count} | 🟠 High: {high_count}\n"
            f"Job ID: {job_id}"
        )
        summary_html = f"""
        <h2>SwitchGuard — Scan Completed</h2>
        <p><b>Target:</b> {target}</p>
        <p><b>Scan Type:</b> {scan_type.upper()}</p>
        <table border="1" cellpadding="6">
            <tr><th>Severity</th><th>Count</th></tr>
            <tr><td>Critical</td><td style="color:red">{critical_count}</td></tr>
            <tr><td>High</td><td style="color:orange">{high_count}</td></tr>
            <tr><td>Total</td><td>{total_vulns}</td></tr>
        </table>
        <p>Job ID: <code>{job_id}</code></p>
        """

        for cfg in configs:
            should_notify = (
                cfg.trigger == "all"
                or cfg.trigger == "scan_complete"
                or (cfg.trigger == "critical_found" and critical_count > 0)
            )
            if not should_notify:
                continue

            if cfg.channel == "slack":
                self.send_slack(cfg.target, summary_text)
            elif cfg.channel == "email":
                self.send_email(
                    cfg.target,
                    f"[SwitchGuard] Scan Complete: {target}",
                    summary_html,
                )
            elif cfg.channel in ("webhook", "teams"):
                payload = {
                    "job_id":         job_id,
                    "target":         target,
                    "scan_type":      scan_type,
                    "critical_count": critical_count,
                    "high_count":     high_count,
                    "total_vulns":    total_vulns,
                }
                self.send_webhook(cfg.target, payload)
