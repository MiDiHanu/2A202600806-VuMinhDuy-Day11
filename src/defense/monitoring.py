"""
Defense-in-Depth — Layer 8 (monitoring): Alerts on anomalous metrics

Why monitor?
  - Each individual layer is good, but the SYSTEM as a whole can be
    degrading. A spike in the rate-limit hit rate means someone is
    brute-forcing. A spike in judge-FAIL means an attacker found a new
    prompt pattern. You need a way to know.
  - In production this is what pages the on-call engineer.

Design:
  - Aggregate counters over the audit log (single source of truth).
  - Configurable thresholds; alerts are simple strings for this lab,
    but in production they'd be PagerDuty / Slack / email payloads.
"""
from collections import Counter
from defense.audit_log import AuditLog


class MonitoringAlerts:
    """Compute security metrics from the audit log and raise alerts."""

    def __init__(
        self,
        block_rate_alert: float = 0.20,   # >20% of requests blocked = alert
        judge_fail_alert: float = 0.10,    # >10% judge FAIL = alert
        rate_limit_alert: int = 5,         # >5 rate-limit hits = alert
    ):
        self.block_rate_alert = block_rate_alert
        self.judge_fail_alert = judge_fail_alert
        self.rate_limit_alert = rate_limit_alert

    def metrics(self, audit: AuditLog) -> dict:
        records = audit.all_records()
        total = len(records)
        blocked_at = Counter(r.blocked_at_layer for r in records if r.blocked_at_layer)
        judge_fails = sum(
            1 for r in records
            if r.blocked_at_layer == "llm_judge"
        )
        block_rate = (sum(blocked_at.values()) / total) if total else 0.0
        return {
            "total_requests": total,
            "blocked_total": sum(blocked_at.values()),
            "blocked_by_layer": dict(blocked_at),
            "block_rate": block_rate,
            "judge_fails": judge_fails,
            "judge_fail_rate": (judge_fails / total) if total else 0.0,
            "rate_limit_hits": blocked_at.get("rate_limiter", 0),
        }

    def check(self, audit: AuditLog) -> list[str]:
        """Return a list of alert strings (empty list = no alerts)."""
        m = self.metrics(audit)
        alerts = []
        if m["block_rate"] > self.block_rate_alert:
            alerts.append(
                f"HIGH BLOCK RATE: {m['block_rate']:.0%} of requests blocked "
                f"(threshold {self.block_rate_alert:.0%})"
            )
        if m["judge_fail_rate"] > self.judge_fail_alert:
            alerts.append(
                f"HIGH JUDGE-FAIL RATE: {m['judge_fail_rate']:.0%} "
                f"(threshold {self.judge_fail_alert:.0%}) — possible new attack"
            )
        if m["rate_limit_hits"] > self.rate_limit_alert:
            alerts.append(
                f"ABUSIVE USER: {m['rate_limit_hits']} rate-limit hits "
                f"(threshold {self.rate_limit_alert})"
            )
        return alerts
