"""
Defense-in-Depth — Layer 5: Audit Log

Why this layer?
  - Catches: nothing on its own (audit is passive, never blocks).
  - But it is the ONLY layer that gives you forensic visibility AFTER an
    attack succeeds. Without a log you cannot answer "who, what, when,
    which layer missed it, and how often".
  - In production this is what compliance / SOC2 / PCI-DSS auditors will
    ask for first.

Design:
  - Append-only in-memory list of structured records.
  - export_json() writes to disk in a schema-stable format so the same
    records can be loaded by a SIEM, a Jupyter notebook, or `jq`.
"""
import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class AuditRecord:
    """One row in the audit log."""
    timestamp: float
    user_id: str
    request_text: str
    response_text: str
    blocked_at_layer: str       # "" if not blocked, else layer name
    latency_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLog:
    """Append-only audit log with JSON export."""

    def __init__(self):
        self._records: list[AuditRecord] = []

    def record(self, user_id: str, request_text: str, response_text: str,
               blocked_at_layer: str = "", latency_ms: float = 0.0,
               metadata: dict | None = None) -> None:
        """Append a new audit record."""
        self._records.append(AuditRecord(
            timestamp=time.time(),
            user_id=user_id,
            request_text=request_text,
            response_text=response_text,
            blocked_at_layer=blocked_at_layer,
            latency_ms=latency_ms,
            metadata=metadata or {},
        ))

    def all_records(self) -> list[AuditRecord]:
        return list(self._records)

    def export_json(self, filepath: str) -> int:
        """Write all records to a JSON file. Returns the number of records."""
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(
                [asdict(r) for r in self._records],
                f, indent=2, ensure_ascii=False,
            )
        return len(self._records)

    def clear(self) -> None:
        self._records.clear()
