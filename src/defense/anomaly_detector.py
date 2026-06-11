"""
Defense-in-Depth — BONUS Layer 3: Session Anomaly Detector

Why this bonus layer?
  - Catches: a single user who sends many "borderline" messages that
    individually pass the injection regex (so input guardrail lets them
    through) but together look like a probing attack.
  - Real-world attacks are usually a sequence: "hello" -> "what
    products do you have?" -> "what systems do you use?" -> "what
    passwords?" Any one of those might be innocent; the SEQUENCE isn't.
  - The other layers see one message at a time, so they miss this.

Design:
  - Per-user counter of "suspicious" messages.
  - A message is suspicious if it contains keywords like "password",
    "api key", "system prompt", "secret", "credential", "admin" --
    even when no other rule fires.
  - When the counter crosses `threshold`, we flag the session.
"""
import re
from collections import defaultdict


SUSPICIOUS_KEYWORDS = re.compile(
    r"\b(password|passcode|api[ _-]?key|secret|credential|admin|root|"
    r"system[ _-]?prompt|internal|override|instruction|configuration|"
    r"database|db\.|connection[ _-]?string)\b",
    re.IGNORECASE,
)


class SessionAnomalyDetector:
    """Counts suspicious messages per user and flags the session."""

    def __init__(self, threshold: int = 3):
        self.threshold = threshold
        # user_id -> {"count": int, "last_messages": list[str]}
        self._state: dict[str, dict] = defaultdict(
            lambda: {"count": 0, "last_messages": []}
        )

    def observe(self, user_id: str, message: str) -> dict:
        """Record a message and return current anomaly state for the user.

        Returns a dict:
          {
            "suspicious_score": int,  # number of suspicious msgs in session
            "flagged": bool,          # True if score >= threshold
            "recent_suspicious": list[str]  # last 3 suspicious snippets
          }
        """
        state = self._state[user_id]
        is_sus = bool(SUSPICIOUS_KEYWORDS.search(message))
        if is_sus:
            state["count"] += 1
            # Keep a short rolling list of the most recent suspicious snippets.
            state["last_messages"].append(message[:80])
            state["last_messages"] = state["last_messages"][-3:]

        return {
            "suspicious_score": state["count"],
            "flagged": state["count"] >= self.threshold,
            "recent_suspicious": list(state["last_messages"]),
        }

    def reset(self, user_id: str | None = None) -> None:
        if user_id is None:
            self._state.clear()
        else:
            self._state.pop(user_id, None)
