"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 12: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # 1) High-risk actions ALWAYS escalate — a confident agent on
        # a money-transfer is still a money transfer that needs a human.
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type} — human approval required",
                priority="high",
                requires_human=True,
            )

        # 2) Confidence-based routing for everything else.
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence — auto-sending to user",
                priority="low",
                requires_human=False,
            )
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs human review",
                priority="normal",
                requires_human=True,
            )
        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence — escalating to human immediately",
            priority="high",
            requires_human=True,
        )


# ============================================================
# TODO 13: Design 3 HITL decision points
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "High-value money transfer approval",
        "trigger": "User initiates a transfer >= 50,000,000 VND OR a transfer to a new beneficiary",
        "hitl_model": "human-in-the-loop",  # agent must wait for approval before executing
        "context_needed": [
            "User identity (verified via OTP/biometric)",
            "Beneficiary details (account number, name, bank)",
            "Amount and currency",
            "Transfer history with this beneficiary (new? recurring?)",
            "Risk score from the fraud-detection model",
        ],
        "example": (
            "Customer 'Lan' tries to send 100,000,000 VND to a new beneficiary "
            "'Tran B' that she's never sent money to. The system pauses, shows a "
            "human banker the transaction details + a 'first-time beneficiary' risk "
            "flag, and only proceeds after the banker clicks 'Approve'."
        ),
    },
    {
        "id": 2,
        "name": "Low-confidence / ambiguous query escalation",
        "trigger": "ConfidenceRouter returns 'queue_review' OR 'escalate' (i.e. confidence < 0.9 OR a blocked/ambiguous intent)",
        "hitl_model": "human-on-the-loop",  # agent drafts, human reviews before send
        "context_needed": [
            "Original user question (verbatim)",
            "Agent's drafted response",
            "Confidence score + reason for the low score",
            "Recent conversation history (last 3 turns)",
        ],
        "example": (
            "User asks 'My card was charged twice at a coffee shop in Tokyo but I "
            "didn't travel — what do I do?'. The LLM's confidence is 0.62 because "
            "this is a fraud-dispute case. The drafted response is queued for a "
            "support agent who specializes in disputes, with a 15-minute SLA."
        ),
    },
    {
        "id": 3,
        "name": "Guardrail conflict / judge disagreement tiebreaker",
        "trigger": "When input/output guardrails and the LLM-as-Judge give conflicting signals (e.g., input passes but judge flags as UNSAFE)",
        "hitl_model": "human-as-tiebreaker",  # human makes the final call when 2 systems disagree
        "context_needed": [
            "Original input (verbatim)",
            "Input guardrail verdict + which pattern matched (if any)",
            "Output guardrail redacted version + list of detected PII/secrets",
            "LLM-as-Judge verdict + reason",
            "Suggested action (block / redact / send-as-is)",
        ],
        "example": (
            "User says 'My phone number is 0901234567 and my email is "
            "a@gmail.com — please confirm you have it on file.' Input layer "
            "says 'safe, on-topic', but the LLM-as-Judge flags the response "
            "as 'UNSAFE — echoed back PII'. A security analyst reviews and "
            "chooses to redact the PII from the response before delivery."
        ),
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
