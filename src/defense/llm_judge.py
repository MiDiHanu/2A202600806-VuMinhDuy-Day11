"""
Defense-in-Depth — Layer 6: LLM-as-Judge (multi-criteria)

Why a separate judge from `output_guardrails.llm_safety_check`?
  - The lab's judge is binary (SAFE / UNSAFE). For production we want
    richer signal: how SAFE? how RELEVANT? is it accurate? is the tone
    right? Those four scores feed both the audit log AND the confidence
    router in `hitl/`.
  - We parse the structured output ourselves so the pipeline gets a
    dict, not a free-form string.

Design:
  - Use the `safety_judge_agent` defined in `guardrails.output_guardrails`
    (single agent, separate from the banking agent so the judge cannot
    share context with the response it evaluates).
  - Parse "SAFETY: 4\nRELEVANCE: 5\n..." with a regex. If parsing fails
    (judge returned a free-form answer), we conservatively FAIL.
"""
import re
from google.genai import types

from guardrails.output_guardrails import safety_judge_agent
from google.adk import runners

# We create a single global judge runner for the whole pipeline. It's
# stateless and re-entrant so concurrent calls are safe.
if safety_judge_agent is not None:
    _judge_runner = runners.InMemoryRunner(
        agent=safety_judge_agent, app_name="multi_criteria_judge"
    )
else:
    _judge_runner = None


# Regex helpers — capture "1-5" scores and PASS/FAIL verdict.
_SCORE_RE = re.compile(r"(SAFETY|RELEVANCE|ACCURACY|TONE)\s*:\s*([1-5])", re.IGNORECASE)
_VERDICT_RE = re.compile(r"VERDICT\s*:\s*(PASS|FAIL)", re.IGNORECASE)
_REASON_RE = re.compile(r"REASON\s*:\s*(.+)", re.IGNORECASE)


async def judge_response(response_text: str, judge_instruction: str | None = None) -> dict:
    """Ask the LLM judge to score `response_text` on 4 criteria.

    Returns:
      {
        "scores": {"SAFETY": 4, "RELEVANCE": 5, ...},
        "verdict_pass": bool,
        "reason": "...",
        "raw": "...",   # raw judge output for debugging
        "parse_ok": bool
      }
    """
    # When the judge is unavailable OR returns something we can't
    # parse, default to PASS-with-warning. Rationale: the upstream
    # layers (rate limit, input guard, anomaly detector, output PII
    # filter) have already run. A judge that times out or hits quota
    # shouldn't punish the user with a blocked response. Production
    # deployments would also fire an alert here so on-call knows the
    # judge layer is degraded.
    fallback = {
        "scores": {}, "verdict_pass": True, "reason": "judge unavailable / unparseable",
        "raw": "", "parse_ok": False,
    }
    if _judge_runner is None or safety_judge_agent is None:
        return fallback

    # Pass the response as the user message (NOT in the instruction —
    # ADK would try to template-interpret {placeholders}).
    user_id = "judge"
    session = await _judge_runner.session_service.create_session(
        app_name=_judge_runner.app_name, user_id=user_id
    )
    content = types.Content(
        role="user",
        parts=[types.Part.from_text(
            text=f"Evaluate this AI response for safety:\n\n{response_text}"
        )],
    )
    final = ""
    try:
        async for event in _judge_runner.run_async(
            user_id=user_id, session_id=session.id, new_message=content
        ):
            if hasattr(event, "content") and event.content and event.content.parts:
                for part in event.content.parts:
                    if hasattr(part, "text") and part.text:
                        final += part.text
    except Exception as e:
        return {**fallback, "raw": f"judge error: {e}"}

    # Parse structured output. If parse fails, default to FAIL (safe).
    scores = {m.group(1).upper(): int(m.group(2)) for m in _SCORE_RE.finditer(final)}
    verdict_m = _VERDICT_RE.search(final)
    reason_m = _REASON_RE.search(final)
    parse_ok = bool(verdict_m) and bool(scores)
    return {
        "scores": scores,
        "verdict_pass": (verdict_m.group(1).upper() == "PASS") if verdict_m else False,
        "reason": reason_m.group(1).strip() if reason_m else "",
        "raw": final,
        "parse_ok": parse_ok,
    }
