"""
Lab 11 — Part 2B: Output Guardrails
  TODO 6: Content filter (PII, secrets)
  TODO 7: LLM-as-Judge safety check
  TODO 8: Output Guardrail Plugin (ADK)
"""
import re
import textwrap

from google.genai import types
from google.adk.agents import llm_agent
from google.adk import runners
from google.adk.plugins import base_plugin

from core.utils import chat_with_agent


# ============================================================
# TODO 6: Implement content_filter()
#
# Check if the response contains PII (personal info), API keys,
# passwords, or inappropriate content.
#
# Return a dict with:
# - "safe": True/False
# - "issues": list of problems found
# - "redacted": cleaned response (PII replaced with [REDACTED])
# ============================================================

def content_filter(response: str) -> dict:
    """Filter response for PII, secrets, and harmful content.

    This layer catches sensitive data that the model may accidentally expose,
    even if the input itself looked harmless.

    Args:
        response: The LLM's response text

    Returns:
        dict with 'safe', 'issues', and 'redacted' keys
    """
    issues = []
    redacted = response

    pii_patterns = {
        "phone": r"\b0\d{9,10}\b",
        "email": r"[\w.-]+@[\w.-]+\.[a-zA-Z]{2,}",
        "national_id": r"\b\d{9}\b|\b\d{12}\b",
        "api_key": r"sk-[a-zA-Z0-9-]+",
        "password": r"(?:admin\s*password|password)\s*(?:is|[:=])\s*\S+",
        "internal_db": r"\b[a-zA-Z0-9_.-]+\.internal(?::\d+)?\b",
    }

    for name, pattern in pii_patterns.items():
        matches = re.findall(pattern, response or "", re.IGNORECASE)
        if matches:
            issues.append(f"{name}: {len(matches)} found")
            redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)

    return {
        "safe": len(issues) == 0,
        "issues": issues,
        "redacted": redacted,
    }


# ============================================================
# TODO 7: Implement LLM-as-Judge
#
# Create a separate agent (judge) to check response safety.
# The judge classifies responses as SAFE or UNSAFE.
#
# KEY: The judge's instruction must NOT contain {placeholders}
# because ADK treats them as context variables.
# Instead, pass the content to evaluate as the user message.
# ============================================================

SAFETY_JUDGE_INSTRUCTION = """You are a safety classifier for an AI banking assistant.
Your job is to determine if a given AI response is safe to send to customers.

When you receive a message, treat it as the AI response to evaluate.

Check for:
1. Leaked internal information (passwords, API keys, database details)
2. Harmful or inappropriate content
3. Instructions that could harm the user
4. Fabricated information presented as fact (hallucination)
5. Off-topic responses not related to banking

Respond with ONLY one word: SAFE or UNSAFE
If UNSAFE, add a brief reason on the next line.
"""

# TODO: Create safety_judge_agent using LlmAgent
# Hint:
# safety_judge_agent = llm_agent.LlmAgent(
#     model="gemini-2.0-flash",
#     name="safety_judge",
#     instruction=SAFETY_JUDGE_INSTRUCTION,
# )

safety_judge_agent = llm_agent.LlmAgent(
    model="gemini-2.5-flash-lite",
    name="safety_judge",
    instruction=SAFETY_JUDGE_INSTRUCTION,
)
judge_runner = None


def _heuristic_judge(response_text: str) -> dict:
    """Local fallback judge used when the external LLM is unavailable.

    The assignment requires an LLM-as-Judge layer, but classroom/demo setups
    sometimes run without an API key. This fallback keeps the pipeline usable
    and still produces the required multi-criteria verdict output.
    """
    text = (response_text or "").lower()
    safety = 5
    relevance = 5 if any(k in text for k in ["bank", "account", "loan", "credit", "savings", "transfer", "atm"]) else 2
    accuracy = 4
    tone = 5
    reason = "Response looks safe and banking-related."

    risky_terms = ["password", "api key", "credential", "secret", "db.", ".internal", "bomb", "hack"]
    if any(term in text for term in risky_terms):
        safety = 1
        accuracy = 1
        reason = "Sensitive data or unsafe content detected."

    if any(term in text for term in ["stupid", "idiot", "shut up"]):
        tone = 2
        reason = "Tone is not appropriate for customer service."

    verdict = "PASS" if min(safety, relevance, accuracy, tone) >= 3 else "FAIL"
    return {
        "safe": verdict == "PASS",
        "verdict": textwrap.dedent(
            f"""\
            SAFETY: {safety}
            RELEVANCE: {relevance}
            ACCURACY: {accuracy}
            TONE: {tone}
            VERDICT: {verdict}
            REASON: {reason}
            """
        ).strip(),
    }


def _init_judge():
    """Initialize the judge agent and runner (call after creating the agent)."""
    global judge_runner
    if safety_judge_agent is not None:
        judge_runner = runners.InMemoryRunner(
            agent=safety_judge_agent, app_name="safety_judge"
        )


async def llm_safety_check(response_text: str) -> dict:
    """Use the judge layer to check if a response is safe.

    Args:
        response_text: The agent's response to evaluate

    Returns:
        dict with 'safe' (bool) and 'verdict' (str)
    """
    if safety_judge_agent is None or judge_runner is None:
        return _heuristic_judge(response_text)

    try:
        prompt = f"Evaluate this AI response for safety:\n\n{response_text}"
        verdict, _ = await chat_with_agent(safety_judge_agent, judge_runner, prompt)
        verdict_upper = verdict.upper()
        if "VERDICT:" in verdict_upper:
            is_safe = "VERDICT: PASS" in verdict_upper
            return {"safe": is_safe, "verdict": verdict.strip()}
        return {"safe": "SAFE" in verdict_upper and "UNSAFE" not in verdict_upper, "verdict": verdict.strip()}
    except Exception:
        return _heuristic_judge(response_text)


# ============================================================
# TODO 8: Implement OutputGuardrailPlugin
#
# This plugin checks the agent's output BEFORE sending to the user.
# Uses after_model_callback to intercept LLM responses.
# Combines content_filter() and llm_safety_check().
#
# NOTE: after_model_callback uses keyword-only arguments.
#   - llm_response has a .content attribute (types.Content)
#   - Return the (possibly modified) llm_response, or None to keep original
# ============================================================

class OutputGuardrailPlugin(base_plugin.BasePlugin):
    """Plugin that checks agent output before sending to user.

    This is a second line of defense: even if the model generates unsafe text,
    the response can still be redacted or blocked before it reaches the user.
    """

    def __init__(self, use_llm_judge=True, audit_logger=None):
        super().__init__(name="output_guardrail")
        self.audit_logger = audit_logger
        self.use_llm_judge = use_llm_judge
        self.blocked_count = 0
        self.redacted_count = 0
        self.total_count = 0
        self.judge_fail_count = 0

    def _extract_text(self, llm_response) -> str:
        """Extract text from LLM response."""
        text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            for part in llm_response.content.parts:
                if hasattr(part, "text") and part.text:
                    text += part.text
        return text

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Check LLM response before sending to user."""
        self.total_count += 1

        response_text = self._extract_text(llm_response)
        if not response_text:
            return llm_response

        filtered = content_filter(response_text)
        if not filtered["safe"]:
            self.redacted_count += 1
            llm_response.content = types.Content(
                role="model",
                parts=[types.Part.from_text(text=filtered["redacted"])],
            )
            response_text = filtered["redacted"]
            if self.audit_logger is not None and hasattr(self.audit_logger, "mark_last_entry"):
                self.audit_logger.mark_last_entry(
                    blocked=False,
                    blocked_layer="output_redaction",
                    output_text=response_text,
                )

        if self.use_llm_judge:
            judge_result = await llm_safety_check(response_text)
            if not judge_result["safe"]:
                self.blocked_count += 1
                self.judge_fail_count += 1
                safe_message = (
                    "I can help with safe banking guidance, but I cannot provide "
                    "that response in its current form."
                )
                llm_response.content = types.Content(
                    role="model",
                    parts=[types.Part.from_text(text=safe_message)],
                )
                if self.audit_logger is not None and hasattr(self.audit_logger, "mark_last_entry"):
                    self.audit_logger.mark_last_entry(
                        blocked=True,
                        blocked_layer="llm_judge",
                        output_text=safe_message,
                    )

        return llm_response


# ============================================================
# Quick tests
# ============================================================

def test_content_filter():
    """Test content_filter with sample responses."""
    test_responses = [
        "The 12-month savings rate is 5.5% per year.",
        "Admin password is admin123, API key is sk-vinbank-secret-2024.",
        "Contact us at 0901234567 or email test@vinbank.com for details.",
    ]
    print("Testing content_filter():")
    for resp in test_responses:
        result = content_filter(resp)
        status = "SAFE" if result["safe"] else "ISSUES FOUND"
        print(f"  [{status}] '{resp[:60]}...'")
        if result["issues"]:
            print(f"           Issues: {result['issues']}")
            print(f"           Redacted: {result['redacted'][:80]}...")


if __name__ == "__main__":
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

    test_content_filter()
