"""
Nebius AI (Token Factory) inference client for ScamShield AI.

Uses the OpenAI-compatible Nebius API:
  Base URL : https://api.tokenfactory.nebius.com/v1
  Auth     : Bearer token via NEBIUS_API_KEY env var
  Model    : Explicitly configured via NEBIUS_MODEL env var

The client is fully optional:
  - If NEBIUS_API_KEY is not set, is_configured() returns False and the
    caller falls back to the existing rule-based detector.
  - If a request fails for any reason, a NebiusError is raised so the
    caller can log and fall back gracefully.

No user data is ever sent unless both the API key and model are configured.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx

# ---------------------------------------------------------------------------
# Constants (no hardcoded secrets - all read from environment at runtime)
# ---------------------------------------------------------------------------
NEBIUS_BASE_URL = "https://api.tokenfactory.nebius.com/v1"
REQUEST_TIMEOUT_SECONDS = 15.0
MAX_TOKENS = 256
TEMPERATURE = 0.1  # Low temperature for classification tasks


# ---------------------------------------------------------------------------
# Prompt engineering
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are ScamShield AI, a concise scam-detection assistant. "
    "Analyse the provided message or URL for phishing, fraud, or social-engineering indicators. "
    "Reply ONLY with a valid JSON object containing exactly these keys: "
    "risk_score (integer 0-100), risk_level (string: Low, Medium, or High), "
    "indicators (list of short strings describing detected signals), "
    "recommendation (one action sentence for the user). "
    "Do NOT include any explanation outside the JSON object."
)


def _build_user_prompt(message: str | None, url: str | None) -> str:
    parts: list[str] = []
    if message:
        parts.append(f"Message: {message}")
    if url:
        parts.append(f"URL: {url}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Configuration helpers
# ---------------------------------------------------------------------------
class NebiusError(RuntimeError):
    """Raised when the Nebius request fails. Callers should fall back to rules."""


def is_configured() -> bool:
    """Return True only when both the API key and model are configured."""
    return bool(
        os.environ.get("NEBIUS_API_KEY", "").strip()
        and os.environ.get("NEBIUS_MODEL", "").strip()
    )


def get_model() -> str:
    model = os.environ.get("NEBIUS_MODEL", "").strip()
    if not model:
        raise NebiusError(
            "NEBIUS_MODEL must be explicitly set to a model ID from Nebius Token Factory."
        )
    return model


# ---------------------------------------------------------------------------
# Async inference call
# ---------------------------------------------------------------------------
async def call_nebius(message: str | None, url: str | None) -> dict[str, Any]:
    """
    Send a single chat-completion request to Nebius Token Factory.

    Returns a dict compatible with evaluate_rules() output:
        {risk_score, risk_level, indicators, recommendation, analysis_method}

    Raises NebiusError on any failure (network, auth, bad JSON, etc.)
    so callers can fall back to rule-based detection.
    """
    api_key = os.environ.get("NEBIUS_API_KEY", "").strip()
    if not api_key:
        raise NebiusError("NEBIUS_API_KEY not set; cannot make inference request.")

    model = get_model()
    user_prompt = _build_user_prompt(message, url)

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": TEMPERATURE,
        "max_tokens": MAX_TOKENS,
        "response_format": {"type": "json_object"},
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }

    try:
        async with httpx.AsyncClient(
            base_url=NEBIUS_BASE_URL,
            timeout=REQUEST_TIMEOUT_SECONDS,
        ) as client:
            response = await client.post(
                "/chat/completions",
                headers=headers,
                json=payload,
            )
    except httpx.HTTPError as exc:
        raise NebiusError(
            f"HTTP request to Nebius failed ({type(exc).__name__})."
        ) from exc

    if response.status_code == 401:
        raise NebiusError("Nebius API returned 401 Unauthorized — check NEBIUS_API_KEY.")
    if response.status_code == 404:
        raise NebiusError(
            f"Nebius API returned 404 — model '{model}' may not exist. "
            "Set NEBIUS_MODEL to a valid model ID."
        )
    if not (200 <= response.status_code < 300):
        raise NebiusError(
            f"Nebius API returned HTTP {response.status_code}."
        )

    try:
        resp_json = response.json()
        raw_content: str = resp_json["choices"][0]["message"]["content"]
        llm_data = json.loads(raw_content)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise NebiusError("Could not parse Nebius response.") from exc

    if not isinstance(llm_data, dict):
        raise NebiusError("Could not parse Nebius response: expected a JSON object.")

    # Missing optional fields retain the established defaults; malformed types fail closed.
    if "risk_score" not in llm_data:
        raise NebiusError("Nebius response did not include a risk score.")
    score_value = llm_data["risk_score"]
    indicators_value = llm_data.get("indicators", [])
    recommendation_value = llm_data.get("recommendation", "")
    if (
        isinstance(score_value, bool)
        or not isinstance(score_value, int)
        or not isinstance(indicators_value, list)
        or not all(isinstance(indicator, str) for indicator in indicators_value)
        or not isinstance(recommendation_value, str)
    ):
        raise NebiusError("Nebius response contained invalid field types.")

    risk_score = max(0, min(100, score_value))
    indicators = indicators_value
    recommendation = recommendation_value
    risk_level = "Low" if risk_score < 30 else ("Medium" if risk_score < 60 else "High")

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "recommendation": recommendation,
        "analysis_method": f"Nebius AI LLM ({model})",
    }
