"""
suggestion_engine.py

Turns Analyzer Findings into concrete, actionable suggestions.

Rule-based suggestions are:
    - fast
    - offline
    - deterministic

Optional LLM synthesis:
    - enabled with config["enable_llm_suggestions"]
    - requires ANTHROPIC_API_KEY
    - must never stop the monitoring agent if unavailable/failing
"""

import json


RULES = {
    "cpu_high": (
        "Consider: (1) profiling the process "
        "(py-spy / perf) to find the hot loop, "
        "(2) adding caching or batching to reduce "
        "repeated work, "
        "(3) scaling workers if load is legitimate, "
        "(4) checking for busy-waiting or excessive polling."
    ),

    "mem_high": (
        "Consider: (1) checking for unbounded caches, "
        "lists, or unclosed file/DB handles, "
        "(2) using tracemalloc or memory_profiler "
        "to identify allocation sources, "
        "(3) setting an explicit memory limit and "
        "controlled restart policy as a safety net."
    ),

    "trend_up": (
        "A steadily rising metric can indicate a memory "
        "leak, unbounded data structure, cache growth, "
        "or increasing workload. Check allocation growth "
        "and add an appropriate ceiling or cleanup policy."
    ),

    "crash_loop": (
        "Check the process's recent stderr, exit code, "
        "and lifecycle events first. Common causes include "
        "missing dependencies, port conflicts, startup "
        "exceptions, invalid configuration, or an overly "
        "aggressive restart policy."
    ),

    "long_running": (
        "If this process is intended to be short-lived, "
        "check for a missing exit condition. If it is a "
        "legitimate long-running service, verify its health "
        "check and recovery policy."
    ),

    "baseline_deviation": (
        "This process is behaving abnormally relative to "
        "its own learned baseline. Check recent changes "
        "such as input volume, deployment, configuration, "
        "or upstream dependency behavior. If the new "
        "behavior becomes normal, the baseline can adapt."
    ),
}


def _rule_key_for(finding) -> str:
    """
    Determine which recommendation rule applies.

    Prefer explicit evidence/type fields when available,
    then fall back to message matching.
    """

    message = (
        getattr(
            finding,
            "message",
            "",
        )
        or ""
    ).lower()

    evidence = (
        getattr(
            finding,
            "evidence",
            {},
        )
        or {}
    )

    # ---------------------------------------------------------
    # Explicit evidence classification
    # ---------------------------------------------------------

    classification = evidence.get(
        "classification"
    )

    if classification == (
        "restart_churn_indicator"
    ):
        return "crash_loop"

    # ---------------------------------------------------------
    # Message-based classification
    # ---------------------------------------------------------

    if (
        "crash-loop" in message
        or "crash loop" in message
        or "crash/restart loop" in message
        or "restart loop" in message
        or "restart churn" in message
    ):
        return "crash_loop"

    if "long-running" in message:
        return "long_running"

    if (
        "deviates from this process's own baseline"
        in message
    ):
        return "baseline_deviation"

    if "trending up" in message:
        return "trend_up"

    if (
        "memory" in message
        or "mem" in message
    ):
        return "mem_high"

    if "cpu" in message:
        return "cpu_high"

    return None


def generate_rule_based_suggestions(
    findings: list,
    storage,
) -> list:
    """
    Convert Findings into actionable suggestions
    and persist them to Storage.
    """

    suggestions = []

    for finding in findings:

        key = _rule_key_for(
            finding
        )

        advice = RULES.get(
            key,
            (
                "Review recent changes and "
                "process logs; no specific rule "
                "matched this finding."
            ),
        )

        message = (
            f"{finding.message}\n"
            f"  → {advice}"
        )

        # Persist evidence so every suggestion
        # remains auditable.
        storage.insert_suggestion(
            finding.scope,
            finding.severity,
            message,
            finding.evidence,
        )

        suggestions.append(
            {
                "scope": finding.scope,
                "severity": finding.severity,
                "message": message,
                "evidence": finding.evidence,
            }
        )

    return suggestions


def generate_llm_suggestions(
    findings: list,
    config: dict,
) -> str:
    """
    Optional deeper analysis using Anthropic.

    IMPORTANT:
        LLM failure must never stop the monitoring agent.
    """

    if not findings:
        return ""

    try:

        import anthropic

    except ImportError:

        return (
            "LLM deep-pass skipped: anthropic SDK "
            "is not installed."
        )

    try:

        client = anthropic.Anthropic()

        findings_text = "\n".join(
            (
                f"- [{finding.severity}] "
                f"{finding.scope}: "
                f"{finding.message} | "
                f"evidence="
                f"{json.dumps(finding.evidence)}"
            )
            for finding in findings
        )

        prompt = (
            "You are a senior SRE reviewing process-level "
            "monitoring findings.\n\n"
            "Analyze the evidence and identify cross-process "
            "patterns. Provide 3-5 concise, concrete "
            "remediation steps.\n\n"
            "Do not invent measurements or facts that are "
            "not present in the supplied evidence.\n\n"
            f"Findings:\n{findings_text}"
        )

        response = client.messages.create(
            model=config.get(
                "llm_model",
                "claude-sonnet-4-6",
            ),
            max_tokens=int(
                config.get(
                    "llm_max_tokens",
                    800,
                )
            ),
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        )

        text_parts = []

        for block in response.content:

            if getattr(
                block,
                "type",
                None,
            ) == "text":

                text_parts.append(
                    block.text
                )

        return "".join(
            text_parts
        )

    except Exception as exc:

        # LLM is optional. Never allow an API,
        # authentication, timeout, model, or network
        # problem to terminate monitoring.
        return (
            "LLM deep-pass failed safely: "
            f"{type(exc).__name__}: {exc}"
        )
