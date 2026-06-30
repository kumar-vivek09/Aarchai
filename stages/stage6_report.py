"""Stage 6 — AI Report Generation with severity-first, chunked LLM calls."""
from __future__ import annotations
import json
from config import LLM_PROVIDER, OLLAMA_URL, OLLAMA_MODEL, OPENAI_API_KEY, OPENAI_MODEL, GOOGLE_API_KEY

# Token budget: never cut critical/high; summarise medium/low/info
MAX_TOKENS_PER_CALL = 6000   # conservative for free-tier / small models
TOKENS_PER_FINDING  = 120    # avg tokens for one full finding object


def run(
    target,
    scan_id,
    session,
    jm,
    fast=False,
    out_dir=None,
    auth=None,
    scope=None,
):
    from core.db import Finding
    jm.log_stage("stage6_report", f"LLM provider: {LLM_PROVIDER}")

    findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    if not findings:
        jm.log_warn("No findings — skipping report")
        return [], []

    payload  = _build_llm_payload(findings, target)
    narrative = _run_llm(payload, findings, target, jm)

    if out_dir:
        from pathlib import Path
        (Path(out_dir) / "ai_narrative.txt").write_text(narrative, encoding="utf-8")
        jm.log_ok(f"AI narrative → {out_dir}/ai_narrative.txt")

    return [], []


# ── Payload builder — SEVERITY-FIRST, never truncate critical/high ─────────
def _build_llm_payload(findings: list, target) -> dict:
    def _detail(f) -> dict:
        return {
            "tool":         f.tool,
            "type":         f.finding_type,
            "title":        f.title,
            "host":         f.host or "",
            "port":         f.port,
            "url":          f.url or "",
            "cve_ids":      f.cve_ids or [],
            "cvss_score":   f.cvss_score,
            "epss_score":   f.epss_score,
            "mitre":        f.mitre_tactics or [],
            "description":  (f.description or "")[:400],
            "remediation":  (f.remediation or "")[:200],
        }

    def _brief(f) -> dict:
        return {"title": f.title, "host": f.host or "", "tool": f.tool,
                "cvss": f.cvss_score}

    def _count_by_type(fs: list) -> dict:
        counts: dict = {}
        for f in fs:
            counts[f.finding_type] = counts.get(f.finding_type, 0) + 1
        return counts

    by_sev = {s: [] for s in ("critical", "high", "medium", "low", "info", "unknown")}
    for f in findings:
        by_sev[f.severity].append(f)

    # Sort medium by CVSS descending
    medium_sorted = sorted(by_sev["medium"], key=lambda x: x.cvss_score or 0, reverse=True)

    return {
        "target":       target.value,
        "target_type":  target.type,
        "scan_summary": {s: len(v) for s, v in by_sev.items()},
        "total":        len(findings),
        # ALL critical — never truncate
        "critical_findings": [_detail(f) for f in by_sev["critical"]],
        # ALL high — never truncate
        "high_findings":     [_detail(f) for f in by_sev["high"]],
        # Medium: top 15 by CVSS score
        "medium_sample":     [_brief(f) for f in medium_sorted[:15]],
        "medium_remaining":  max(0, len(by_sev["medium"]) - 15),
        # Low/Info: just type breakdown (not worth LLM tokens)
        "low_summary":  _count_by_type(by_sev["low"]),
        "info_summary": _count_by_type(by_sev["info"]),
    }


# ── Chunked LLM runner — handles large datasets via multiple calls ─────────
def _run_llm(payload: dict, findings: list, target, jm) -> str:
    n_critical = len(payload["critical_findings"])
    n_high     = len(payload["high_findings"])
    estimated_tokens = (n_critical + n_high) * TOKENS_PER_FINDING

    if estimated_tokens <= MAX_TOKENS_PER_CALL:
        # Single call — everything fits
        return _call_llm_single(payload, jm)
    else:
        # Chunked — too many findings for one call
        jm.log_info(f"LLM chunked mode: {n_critical} critical + {n_high} high findings")
        return _call_llm_chunked(payload, jm)


def _call_llm_single(payload: dict, jm) -> str:
    prompt = _build_prompt(payload)
    return _dispatch(prompt, jm)


def _call_llm_chunked(payload: dict, jm) -> str:
    """Process critical and high in separate calls, then synthesise."""
    # Critical findings narrative
    crit_payload = {**payload, "high_findings": [], "mode": "critical_only"}
    crit_prompt  = _build_prompt(crit_payload, mode="critical")
    crit_narr    = _dispatch(crit_prompt, jm)

    # High findings narrative
    high_payload = {**payload, "critical_findings": [], "mode": "high_only"}
    high_prompt  = _build_prompt(high_payload, mode="high")
    high_narr    = _dispatch(high_prompt, jm)

    # Synthesis call
    synth_prompt = f"""You are a senior penetration tester. Combine the following two partial 
security assessment sections into one coherent executive summary. Avoid repetition. 
Prioritise remediation by business risk.

--- CRITICAL FINDINGS SECTION ---
{crit_narr}

--- HIGH FINDINGS SECTION ---
{high_narr}

Write the final merged executive summary:"""
    return _dispatch(synth_prompt, jm)


def _build_prompt(payload: dict, mode: str = "full") -> str:
    findings_json = json.dumps(payload, indent=2)
    scope = {
        "full":     "all findings including critical, high, medium summary, and low/info counts",
        "critical": "CRITICAL severity findings only",
        "high":     "HIGH severity findings only",
    }[mode]

    return f"""You are a senior penetration tester writing a professional security assessment report.

You have been given {scope} from an automated recon scan of {payload["target"]}.

FINDINGS DATA:
{findings_json}

Write a structured report with these sections:
1. EXECUTIVE SUMMARY (3-4 sentences, business language, no jargon)
2. CRITICAL RISK AREAS (one paragraph per critical finding — what it means, business impact)
3. TOP ATTACK PATHS (describe 2-3 realistic attack chains based on the findings)
4. REMEDIATION PRIORITIES (ordered list: what to fix first, estimated effort)
5. QUICK WINS (fixes that can be done in < 1 day)

Rules:
- Reference specific CVE IDs and CVSS scores where available
- Use plain English — the audience is non-technical management
- Be specific about hosts/URLs affected
- Do NOT invent findings not present in the data
- If a finding has EPSS score > 0.5, flag it as "actively exploited in the wild"
"""


def _dispatch(prompt: str, jm) -> str:
    handler = PROVIDERS.get(LLM_PROVIDER, _stub)
    return handler(prompt, jm)


def _stub(prompt: str, jm) -> str:
    jm.log_info("LLM stub — set LLM_PROVIDER=ollama or openai in .env")
    return "[LLM stub — configure LLM_PROVIDER in .env to get AI narratives]\n" + prompt[:500]


def _google(prompt: str, jm) -> str:
    jm.log_info(f"Google Gemini ({GOOGLE_MODEL}) generating narrative...")
    try:
        from google import genai
        if not GOOGLE_API_KEY:
             raise ValueError("GOOGLE_API_KEY not set")
        client = genai.Client(api_key=GOOGLE_API_KEY)
        response = client.models.generate_content(
            model=GOOGLE_MODEL,
            contents=prompt,
        )
        return response.text
    except Exception as e:
        jm.log_warn(f"Google Gemini error: {e}. Falling back to stub provider.")
        return _stub(prompt, jm)


def _ollama(prompt: str, jm) -> str:
    import requests as req
    jm.log_info(f"Ollama ({OLLAMA_MODEL}) generating narrative...")
    try:
        resp = req.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=300
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
    except Exception as e:
        jm.log_warn(f"Ollama error: {e}. Falling back to stub provider.")
        return _stub(prompt, jm)


def _openai(prompt: str, jm) -> str:
    import requests as req
    jm.log_info(f"OpenAI ({OPENAI_MODEL}) generating narrative...")
    try:
        if not OPENAI_API_KEY:
             raise ValueError("OPENAI_API_KEY not set")
        resp = req.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": OPENAI_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2000,
                "temperature": 0.3,
            },
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        jm.log_warn(f"OpenAI error: {e}. Falling back to stub provider.")
        return _stub(prompt, jm)


PROVIDERS = {
    "google": _google,
    "ollama": _ollama,
    "openai": _openai,
    "stub": _stub,
}
