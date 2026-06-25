"""Stage 7 — AI Attacker Perspective: red team simulation after report generation."""
from __future__ import annotations
import json
from pathlib import Path
from config import LLM_PROVIDER, OLLAMA_URL, OLLAMA_MODEL, OPENAI_API_KEY, OPENAI_MODEL


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    from core.db import Finding, Asset
    jm.log_stage("stage7_attacker", "AI Red Team — simulating attacker perspective")

    findings = session.query(Finding).filter(Finding.scan_id == scan_id).all()
    assets   = session.query(Asset).filter(Asset.scan_id == scan_id).all()

    if not findings:
        jm.log_warn("No findings — skipping attacker simulation")
        return [], []

    payload  = _build_attacker_payload(findings, assets, target)
    analysis = _run_attacker_llm(payload, jm)

    if out_dir:
        p = Path(out_dir)
        (p / "attacker_perspective.txt").write_text(analysis, encoding="utf-8")
        (p / "attacker_perspective.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
        jm.log_ok(f"Attacker analysis → {out_dir}/attacker_perspective.txt")

    return [], []


def _build_attacker_payload(findings, assets, target) -> dict:
    """Build structured payload emphasising attacker-relevant data."""
    crit_high = [f for f in findings if f.severity in ("critical", "high")]

    # Group by attack category
    initial_access = [f for f in crit_high if any(t in (f.finding_type or "")
        for t in ("rce","sql","xss","lfi","ssrf","default_credential","git_exposed","env_exposed","secret"))]
    lateral_move   = [f for f in crit_high if any(t in (f.finding_type or "")
        for t in ("open_port","default_credential","weak_ssl","weak_cipher","smb","rdp","ssh"))]
    data_exposure  = [f for f in findings if any(t in (f.finding_type or "")
        for t in ("backup","env","secret","git","database","config","phpinfo","credential"))]
    exploitable    = [f for f in crit_high if f.exploit_available or f.in_cisa_kev]

    def brief(f):
        return {
            "title":     f.title,
            "type":      f.finding_type,
            "host":      f.host,
            "port":      f.port,
            "url":       f.url,
            "cvss":      f.cvss_score,
            "cve":       (f.cve_ids or [])[:2],
            "exploit":   f.exploit_available,
            "kev":       f.in_cisa_kev,
            "msf":       f.metasploit_module,
            "mitre":     (f.mitre_tactics or [])[:2],
        }

    return {
        "target":          target.value,
        "target_type":     target.type,
        "attack_surface": {
            "total_findings":  len(findings),
            "critical_high":   len(crit_high),
            "exploitable_now": len(exploitable),
            "exposed_creds":   len(data_exposure),
            "subdomains":      len([a for a in assets if a.asset_type == "subdomain"]),
            "open_ports":      len([a for a in assets if a.asset_type == "port"]),
            "live_urls":       len([a for a in assets if a.asset_type == "url"]),
        },
        "initial_access_vectors": [brief(f) for f in initial_access[:10]],
        "lateral_movement_paths": [brief(f) for f in lateral_move[:8]],
        "data_exposure_risks":    [brief(f) for f in data_exposure[:8]],
        "confirmed_exploitable":  [brief(f) for f in exploitable[:5]],
        "kev_findings":           [brief(f) for f in findings if f.in_cisa_kev],
    }


def _run_attacker_llm(payload: dict, jm) -> str:
    prompt = _build_attacker_prompt(payload)
    if LLM_PROVIDER == "ollama":
        return _ollama(prompt, jm)
    elif LLM_PROVIDER == "openai" and OPENAI_API_KEY:
        return _openai(prompt, jm)
    return _stub(payload)


def _build_attacker_prompt(payload: dict) -> str:
    data_str = json.dumps(payload, indent=2)
    return f"""You are an elite red team operator conducting a penetration test on {payload['target']}.
You have completed automated recon and have the following attack surface data.

ATTACK SURFACE:
{data_str}

As a red team operator, provide a realistic attack simulation covering:

1. INITIAL ACCESS (pick the single most likely entry point and explain why)
   - Exact steps to exploit it
   - Tools and commands you would use
   - Time estimate to gain initial foothold

2. ATTACK CHAIN (step-by-step from initial access to goal)
   - Show the complete kill chain: Initial Access → Execution → Persistence → Privilege Escalation → Lateral Movement → Exfiltration
   - Reference specific findings by title
   - Show how vulnerabilities chain together

3. HIGH-VALUE TARGETS (what data/systems would you prioritise)
   - Based on the exposed services and credentials found
   - Business impact of each

4. REALISTIC TIMELINE
   - How long would an experienced attacker take? (hours/days)
   - Skill level required (script kiddie / intermediate / APT)

5. DETECTION GAPS
   - What evidence would be left behind?
   - Which attacks would be hardest to detect?
   - Where would existing defenses likely fail?

6. IMMEDIATE STOP-THE-BLEEDING ACTIONS
   - Top 3 things the defender must do RIGHT NOW to break the attack chain

Be specific, technical, and realistic. Reference actual CVE IDs, tools, and techniques.
Do NOT be generic. Every recommendation must be grounded in the actual findings above.
"""


def _stub(payload: dict) -> str:
    return (
        "== ATTACKER PERSPECTIVE (stub — configure LLM_PROVIDER in .env) ==\n\n"
        f"Attack surface: {payload['attack_surface']}\n"
        f"Initial access vectors: {len(payload['initial_access_vectors'])}\n"
        f"Confirmed exploitable: {len(payload['confirmed_exploitable'])}\n\n"
        "[Set LLM_PROVIDER=ollama and run Ollama locally for AI red team analysis]"
    )


def _ollama(prompt: str, jm) -> str:
    import requests
    jm.log_info(f"Red team analysis via Ollama ({OLLAMA_MODEL})...")
    try:
        resp = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json={"model": OLLAMA_MODEL, "prompt": prompt, "stream": False},
            timeout=300
        )
        resp.raise_for_status()
        return resp.json().get("response", "")
    except Exception as e:
        jm.log_warn(f"Ollama: {e}")
        return _stub({})


def _openai(prompt: str, jm) -> str:
    import requests
    jm.log_info(f"Red team analysis via OpenAI ({OPENAI_MODEL})...")
    try:
        resp = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
            json={
                "model": OPENAI_MODEL,
                "messages": [
                    {"role": "system", "content": "You are an elite red team penetration tester. Be specific, technical, and realistic."},
                    {"role": "user",   "content": prompt}
                ],
                "max_tokens": 3000,
                "temperature": 0.4,
            },
            timeout=120
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"]
    except Exception as e:
        jm.log_warn(f"OpenAI: {e}")
        return _stub({})
