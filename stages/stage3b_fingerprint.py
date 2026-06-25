"""Stage 3b — Deep Service Fingerprinting: screenshots, JS detection, Wappalyzer."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth):
    from core.db import Asset
    host = target.host
    jm.log_stage("stage3b_fingerprint", f"Deep fingerprinting {host}")

    # Get live URLs from DB
    urls = [a.value for a in session.query(Asset).filter(
        Asset.scan_id == scan_id, Asset.asset_type == "url"
    ).all()]
    if not urls:
        urls = [f"http://{host}", f"https://{host}"]

    findings, assets = [], []

    # Run screenshots and JS detection in parallel
    tasks = [asyncio.create_task(_playwright_fingerprint(url, host, scan_id, jm, out_dir, auth))
             for url in urls[:10]]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if not isinstance(r, Exception):
            f, a = r
            findings.extend(f); assets.extend(a)

    jm.log_ok(f"Fingerprinting: {len(findings)} findings, {len(assets)} enriched assets")
    return findings, assets


async def _playwright_fingerprint(url, host, scan_id, jm, out_dir, auth):
    findings = []
    assets   = []
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        jm.log_warn("playwright not installed — run: playwright install chromium")
        return [], []

    screenshot_dir = Path(out_dir) / "screenshots" if out_dir else Path("/tmp/screenshots")
    screenshot_dir.mkdir(parents=True, exist_ok=True)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx_opts = {}
            if auth and auth.cookies:
                # Parse cookie string into list of dicts for Playwright
                cookie_list = []
                for c in auth.cookies.split(";"):
                    c = c.strip()
                    if "=" in c:
                        name, _, val = c.partition("=")
                        cookie_list.append({"name": name.strip(), "value": val.strip(),
                                            "url": url})
                ctx_opts["storage_state"] = {"cookies": cookie_list}
            ctx = await browser.new_context(**ctx_opts)
            page = await ctx.new_page()

            # Extra headers for auth
            if auth and auth.headers:
                await page.set_extra_http_headers(auth.headers)

            jm.log_info(f"Screenshot: {url}")
            await page.goto(url, wait_until="networkidle", timeout=20000)

            # Screenshot
            safe_name = url.replace("://","_").replace("/","_").replace(":","_")[:80]
            shot_path = screenshot_dir / f"{safe_name}.png"
            await page.screenshot(path=str(shot_path), full_page=False)

            # JS tech detection from page content
            title   = await page.title()
            content = await page.content()

            tech = _detect_js_framework(content)
            secrets_found = _scan_for_secrets_in_js(content, url, host, scan_id)

            # Forms discovery
            forms = await page.query_selector_all("form")
            inputs = await page.query_selector_all("input[type!=hidden]")

            findings.extend(secrets_found)

            if tech:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="playwright",
                    finding_type="tech_fingerprint",
                    title=f"JS Framework: {', '.join(tech)}",
                    severity=Severity.info,
                    host=host, url=url,
                    description=f"Title: {title}
Frameworks: {', '.join(tech)}
Forms: {len(forms)}, Inputs: {len(inputs)}",
                    raw_output=f"tech={tech}",
                    fingerprint_hash=make_hash("playwright_tech", host, url),
                ))

            if len(forms) > 0:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="playwright",
                    finding_type="form_discovered",
                    title=f"Form discovered at {url} ({len(forms)} forms, {len(inputs)} inputs)",
                    severity=Severity.info,
                    host=host, url=url,
                    description=f"Found {len(forms)} HTML forms and {len(inputs)} user inputs. Potential SQL injection, XSS, and CSRF targets.",
                    raw_output=f"forms={len(forms)} inputs={len(inputs)}",
                    fingerprint_hash=make_hash("playwright_forms", host, url, str(len(forms))),
                ))

            assets.append({
                "type": "url", "value": url, "source_tool": "playwright",
                "screenshot_path": str(shot_path), "tech_stack": tech,
                "service": f"HTTP | {title[:60]}"
            })

            await browser.close()

    except Exception as e:
        jm.log_warn(f"Playwright {url}: {e}")

    return findings, assets


def _detect_js_framework(html: str) -> list[str]:
    tech = []
    checks = {
        "React":      ["react.js", "react.min.js", "__react", "_reactRootContainer", "react-dom"],
        "Vue.js":     ["vue.js", "vue.min.js", "__vue__", "Vue.component"],
        "Angular":    ["angular.js", "ng-version", "ng-app", "@angular"],
        "Next.js":    ["__next", "_next/static"],
        "Nuxt.js":    ["__nuxt", "_nuxt"],
        "jQuery":     ["jquery.min.js", "jquery-", "window.jQuery"],
        "Svelte":     ["svelte", "__SVELTEKIT"],
        "Bootstrap":  ["bootstrap.min.css", "bootstrap.bundle"],
        "Tailwind":   ["tailwind", "cdn.tailwindcss"],
        "WordPress":  ["wp-content", "wp-includes", "WordPress"],
        "Drupal":     ["Drupal.settings", "sites/default"],
        "Joomla":     ["/components/com_", "Joomla!"],
        "Laravel":    ["laravel_session", "X-Powered-By: PHP"],
        "Django":     ["csrfmiddlewaretoken", "django"],
        "Express":    ["X-Powered-By: Express"],
    }
    html_lower = html.lower()
    for name, patterns in checks.items():
        if any(p.lower() in html_lower for p in patterns):
            tech.append(name)
    return tech


def _scan_for_secrets_in_js(content: str, url: str, host: str, scan_id: int) -> list:
    """Basic pattern matching for secrets in page source."""
    import re
    findings = []
    patterns = {
        "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
        "AWS Secret Key":    r"['"]([A-Za-z0-9/+]{40})['"]",
        "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Key":        r"sk_(live|test)_[0-9a-zA-Z]{24}",
        "GitHub Token":      r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}",
        "JWT Token":         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "Private Key PEM":   r"-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----",
        "SendGrid Key":      r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        "Twilio Key":        r"SK[0-9a-fA-F]{32}",
        "Slack Token":       r"xox[baprs]-[0-9a-zA-Z]{10,}",
    }
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="playwright",
                finding_type="secret_in_js",
                title=f"Secret in page source: {name}",
                severity=Severity.critical,
                host=host, url=url,
                description=f"Found {len(matches)} potential {name} secret(s) in page source/JS at {url}.",
                remediation="Remove secrets from client-side code immediately. Rotate the exposed credentials.",
                raw_output=f"pattern={pattern} matches={len(matches)}",
                fingerprint_hash=make_hash("playwright_secret", host, url, name),
            ))
    return findings
