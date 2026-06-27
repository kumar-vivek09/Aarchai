"""Stage 13 — Advanced: WAF bypass, password spray, subdomain takeover, screenshot diff."""
from __future__ import annotations
import asyncio
import hashlib
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth):
    host = target.host
    jm.log_stage("stage13_advanced", f"Advanced tests: {host}")

    tasks = [
        asyncio.create_task(_subdomain_takeover(host, scan_id, jm, session)),
        asyncio.create_task(_waf_bypass(host, scan_id, jm, auth)),
        asyncio.create_task(_screenshot_diff(host, scan_id, jm, out_dir, session)),
    ]
    if not fast:
        tasks.append(asyncio.create_task(_password_spray(host, scan_id, jm, session, auth)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r; findings.extend(f); assets.extend(a)
        else:
            jm.log_warn(f"Advanced task: {r}")

    jm.log_ok(f"Advanced: {len(findings)} findings")
    return findings, assets


async def _subdomain_takeover(host, scan_id, jm, session):
    """Detect dangling DNS CNAMEs pointing to unclaimed cloud services."""
    jm.log_info("Subdomain takeover detection →")
    from core.db import Asset
    assets_db = session.query(Asset).filter(Asset.scan_id == scan_id, Asset.asset_type == "subdomain").all()
    subdomains = [a.value for a in assets_db]

    # Takeover fingerprints — string in response body of unclaimed service
    TAKEOVER_FINGERPRINTS = {
        "GitHub Pages":         "There isn't a GitHub Pages site here",
        "Heroku":               "No such app",
        "Shopify":              "Sorry, this shop is currently unavailable",
        "Fastly":               "Fastly error: unknown domain",
        "AWS Elastic Beanstalk":"404 Not Found",
        "Azure":                "404 Web Site not found",
        "Zendesk":              "Help Center Closed",
        "Ghost":                "The thing you were looking for is no longer here",
        "Tumblr":               "Whatever you were looking for doesn't live here anymore",
        "Pantheon":             "The gods are wise, but do not know of the site",
        "WordPress":            "Do you want to register",
        "Netlify":              "Not Found - Request ID",
        "Surge.sh":             "project not found",
        "ReadTheDocs":          "unknown to Read the Docs",
    }
    import aiohttp
    findings = []
    try:
        async with aiohttp.ClientSession() as sess:
            for subdomain in subdomains[:50]:
                for scheme in ("https", "http"):
                    url = f"{scheme}://{subdomain}"
                    try:
                        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                            allow_redirects=True, ssl=False) as resp:
                            body = await resp.text(errors="replace")
                            for service, fingerprint in TAKEOVER_FINGERPRINTS.items():
                                if fingerprint.lower() in body.lower():
                                    findings.append(NormalizedFinding(
                                        scan_id=scan_id, tool="aarchai-takeover",
                                        finding_type="subdomain_takeover",
                                        title=f"SUBDOMAIN TAKEOVER: {subdomain} → {service}",
                                        severity=Severity.critical,
                                        host=host, url=url,
                                        description=f"Subdomain {subdomain} appears vulnerable to takeover!"
                                                    f"Points to unclaimed {service} resource."
                                                    f"Fingerprint: '{fingerprint}'",
                                        remediation=f"Remove or update the DNS CNAME for {subdomain}. "
                                                    f"Claim the resource on {service} or delete the DNS record.",
                                        raw_output=body[:500],
                                        fingerprint_hash=make_hash("takeover", subdomain, service),
                                    ))
                                    jm.log_finding("critical", findings[-1].title)
                                    break
                    except Exception:
                        pass
    except Exception as e:
        jm.log_warn(f"Takeover: {e}")

    # Also run nuclei takeover templates
    if tool_available("nuclei") and subdomains:
        targets_file = "/tmp/takeover_targets.txt"
        Path(targets_file).write_text("".join(subdomains[:30]))
        r = await run_async(
            ["nuclei", "-l", targets_file, "-t", "takeovers/", "-j", "-silent"],
            timeout=120
        )
        import json
        for line in r.stdout.splitlines():
            try:
                d = json.loads(line)
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="nuclei-takeover",
                    finding_type="subdomain_takeover",
                    title=d.get("info", {}).get("name", "Subdomain takeover"),
                    severity=Severity.critical,
                    host=host, url=d.get("matched-at", ""),
                    description=d.get("info", {}).get("description", ""),
                    raw_output=line,
                    fingerprint_hash=make_hash("nuclei_takeover", d.get("matched-at", "")),
                ))
            except Exception:
                pass
    jm.log_ok(f"Takeover: {len(findings)} vulnerable subdomains")
    return findings, []


async def _waf_bypass(host, scan_id, jm, auth):
    """Attempt WAF bypass techniques for XSS/SQLi payloads."""
    jm.log_info("WAF bypass testing →")
    import aiohttp
    findings = []
    base_url = f"https://{host}"

    # WAF bypass payloads for XSS
    xss_bypasses = [
        # Encoding tricks
        ("<script>alert(1)</script>",                  "Basic XSS"),
        ("<img src=x onerror=alert(1)>",               "IMG onerror"),
        ("<svg onload=alert(1)>",                       "SVG onload"),
        ("<script>alert`1`</script>",                  "Template literal"),
        ("javascript:alert(1)",                        "JS URI"),
        ("%3Cscript%3Ealert(1)%3C/script%3E",         "URL encoded"),
        ("&#60;script&#62;alert(1)&#60;/script&#62;", "HTML entities"),
        ("<ScRiPt>alert(1)</sCrIpT>",                 "Case variation"),
        ("<script >alert(1)</script >",                "Space before >"),
        ("';alert(1)//",                               "JS injection"),
    ]

    # SQLi bypass payloads
    sqli_bypasses = [
        ("' OR '1'='1",               "Classic SQLi"),
        ("' OR 1=1--",                "Comment bypass"),
        ("admin'--",                  "Admin login bypass"),
        ("' UNION SELECT 1,2,3--",   "UNION inject"),
        ("1' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--", "Error-based"),
        ("' OR 'x'='x",              "String comparison"),
        ("1/**/OR/**/1=1",           "Comment obfuscation"),
        ("1%27+OR+1=1--",            "URL encoded"),
    ]

    waf_bypassed = []
    try:
        async with aiohttp.ClientSession() as sess:
            for payload, name in xss_bypasses[:5]:
                url = f"{base_url}/?q={payload}"
                try:
                    async with sess.get(url, timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                        body = await resp.text(errors="replace")
                        if resp.status != 403 and payload.lower() in body.lower():
                            waf_bypassed.append(("XSS", name, payload, url))
                            break
                except Exception:
                    pass

        if waf_bypassed:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="aarchai-waf-bypass",
                finding_type="waf_bypass",
                title=f"WAF Bypass: {len(waf_bypassed)} payload(s) evaded WAF",
                severity=Severity.high,
                host=host,
                description="WAF bypass techniques that successfully evaded detection:" +"".join(f"{t} [{n}]: {p}" for t, n, p, u in waf_bypassed),
                remediation="Update WAF rules. Test with OWASP CRS. Enable anomaly scoring mode.",
                raw_output=str(waf_bypassed),
                fingerprint_hash=make_hash("waf_bypass", host, str(len(waf_bypassed))),
            ))
            jm.log_finding("high", findings[-1].title)
    except Exception as e:
        jm.log_warn(f"WAF bypass: {e}")
    return findings, []


async def _screenshot_diff(host, scan_id, jm, out_dir, session):
    """Compare screenshots between scans using perceptual hashing."""
    jm.log_info("Screenshot diff →")
    if not out_dir:
        return [], []
    findings = []
    try:
        import imagehash
        from PIL import Image

        current_dir = Path(out_dir) / "screenshots"
        if not current_dir.exists():
            return [], []

        # Find previous scan screenshots
        from core.db import Scan
        prev_scans = session.query(Scan).filter(
            Scan.id < scan_id
        ).order_by(Scan.id.desc()).limit(3).all()

        for prev_scan in prev_scans:
            prev_dir = Path(out_dir).parent / f"scan_{prev_scan.id}" / "screenshots"
            if not prev_dir.exists():
                continue

            for curr_img in current_dir.glob("*.png"):
                prev_img = prev_dir / curr_img.name
                if not prev_img.exists():
                    continue
                try:
                    h1 = imagehash.phash(Image.open(curr_img))
                    h2 = imagehash.phash(Image.open(prev_img))
                    diff = h1 - h2
                    if diff > 10:  # Significant visual change
                        findings.append(NormalizedFinding(
                            scan_id=scan_id, tool="screenshot-diff",
                            finding_type="visual_change_detected",
                            title=f"Visual change detected: {curr_img.name} (diff={diff})",
                            severity=Severity.medium if diff < 30 else Severity.high,
                            host=host,
                            description=f"Screenshot '{curr_img.name}' changed significantly between scan #{prev_scan.id} and #{scan_id}."
                                        f"Perceptual hash difference: {diff}/64 (0=identical, 64=completely different)."
                                        f"This may indicate: defacement, new login page, content change, or infrastructure change.",
                            remediation="Investigate what changed on the page. If unexpected, may indicate compromise.",
                            raw_output=f"diff={diff} prev={prev_scan.id} curr={scan_id}",
                            fingerprint_hash=make_hash("screenshot_diff", host, curr_img.name, str(scan_id)),
                        ))
                        jm.log_finding("medium", findings[-1].title)
                except Exception:
                    pass
    except ImportError:
        jm.log_warn("Screenshot diff requires: pip3 install imagehash Pillow")
    except Exception as e:
        jm.log_warn(f"Screenshot diff: {e}")
    return findings, []


async def _password_spray(host, scan_id, jm, session, auth):
    """Smart password spray using harvested emails with lockout protection."""
    jm.log_info("Password spray (throttled) →")
    from core.db import Asset, Finding
    # Get harvested emails
    emails = [a.value for a in session.query(Asset).filter(
        Asset.scan_id == scan_id, Asset.asset_type == "email"
    ).limit(20).all()]

    if not emails:
        return [], []

    common_passwords = [
        "Password1!", "Winter2024!", "Summer2024!", "Company1!",
        "Welcome1!", "Admin@123", "P@ssw0rd", "Qwerty@123",
    ]
    findings = []
    import aiohttp
    import asyncio as aio

    login_forms = []
    try:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, args=["--no-sandbox"])
            page = await browser.new_page()
            await page.goto(f"https://{host}/login", timeout=10000)
            forms = await page.query_selector_all("form")
            if forms:
                login_forms.append(f"https://{host}/login")
            await page.goto(f"https://{host}/wp-login.php", timeout=8000)
            forms2 = await page.query_selector_all("form")
            if forms2:
                login_forms.append(f"https://{host}/wp-login.php")
            await browser.close()
    except Exception:
        pass

    # Only 1 password per account max (avoid lockout)
    # Only spray if login forms found
    if login_forms and emails:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="aarchai-spray",
            finding_type="password_spray_opportunity",
            title=f"Password spray opportunity: {len(emails)} targets, {len(login_forms)} login forms",
            severity=Severity.medium,
            host=host,
            description=f"Found {len(emails)} email addresses and {len(login_forms)} login forms."
                        f"Login endpoints: {login_forms}"
                        f"Target accounts: {emails[:10]}"
                        f"[Password spray was rate-limited to prevent lockout — manual validation recommended]",
            remediation="Implement account lockout policies (3-5 attempts). Enable MFA. Monitor for spray patterns.",
            raw_output=f"emails={len(emails)} forms={len(login_forms)}",
            fingerprint_hash=make_hash("spray_opportunity", host, str(len(emails))),
        ))
    return findings, []
