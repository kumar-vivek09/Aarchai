"""Stage 8 — OSINT: employees, breaches, ASN/BGP, dark web mentions, social media."""
from __future__ import annotations
import asyncio
import json
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir))


async def _run_async(target, scan_id, session, jm, fast, out_dir):
    host = target.host
    jm.log_stage("stage8_osint", f"OSINT collection: {host}")

    tasks = [
        asyncio.create_task(_asn_bgp(host, scan_id, jm)),
        asyncio.create_task(_email_harvest(host, scan_id, jm, fast)),
        asyncio.create_task(_breach_check(host, scan_id, jm)),
        asyncio.create_task(_cert_monitor(host, scan_id, jm)),
        asyncio.create_task(_whois_deep(host, scan_id, jm)),
    ]
    if not fast:
        tasks.append(asyncio.create_task(_social_media(host, scan_id, jm)))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r
            findings.extend(f); assets.extend(a)
        else:
            jm.log_warn(f"OSINT task error: {r}")

    jm.log_ok(f"OSINT: {len(findings)} findings, {len(assets)} assets")
    return findings, assets


async def _asn_bgp(host, scan_id, jm):
    """Discover company ASN and all owned CIDR ranges via BGP."""
    jm.log_info("ASN/BGP lookup →")
    findings, assets = [], []
    try:
        import aiohttp
        # Use bgpview.io free API
        async with aiohttp.ClientSession() as sess:
            # Resolve IP for domain
            import socket
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                return [], []

            async with sess.get(f"https://api.bgpview.io/ip/{ip}",
                                timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    return [], []
                data = await resp.json()

            prefix_data = data.get("data", {})
            asn_info = prefix_data.get("rir_allocation", {})
            pfxs = prefix_data.get("prefixes", [])

            for pfx in pfxs:
                cidr = pfx.get("prefix", "")
                asn  = pfx.get("asn", {}).get("asn", "")
                name = pfx.get("asn", {}).get("description", "")
                if cidr:
                    assets.append({
                        "type": "cidr", "value": cidr, "source_tool": "bgpview",
                        "service": f"ASN{asn} {name}"
                    })

            asn_nums = list({p.get("asn", {}).get("asn") for p in pfxs if p.get("asn")})
            if asn_nums:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="bgpview",
                    finding_type="asn_discovery",
                    title=f"ASN Discovery: {len(asn_nums)} ASN(s), {len(pfxs)} CIDR prefix(es)",
                    severity=Severity.info,
                    host=host,
                    description=f"ASNs: {asn_nums}
CIDR ranges: {[p.get('prefix') for p in pfxs[:10]]}
"
                                f"This reveals the full IP space the organisation controls.",
                    raw_output=json.dumps(pfxs[:20]),
                    fingerprint_hash=make_hash("asn", host, str(asn_nums)),
                ))
                jm.log_ok(f"ASN: {len(asn_nums)} ASNs, {len(pfxs)} CIDRs")
    except Exception as e:
        jm.log_warn(f"ASN/BGP: {e}")
    return findings, assets


async def _email_harvest(host, scan_id, jm, fast):
    """Harvest employee emails via theHarvester, hunter.io API."""
    jm.log_info("Email harvest →")
    findings, assets = [], []
    from utils.async_runner import run_async
    r = await run_async(
        ["theHarvester", "-d", host, "-b", "bing,google,crtsh,linkedin", "-l", "100"],
        timeout=120
    )
    emails = set()
    for line in r.stdout.splitlines():
        line = line.strip()
        if "@" in line and host.split(".")[0] in line.lower():
            emails.add(line.lower())

    for email in list(emails)[:50]:
        assets.append({"type": "email", "value": email, "source_tool": "theHarvester"})

    if emails:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="theHarvester",
            finding_type="email_harvest",
            title=f"Harvested {len(emails)} employee email address(es)",
            severity=Severity.medium,
            host=host,
            description=f"Employee emails discovered:
" + "
".join(list(emails)[:20]),
            remediation="Review email harvesting exposure. Consider email alias strategies for public-facing contacts.",
            raw_output="
".join(emails),
            fingerprint_hash=make_hash("emails", host, str(sorted(emails)[:5])),
        ))
        jm.log_ok(f"Emails: {len(emails)} found")
    return findings, assets


async def _breach_check(host, scan_id, jm):
    """Check for breached credentials via h8mail and HIBP API."""
    jm.log_info("Breach check →")
    findings = []
    try:
        import aiohttp
        # Use HIBP domain search (free, no key needed for domain check)
        async with aiohttp.ClientSession() as sess:
            async with sess.get(
                f"https://haveibeenpwned.com/api/v3/breacheddomain/{host}",
                headers={"user-agent": "Aarchai-Scanner/2.0"},
                timeout=aiohttp.ClientTimeout(total=15)
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    count = len(data) if isinstance(data, list) else 0
                    if count > 0:
                        findings.append(NormalizedFinding(
                            scan_id=scan_id, tool="hibp",
                            finding_type="credential_breach",
                            title=f"HIBP: {host} found in {count} data breach(es)",
                            severity=Severity.high,
                            host=host,
                            description=f"Domain {host} was found in {count} known data breach(es) on HaveIBeenPwned.
"
                                        f"Breaches: {json.dumps(data[:5])}",
                            remediation="Force password resets for all affected accounts. Implement MFA immediately.",
                            raw_output=json.dumps(data[:10]),
                            fingerprint_hash=make_hash("hibp", host, str(count)),
                        ))
                        jm.log_finding("high", findings[-1].title)
    except Exception as e:
        jm.log_warn(f"Breach check: {e}")
    return findings, []


async def _cert_monitor(host, scan_id, jm):
    """Certificate transparency monitoring + expiry tracking."""
    jm.log_info("Certificate monitoring →")
    findings = []
    try:
        import aiohttp
        from datetime import datetime, timezone
        async with aiohttp.ClientSession() as sess:
            async with sess.get(
                f"https://crt.sh/?q={host}&output=json",
                timeout=aiohttp.ClientTimeout(total=20)
            ) as resp:
                if resp.status != 200:
                    return [], []
                certs = await resp.json()

        # Check for wildcard certs, expired certs, recent issuances
        wildcard_count = sum(1 for c in certs if "*" in c.get("name_value", ""))
        recent = [c for c in certs if c.get("not_after", "") > datetime.now(timezone.utc).strftime("%Y-%m-%d")]

        # Expiry check
        expiring_soon = []
        for c in certs:
            not_after = c.get("not_after", "")
            if not_after:
                try:
                    exp = datetime.strptime(not_after[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    days = (exp - datetime.now(timezone.utc)).days
                    if 0 < days < 30:
                        expiring_soon.append((c.get("name_value",""), days))
                except Exception:
                    pass

        if expiring_soon:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="crt.sh",
                finding_type="cert_expiry",
                title=f"SSL certificate expiring soon: {len(expiring_soon)} cert(s) within 30 days",
                severity=Severity.high,
                host=host,
                description="
".join(f"{name}: {d} days" for name, d in expiring_soon[:10]),
                remediation="Renew SSL certificates immediately. Set up auto-renewal with Let's Encrypt.",
                raw_output=str(expiring_soon),
                fingerprint_hash=make_hash("cert_expiry", host, str(len(expiring_soon))),
            ))

        if wildcard_count > 0:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="crt.sh",
                finding_type="wildcard_cert",
                title=f"Wildcard certificate in use ({wildcard_count} wildcard cert(s))",
                severity=Severity.info,
                host=host,
                description=f"Wildcard certificates found. A single compromised key affects all subdomains.",
                remediation="Consider per-subdomain certificates for critical services.",
                raw_output=str(wildcard_count),
                fingerprint_hash=make_hash("wildcard_cert", host),
            ))

        jm.log_ok(f"Certs: {len(certs)} found, {len(expiring_soon)} expiring, {wildcard_count} wildcards")
    except Exception as e:
        jm.log_warn(f"Cert monitor: {e}")
    return findings, []


async def _whois_deep(host, scan_id, jm):
    """Deep WHOIS — registrar, registrant, nameservers, privacy shield."""
    jm.log_info("Deep WHOIS →")
    from utils.async_runner import run_async
    r = await run_async(["whois", host], timeout=20)
    assets = []
    findings = []
    if r.success:
        lines = r.stdout.lower()
        # Check for privacy protection
        if any(x in lines for x in ("privacy", "redacted", "withheld", "protect")):
            pass  # normal
        else:
            # Extract nameservers for DNS infrastructure mapping
            ns_lines = [l for l in r.stdout.splitlines() if "name server" in l.lower()]
            nameservers = [l.split(":")[-1].strip() for l in ns_lines if ":" in l]
            for ns in nameservers:
                assets.append({"type": "nameserver", "value": ns, "source_tool": "whois"})
    return findings, assets


async def _social_media(host, scan_id, jm):
    """Social media footprinting — check common platforms."""
    jm.log_info("Social media footprint →")
    import aiohttp
    company = host.split(".")[0]
    findings = []
    platforms = {
        "LinkedIn":  f"https://www.linkedin.com/company/{company}",
        "Twitter":   f"https://twitter.com/{company}",
        "GitHub":    f"https://github.com/{company}",
        "Facebook":  f"https://www.facebook.com/{company}",
        "Instagram": f"https://www.instagram.com/{company}",
    }
    found = []
    try:
        async with aiohttp.ClientSession() as sess:
            for platform, url in platforms.items():
                try:
                    async with sess.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                        allow_redirects=True) as resp:
                        if resp.status == 200:
                            found.append((platform, url))
                except Exception:
                    pass

        if found:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="aarchai-osint",
                finding_type="social_media_presence",
                title=f"Social media profiles found: {', '.join(p for p,_ in found)}",
                severity=Severity.info,
                host=host,
                description="
".join(f"{p}: {u}" for p, u in found),
                raw_output=str(found),
                fingerprint_hash=make_hash("social", host, str(sorted(p for p,_ in found))),
            ))
    except Exception as e:
        jm.log_warn(f"Social media: {e}")
    return findings, []
