"""Stage 12 — Active Directory / Kerberos: bloodhound, kerbrute, AD attack paths."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None, ad_domain=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth, ad_domain))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth, ad_domain):
    host = target.host
    domain = ad_domain or host
    jm.log_stage("stage12_ad", f"AD/Kerberos scan: {host} | domain: {domain}")

    tasks = [
        asyncio.create_task(_ldap_enum(host, scan_id, jm, domain, auth)),
        asyncio.create_task(_kerbrute(host, scan_id, jm, domain, fast)),
        asyncio.create_task(_asrep_roasting(host, scan_id, jm, domain)),
        asyncio.create_task(_smb_enum(host, scan_id, jm, auth)),
        asyncio.create_task(_bloodhound_collect(host, scan_id, jm, domain, auth, out_dir)),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r; findings.extend(f); assets.extend(a)
        else:
            jm.log_warn(f"AD task error: {r}")

    jm.log_ok(f"AD: {len(findings)} findings")
    return findings, assets


async def _ldap_enum(host, scan_id, jm, domain, auth):
    """Enumerate AD via LDAP — users, groups, OUs."""
    jm.log_info("LDAP enumeration →")
    if not tool_available("ldapsearch"):
        return [], []
    findings, assets = [], []
    r = await run_async(
        ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", "", "-s", "base"],
        timeout=30
    )
    if r.success and ("namingContexts" in r.stdout or "defaultNamingContext" in r.stdout):
        # Extract naming context
        for line in r.stdout.splitlines():
            if "namingContexts" in line:
                nc = line.split(":")[-1].strip()
                # Try anonymous user enum
                r2 = await run_async(
                    ["ldapsearch", "-x", "-H", f"ldap://{host}", "-b", nc,
                     "(objectClass=user)", "samAccountName", "mail"],
                    timeout=60
                )
                if r2.success:
                    users = [l.split(":")[-1].strip() for l in r2.stdout.splitlines()
                             if l.startswith("sAMAccountName")]
                    if users:
                        findings.append(NormalizedFinding(
                            scan_id=scan_id, tool="ldapsearch",
                            finding_type="ad_anonymous_ldap",
                            title=f"Anonymous LDAP enabled — {len(users)} AD users enumerated",
                            severity=Severity.critical,
                            host=host,
                            description=f"LDAP anonymous bind allowed on {host}."
                                        f"Enumerated {len(users)} users:" + "".join(users[:20]),
                            remediation="Disable anonymous LDAP bind. Require authentication for all LDAP queries.",
                            raw_output="".join(users),
                            fingerprint_hash=make_hash("ldap_anon", host, domain),
                        ))
                        for u in users[:50]:
                            assets.append({"type": "ad_user", "value": u, "source_tool": "ldapsearch"})
                        jm.log_finding("critical", findings[-1].title)
    return findings, assets


async def _kerbrute(host, scan_id, jm, domain, fast):
    """User enumeration via Kerberos pre-auth (no creds needed)."""
    jm.log_info("kerbrute user enum →")
    if not tool_available("kerbrute"):
        jm.log_warn("kerbrute not installed: https://github.com/ropnop/kerbrute")
        return [], []
    wordlist = "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
    if not Path(wordlist).exists():
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not Path(wordlist).exists():
        return [], []

    r = await run_async(
        ["kerbrute", "userenum", "--dc", host, "-d", domain, wordlist,
         "--output", "/tmp/kerbrute_out.txt"],
        timeout=180 if not fast else 60
    )
    findings, assets = [], []
    valid_users = []
    if Path("/tmp/kerbrute_out.txt").exists():
        for line in Path("/tmp/kerbrute_out.txt").read_text().splitlines():
            if "VALID USERNAME" in line:
                user = line.split(":")[-1].strip()
                valid_users.append(user)
                assets.append({"type": "ad_user", "value": user, "source_tool": "kerbrute"})

    if valid_users:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="kerbrute",
            finding_type="ad_user_enum",
            title=f"Kerberos user enumeration: {len(valid_users)} valid AD user(s) found",
            severity=Severity.high,
            host=host,
            description=f"Valid AD usernames discovered via Kerberos pre-auth:" + "".join(valid_users[:30]),
            remediation="Implement Kerberos pre-auth requirements for all accounts. Monitor for Kerberos enum attempts.",
            raw_output="".join(valid_users),
            fingerprint_hash=make_hash("kerbrute", host, domain, str(len(valid_users))),
        ))
        jm.log_finding("high", findings[-1].title)
    return findings, assets


async def _asrep_roasting(host, scan_id, jm, domain):
    """AS-REP roasting — find accounts without pre-auth (Kerberoasting)."""
    jm.log_info("AS-REP roasting →")
    if not tool_available("GetNPUsers.py"):
        return [], []
    r = await run_async(
        ["GetNPUsers.py", f"{domain}/", "-dc-ip", host, "-no-pass", "-usersfile",
         "/tmp/kerbrute_out.txt", "-format", "hashcat", "-outputfile", "/tmp/asrep_hashes.txt"],
        timeout=120
    )
    findings = []
    if Path("/tmp/asrep_hashes.txt").exists():
        hashes = Path("/tmp/asrep_hashes.txt").read_text().strip().splitlines()
        if hashes:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="impacket",
                finding_type="asrep_roasting",
                title=f"AS-REP Roasting: {len(hashes)} crackable hash(es) captured",
                severity=Severity.critical,
                host=host,
                description=f"Found {len(hashes)} account(s) with Kerberos pre-authentication disabled."
                            f"Hashes can be cracked offline with hashcat:"
                            f"hashcat -m 18200 hashes.txt rockyou.txt",
                remediation="Enable Kerberos pre-authentication for all accounts. "
                            "Immediately reset passwords of affected accounts.",
                raw_output="".join(hashes[:5]),
                fingerprint_hash=make_hash("asrep", host, domain, str(len(hashes))),
            ))
            jm.log_finding("critical", findings[-1].title)
    return findings, []


async def _smb_enum(host, scan_id, jm, auth):
    """SMB enumeration — shares, null sessions, relay opportunities."""
    jm.log_info("SMB enumeration →")
    findings, assets = [], []
    # Check SMB signing (relay attack prerequisite)
    r = await run_async(
        ["nmap", "-p", "445", "--script", "smb2-security-mode", host],
        timeout=30
    )
    if "Message signing enabled but not required" in r.stdout:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="nmap",
            finding_type="smb_signing_disabled",
            title=f"SMB Signing NOT Required on {host} — NTLM relay attack possible",
            severity=Severity.high,
            host=host, port=445,
            description="SMB message signing is not required. This allows NTLM relay attacks."
                        "An attacker can relay authentication to gain access with victim's privileges.",
            remediation="Enable and require SMB message signing via GPO: "
                        "'Microsoft network server: Digitally sign communications (always)'",
            raw_output=r.stdout[:500],
            fingerprint_hash=make_hash("smb_signing", host),
        ))
        jm.log_finding("high", findings[-1].title)

    # Enumerate shares via null session
    r2 = await run_async(["smbclient", "-L", host, "-N"], timeout=20)
    if r2.success:
        shares = [l.strip().split()[0] for l in r2.stdout.splitlines() if "Disk" in l or "IPC" in l]
        for share in shares:
            assets.append({"type": "smb_share", "value": f"\\{host}\{share}", "source_tool": "smbclient"})
        if shares:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="smbclient",
                finding_type="smb_null_session",
                title=f"SMB null session: {len(shares)} share(s) enumerated without credentials",
                severity=Severity.high,
                host=host, port=445,
                description=f"SMB null session allowed. Shares: {shares}",
                remediation="Disable null session access via Group Policy. Require authentication for all SMB connections.",
                raw_output=r2.stdout[:500],
                fingerprint_hash=make_hash("smb_null", host),
            ))
            jm.log_finding("high", findings[-1].title)
    return findings, assets


async def _bloodhound_collect(host, scan_id, jm, domain, auth, out_dir):
    """Run BloodHound data collection (requires credentials)."""
    jm.log_info("BloodHound collection →")
    if not tool_available("bloodhound-python"):
        jm.log_warn("bloodhound-python not installed: pip3 install bloodhound")
        return [], []
    if not auth:
        jm.log_info("BloodHound skipped — no auth credentials provided")
        return [], []

    username = getattr(auth, "username", None)
    password = getattr(auth, "password", None)
    if not username or not password:
        return [], []

    out_path = str(out_dir) + "/bloodhound" if out_dir else "/tmp/bloodhound"
    Path(out_path).mkdir(parents=True, exist_ok=True)

    r = await run_async(
        ["bloodhound-python", "-d", domain, "-u", username, "-p", password,
         "-c", "All", "--zip", "-o", out_path],
        timeout=300
    )
    findings = []
    if r.success:
        findings.append(NormalizedFinding(
            scan_id=scan_id, tool="bloodhound",
            finding_type="ad_bloodhound_collected",
            title=f"BloodHound data collected for {domain}",
            severity=Severity.info,
            host=host,
            description=f"BloodHound collection complete. Import ZIP from {out_path} into BloodHound GUI to visualize attack paths.",
            raw_output=r.stdout[:1000],
            fingerprint_hash=make_hash("bloodhound", host, domain),
        ))
        jm.log_ok("BloodHound collection done — import ZIP into BloodHound GUI")
    return findings, []
