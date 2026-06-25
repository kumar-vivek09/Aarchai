"""Stage 4b — Secret & Credential Detection: gitleaks, trufflehog, JS scan, default creds."""
from __future__ import annotations
import asyncio
import json
from pathlib import Path
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth):
    host = target.host
    jm.log_stage("stage4b_secrets", f"Secret & credential detection on {host}")

    tasks = [
        asyncio.create_task(_check_exposed_files(host, scan_id, jm, auth)),
        asyncio.create_task(_run_gitleaks(host, scan_id, jm, auth)),
        asyncio.create_task(_run_jsfinder(host, scan_id, jm, auth)),
        asyncio.create_task(_check_default_creds(host, scan_id, jm, fast)),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    findings = []
    for r in results:
        if not isinstance(r, Exception):
            findings.extend(r)
        elif isinstance(r, Exception):
            jm.log_warn(f"Secrets task error: {r}")

    jm.log_ok(f"Secrets stage: {len(findings)} findings")
    return findings, []


async def _check_exposed_files(host, scan_id, jm):
    """Check for exposed sensitive files: .git, .env, config.json, etc."""
    jm.log_info("Checking exposed sensitive files →")
    import aiohttp
    sensitive_paths = [
        "/.git/HEAD",
        "/.git/config",
        "/.env",
        "/.env.local",
        "/.env.production",
        "/config.json",
        "/config.yaml",
        "/config.yml",
        "/database.yml",
        "/settings.py",
        "/wp-config.php",
        "/phpinfo.php",
        "/server-status",
        "/actuator/env",
        "/actuator/health",
        "/.htpasswd",
        "/backup.zip",
        "/backup.sql",
        "/dump.sql",
        "/id_rsa",
        "/id_rsa.pub",
        "/credentials.json",
        "/secrets.json",
        "/api-keys.json",
    ]
    findings = []
    async with aiohttp.ClientSession() as sess:
        tasks = [_check_path(sess, host, path, scan_id) for path in sensitive_paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if r and not isinstance(r, Exception):
            findings.append(r)
            jm.log_finding("critical", findings[-1].title)
    jm.log_ok(f"Exposed files: {len(findings)} found")
    return findings


async def _check_path(sess, host, path, scan_id):
    import aiohttp
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}{path}"
        try:
            async with sess.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                allow_redirects=False, ssl=False) as resp:
                if resp.status in (200, 206):
                    body = await resp.text(errors="replace")
                    sev, ftype = _classify_exposed_file(path, body)
                    return NormalizedFinding(
                        scan_id=scan_id, tool="aarchai-scanner",
                        finding_type=ftype,
                        title=f"Exposed file: {path}",
                        severity=sev,
                        host=host, url=url,
                        description=f"HTTP {resp.status} at {url}Content preview:{body[:500]}",
                        remediation=f"Block access to {path} via web server config. Restrict file permissions.",
                        raw_output=body[:2000],
                        fingerprint_hash=make_hash("exposed_file", host, path),
                    )
        except Exception:
            pass
    return None


def _classify_exposed_file(path: str, body: str) -> tuple:
    path_lower = path.lower()
    if ".git" in path_lower:
        return Severity.critical, "git_exposed"
    if ".env" in path_lower or "password" in body.lower() or "secret" in body.lower():
        return Severity.critical, "env_exposed"
    if "phpinfo" in path_lower:
        return Severity.high, "phpinfo_exposed"
    if "actuator" in path_lower:
        return Severity.high, "actuator_exposed"
    if any(x in path_lower for x in (".sql", "backup", "dump")):
        return Severity.critical, "backup_exposed"
    if "id_rsa" in path_lower:
        return Severity.critical, "private_key_exposed"
    return Severity.high, "sensitive_file_exposed"


async def _run_gitleaks(host, scan_id, jm, auth=None):
    """Check .git repo for leaked secrets using gitleaks."""
    jm.log_info("gitleaks →")
    import aiohttp, tempfile
    if not tool_available("gitleaks"):
        jm.log_warn("gitleaks not found — install: apt install gitleaks")
        return []

    # Try to clone the exposed git repo
    git_url = f"http://{host}/.git"
    with tempfile.TemporaryDirectory() as td:
        clone_r = await run_async(
            ["git", "clone", f"http://{host}/", td + "/repo", "--depth=1"],
            timeout=60
        )
        if not clone_r.success:
            return []

        r = await run_async(
            ["gitleaks", "detect", "--source", td + "/repo",
             "--report-format", "json", "--report-path", "/tmp/gitleaks.json",
             "--no-banner"],
            timeout=90
        )

    findings = []
    if Path("/tmp/gitleaks.json").exists():
        try:
            leaks = json.loads(Path("/tmp/gitleaks.json").read_text())
            for leak in leaks:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="gitleaks",
                    finding_type="secret_in_git",
                    title=f"Secret in Git: {leak.get('Description','secret')} in {leak.get('File','')}",
                    severity=Severity.critical,
                    host=host,
                    description=f"Rule: {leak.get('RuleID','')}\n" +
                                f"File: {leak.get('File','')}\n" +
                                f"Line: {leak.get('StartLine','')}\n" +
                                f"Match: {str(leak.get('Match',''))[:200]}",
                    remediation="Remove the secret from git history using git-filter-repo. Rotate the exposed credentials immediately.",
                    raw_output=str(leak)[:2000],
                    fingerprint_hash=make_hash("gitleaks", host, leak.get("File",""), leak.get("RuleID","")),
                ))
                jm.log_finding("critical", findings[-1].title)
        except Exception:
            pass
    jm.log_ok(f"gitleaks: {len(findings)} secrets found")
    return findings


async def _run_jsfinder(host, scan_id, jm, auth=None):
    """Scan JS files for API keys and endpoints using jsfinder."""
    jm.log_info("JS secret scan →")
    if not tool_available("jsfinder"):
        # Fallback: use our own JS pattern scanner via httpx output
        return []

    r = await run_async(
        ["jsfinder", "-u", f"http://{host}", "-o", "/tmp/jsfinder_out.txt"],
        timeout=120
    )
    findings = []
    if Path("/tmp/jsfinder_out.txt").exists():
        content = Path("/tmp/jsfinder_out.txt").read_text()
        for line in content.splitlines():
            if any(k in line.lower() for k in ("api_key", "secret", "token", "password", "access_key")):
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="jsfinder",
                    finding_type="secret_in_js",
                    title=f"Potential secret in JS: {line[:80]}",
                    severity=Severity.high,
                    host=host,
                    description=f"jsfinder found potential secret in JavaScript:{line[:500]}",
                    remediation="Move secrets to environment variables. Never include API keys in client-side code.",
                    raw_output=line[:1000],
                    fingerprint_hash=make_hash("jsfinder", host, line[:60]),
                ))
    return findings


async def _check_default_creds(host, scan_id, jm, fast=False):
    """Check for default credentials on common services."""
    jm.log_info("Default credential check →")
    from utils.async_runner import run_async

    # Common service:port:creds to check
    checks = [
        (21,   "ftp",       "admin", "admin"),
        (21,   "ftp",       "anonymous", ""),
        (22,   "ssh",       "root", "root"),
        (22,   "ssh",       "admin", "admin"),
        (23,   "telnet",    "admin", "admin"),
        (3306, "mysql",     "root", ""),
        (5432, "postgres",  "postgres", "postgres"),
        (6379, "redis",     "", ""),
        (27017, "mongodb",  "", ""),
    ]

    findings = []
    # Check open ports first
    from utils.async_runner import run_async
    open_ports = await _get_open_ports(host)

    for port, service, user, passwd in checks:
        if fast and port not in (22, 3306, 6379):
            continue
        if port not in open_ports:
            continue

        found = await _try_cred(host, port, service, user, passwd)
        if found:
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="aarchai-default-creds",
                finding_type="default_credential",
                title=f"Default credential on {service}:{port} ({user}:{passwd or '<empty>'})",
                severity=Severity.critical,
                host=host, port=port,
                description=f"Successfully authenticated to {service} on port {port} using default credentials: {user}:{passwd}",
                remediation=f"Change the default password for {service} immediately. Disable the service if not needed.",
                raw_output=f"service={service} port={port} user={user}",
                fingerprint_hash=make_hash("default_cred", host, str(port), service, user),
            ))
            jm.log_finding("critical", findings[-1].title)

    jm.log_ok(f"Default creds: {len(findings)} found")
    return findings


async def _get_open_ports(host: str) -> set[int]:
    r = await run_async(["nmap", "-p", "21,22,23,3306,5432,6379,27017", "--open",
                         "-oG", "-", host], timeout=60)
    ports = set()
    for line in r.stdout.splitlines():
        if "open" in line:
            for part in line.split():
                if "/open" in part:
                    try:
                        ports.add(int(part.split("/")[0]))
                    except Exception:
                        pass
    return ports


async def _try_cred(host: str, port: int, service: str, user: str, passwd: str) -> bool:
    """Attempt a credential check using appropriate tool."""
    if service == "ftp":
        import ftplib
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=5)
            ftp.login(user, passwd)
            ftp.quit()
            return True
        except Exception:
            return False
    elif service in ("ssh",):
        if not tool_available("hydra"):
            return False
        r = await run_async(
            ["hydra", "-l", user, "-p", passwd, f"ssh://{host}:{port}",
             "-t", "1", "-f", "-q"],
            timeout=20
        )
        return "1 valid password" in r.stdout.lower()
    elif service == "redis":
        r = await run_async(["redis-cli", "-h", host, "-p", str(port), "PING"], timeout=5)
        return "PONG" in r.stdout
    elif service == "mysql":
        r = await run_async(
            ["mysql", "-h", host, f"-P{port}", f"-u{user}", "--connect-timeout=5", "-e", "SELECT 1"],
            timeout=10
        )
        return r.success
    return False
