"""Stage 9 — Cloud Asset Discovery: S3, Azure Blob, GCP, metadata endpoints."""
from __future__ import annotations
import asyncio
import json
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir))


async def _run_async(target, scan_id, session, jm, fast, out_dir):
    host = target.host
    jm.log_stage("stage9_cloud", f"Cloud asset discovery: {host}")

    company = host.split(".")[0]  # e.g. "example" from "example.com"

    tasks = [
        asyncio.create_task(_metadata_endpoint(host, scan_id, jm)),
        asyncio.create_task(_s3_enum(company, host, scan_id, jm)),
        asyncio.create_task(_azure_enum(company, host, scan_id, jm)),
        asyncio.create_task(_gcp_enum(company, host, scan_id, jm)),
        asyncio.create_task(_cloud_nuclei(host, scan_id, jm, out_dir)),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r
            findings.extend(f); assets.extend(a)
        else:
            jm.log_warn(f"Cloud task: {r}")

    jm.log_ok(f"Cloud: {len(findings)} findings, {len(assets)} assets")
    return findings, assets


async def _metadata_endpoint(host, scan_id, jm):
    """Test for cloud metadata endpoints (AWS/GCP/Azure SSRF vector)."""
    jm.log_info("Cloud metadata endpoint test →")
    import aiohttp
    findings = []
    metadata_urls = [
        ("AWS",   f"http://169.254.169.254/latest/meta-data/"),
        ("GCP",   f"http://metadata.google.internal/computeMetadata/v1/"),
        ("Azure", f"http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
    ]
    try:
        async with aiohttp.ClientSession() as sess:
            for provider, url in metadata_urls:
                try:
                    async with sess.get(url, timeout=aiohttp.ClientTimeout(total=4)) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            findings.append(NormalizedFinding(
                                scan_id=scan_id, tool="aarchai-cloud",
                                finding_type="cloud_metadata_exposed",
                                title=f"Cloud Metadata Accessible: {provider} ({url})",
                                severity=Severity.critical,
                                host=host, url=url,
                                description=f"{provider} metadata endpoint is accessible from the scan host.
"
                                            f"This is a SSRF target. If accessible from the target app, "
                                            f"attackers can steal IAM credentials.
Preview:
{body[:500]}",
                                remediation=f"Block access to {url} via firewall/iptables unless explicitly needed. "
                                            f"Enable IMDSv2 on AWS instances.",
                                raw_output=body[:2000],
                                fingerprint_hash=make_hash("cloud_metadata", host, provider),
                            ))
                            jm.log_finding("critical", findings[-1].title)
                except Exception:
                    pass
    except Exception as e:
        jm.log_warn(f"Metadata: {e}")
    return findings, []


async def _s3_enum(company, host, scan_id, jm):
    """Enumerate S3 buckets using common naming patterns."""
    jm.log_info("S3 bucket enumeration →")
    import aiohttp
    findings, assets = [], []

    # Generate bucket name candidates
    candidates = [
        company, f"{company}-backup", f"{company}-dev", f"{company}-prod",
        f"{company}-staging", f"{company}-data", f"{company}-uploads",
        f"{company}-assets", f"{company}-static", f"{company}-media",
        f"{company}-logs", f"{company}-archive", f"{company}-public",
        f"backup-{company}", f"dev-{company}", f"prod-{company}",
        f"{company}.com", f"www.{company}", f"api.{company}",
    ]
    regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    try:
        async with aiohttp.ClientSession() as sess:
            for bucket in candidates:
                for region in regions[:2]:  # Check top 2 regions
                    url = f"https://{bucket}.s3.{region}.amazonaws.com/"
                    try:
                        async with sess.get(url, timeout=aiohttp.ClientTimeout(total=6),
                                            allow_redirects=False) as resp:
                            if resp.status in (200, 403):
                                accessible = resp.status == 200
                                body = await resp.text() if accessible else ""
                                sev = Severity.critical if accessible else Severity.high
                                findings.append(NormalizedFinding(
                                    scan_id=scan_id, tool="aarchai-cloud",
                                    finding_type="s3_bucket_found",
                                    title=f"S3 Bucket: s3://{bucket} ({'PUBLIC READ' if accessible else 'exists, private'})",
                                    severity=sev,
                                    host=host, url=url,
                                    description=f"S3 bucket found: {bucket}
Region: {region}
"
                                                f"Status: {'Publicly accessible — anyone can list/download files' if accessible else 'Bucket exists but access restricted'}
"
                                                + (f"Content preview:
{body[:500]}" if accessible else ""),
                                    remediation="Make S3 buckets private. Use IAM policies and bucket policies to restrict access. Enable S3 Block Public Access.",
                                    raw_output=body[:1000] if accessible else "",
                                    fingerprint_hash=make_hash("s3", bucket, region),
                                ))
                                assets.append({"type": "s3_bucket", "value": f"s3://{bucket}", "source_tool": "aarchai-cloud"})
                                jm.log_finding("critical" if accessible else "high", findings[-1].title)
                                break  # Found in this region, move to next bucket
                    except Exception:
                        pass
    except Exception as e:
        jm.log_warn(f"S3 enum: {e}")
    return findings, assets


async def _azure_enum(company, host, scan_id, jm):
    """Enumerate Azure Blob Storage containers."""
    jm.log_info("Azure blob enumeration →")
    import aiohttp
    findings, assets = [], []
    candidates = [
        company, f"{company}storage", f"{company}backup", f"{company}prod",
        f"{company}dev", f"{company}data", f"{company}assets",
    ]
    try:
        async with aiohttp.ClientSession() as sess:
            for account in candidates:
                url = f"https://{account}.blob.core.windows.net/?comp=list"
                try:
                    async with sess.get(url, timeout=aiohttp.ClientTimeout(total=6),
                                        allow_redirects=False) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            findings.append(NormalizedFinding(
                                scan_id=scan_id, tool="aarchai-cloud",
                                finding_type="azure_blob_exposed",
                                title=f"Azure Blob Storage PUBLICLY ACCESSIBLE: {account}",
                                severity=Severity.critical,
                                host=host, url=url,
                                description=f"Azure Blob account {account} is publicly accessible.
{body[:500]}",
                                remediation="Disable public access on Azure Storage accounts. Use Shared Access Signatures for controlled access.",
                                raw_output=body[:2000],
                                fingerprint_hash=make_hash("azure_blob", account),
                            ))
                            assets.append({"type": "azure_blob", "value": account, "source_tool": "aarchai-cloud"})
                            jm.log_finding("critical", findings[-1].title)
                except Exception:
                    pass
    except Exception as e:
        jm.log_warn(f"Azure blob: {e}")
    return findings, assets


async def _gcp_enum(company, host, scan_id, jm):
    """Enumerate GCP Storage buckets."""
    jm.log_info("GCP bucket enumeration →")
    import aiohttp
    findings, assets = [], []
    candidates = [company, f"{company}-backup", f"{company}-dev", f"{company}-prod",
                  f"{company}-assets", f"{company}-data"]
    try:
        async with aiohttp.ClientSession() as sess:
            for bucket in candidates:
                url = f"https://storage.googleapis.com/{bucket}/"
                try:
                    async with sess.get(url, timeout=aiohttp.ClientTimeout(total=6),
                                        allow_redirects=False) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            findings.append(NormalizedFinding(
                                scan_id=scan_id, tool="aarchai-cloud",
                                finding_type="gcp_bucket_exposed",
                                title=f"GCP Bucket PUBLIC: gs://{bucket}",
                                severity=Severity.critical,
                                host=host, url=url,
                                description=f"GCP Storage bucket {bucket} is publicly accessible.
{body[:500]}",
                                remediation="Remove 'allUsers' from bucket IAM policy. Enable Uniform Bucket-Level Access.",
                                raw_output=body[:2000],
                                fingerprint_hash=make_hash("gcp_bucket", bucket),
                            ))
                            assets.append({"type": "gcp_bucket", "value": f"gs://{bucket}", "source_tool": "aarchai-cloud"})
                            jm.log_finding("critical", findings[-1].title)
                except Exception:
                    pass
    except Exception as e:
        jm.log_warn(f"GCP bucket: {e}")
    return findings, assets


async def _cloud_nuclei(host, scan_id, jm, out_dir):
    """Run cloud-specific nuclei templates."""
    jm.log_info("Nuclei cloud templates →")
    if not tool_available("nuclei"):
        return [], []
    r = await run_async(
        ["nuclei", "-u", f"https://{host}", "-t", "cloud/", "-j",
         "-severity", "medium,high,critical", "-silent"],
        timeout=180
    )
    findings = []
    for line in r.stdout.splitlines():
        try:
            d = json.loads(line)
            findings.append(NormalizedFinding(
                scan_id=scan_id, tool="nuclei-cloud",
                finding_type=d.get("template-id", "cloud_vuln"),
                title=d.get("info", {}).get("name", d.get("template-id", "")),
                severity=getattr(Severity, d.get("info", {}).get("severity", "info").lower(), Severity.info),
                host=host, url=d.get("matched-at", ""),
                description=d.get("info", {}).get("description", ""),
                raw_output=line,
                fingerprint_hash=make_hash("nuclei_cloud", host, d.get("template-id", "")),
            ))
        except Exception:
            pass
    jm.log_ok(f"Nuclei cloud: {len(findings)} findings")
    return findings, []
