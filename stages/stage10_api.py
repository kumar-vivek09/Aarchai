"""Stage 10 — API Security: OpenAPI/Swagger, GraphQL, JWT, arjun, kiterunner."""
from __future__ import annotations
import asyncio
import json
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash
from utils.async_runner import run_async, tool_available


def run(target, scan_id, session, jm, fast=False, out_dir=None, auth=None, scope=None):
    return asyncio.run(_run_async(target, scan_id, session, jm, fast, out_dir, auth))


async def _run_async(target, scan_id, session, jm, fast, out_dir, auth):
    host = target.host
    jm.log_stage("stage10_api", f"API security testing: {host}")

    # Find all live URLs to test
    from core.db import Asset
    from core.db import get_session
    db_session = get_session()
    urls = [a.value for a in db_session.query(Asset).filter(
        Asset.scan_id == scan_id, Asset.asset_type == "url"
    ).all()]
    db_session.close()
    if not urls:
        urls = [f"https://{host}", f"http://{host}"]

    base_url = urls[0] if urls else f"https://{host}"

    tasks = [
        asyncio.create_task(_swagger_discover(host, base_url, scan_id, jm, auth)),
        asyncio.create_task(_graphql_test(host, base_url, scan_id, jm, auth)),
        asyncio.create_task(_jwt_test(host, base_url, scan_id, jm, auth)),
        asyncio.create_task(_cors_test(host, base_url, scan_id, jm, auth)),
    ]
    if not fast:
        tasks += [
            asyncio.create_task(_arjun_scan(host, base_url, scan_id, jm, auth)),
            asyncio.create_task(_kiterunner_scan(host, base_url, scan_id, jm, auth)),
        ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    findings, assets = [], []
    for r in results:
        if not isinstance(r, Exception):
            f, a = r
            findings.extend(f); assets.extend(a)
        else:
            jm.log_warn(f"API task: {r}")

    jm.log_ok(f"API: {len(findings)} findings")
    return findings, assets


async def _swagger_discover(host, base_url, scan_id, jm, auth):
    """Discover OpenAPI/Swagger specs and test exposed endpoints."""
    jm.log_info("Swagger/OpenAPI discovery →")
    import aiohttp
    findings = []
    swagger_paths = [
        "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
        "/api/swagger.json", "/api/openapi.json", "/api/v1/swagger.json",
        "/api/v2/swagger.json", "/api/v3/swagger.json", "/api-docs",
        "/api-docs.json", "/swagger-ui.html", "/swagger-ui",
        "/docs", "/redoc", "/api/docs", "/v1/api-docs",
        "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
        "/.well-known/openapi.json",
    ]
    headers = {}
    if auth and hasattr(auth, "headers"):
        headers = auth.headers or {}

    try:
        async with aiohttp.ClientSession() as sess:
            for path in swagger_paths:
                url = base_url.rstrip("/") + path
                try:
                    async with sess.get(url, headers=headers,
                                        timeout=aiohttp.ClientTimeout(total=8),
                                        ssl=False) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            # Check if it's actually a spec
                            if any(k in body.lower() for k in ("openapi", "swagger", "paths", "info")):
                                # Parse and count endpoints
                                endpoint_count = body.count('"get"') + body.count('"post"') +                                                  body.count('"put"') + body.count('"delete"')
                                findings.append(NormalizedFinding(
                                    scan_id=scan_id, tool="aarchai-api",
                                    finding_type="api_spec_exposed",
                                    title=f"API Specification Exposed: {path} (~{endpoint_count} endpoints)",
                                    severity=Severity.medium,
                                    host=host, url=url,
                                    description=f"OpenAPI/Swagger specification found at {url}.
"
                                                f"Approximately {endpoint_count} API endpoints documented.
"
                                                f"This gives attackers a complete map of your API surface.",
                                    remediation="Restrict access to API documentation to authenticated users only. "
                                                "Never expose internal API specs publicly.",
                                    raw_output=body[:3000],
                                    fingerprint_hash=make_hash("swagger", host, path),
                                ))
                                jm.log_finding("medium", findings[-1].title)
                except Exception:
                    pass
    except Exception as e:
        jm.log_warn(f"Swagger: {e}")
    return findings, []


async def _graphql_test(host, base_url, scan_id, jm, auth):
    """Test GraphQL endpoint for introspection and common vulnerabilities."""
    jm.log_info("GraphQL test →")
    import aiohttp
    findings = []
    graphql_paths = ["/graphql", "/api/graphql", "/gql", "/api/gql", "/query",
                     "/v1/graphql", "/graphiql", "/playground"]
    headers = {"Content-Type": "application/json"}
    if auth and hasattr(auth, "headers"):
        headers.update(auth.headers or {})

    introspection_query = {"query": "{ __schema { types { name } } }"}
    batching_query = [
        {"query": "{ __typename }"},
        {"query": "{ __schema { queryType { name } } }"},
    ]

    try:
        async with aiohttp.ClientSession() as sess:
            for path in graphql_paths:
                url = base_url.rstrip("/") + path
                try:
                    # Test introspection
                    async with sess.post(url, json=introspection_query, headers=headers,
                                         timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                        if resp.status in (200, 400):
                            body = await resp.text()
                            if "__schema" in body or "types" in body:
                                findings.append(NormalizedFinding(
                                    scan_id=scan_id, tool="aarchai-api",
                                    finding_type="graphql_introspection",
                                    title=f"GraphQL Introspection Enabled: {path}",
                                    severity=Severity.medium,
                                    host=host, url=url,
                                    description="GraphQL introspection is enabled, exposing the full schema.
"
                                                "Attackers can map all types, queries, mutations, and fields.",
                                    remediation="Disable introspection in production. Use query allowlisting.",
                                    raw_output=body[:1000],
                                    fingerprint_hash=make_hash("graphql_introspection", host, path),
                                ))
                                jm.log_finding("medium", findings[-1].title)

                                # Test query batching (DoS amplification)
                                async with sess.post(url, json=batching_query, headers=headers,
                                                     timeout=aiohttp.ClientTimeout(total=10), ssl=False) as batch_resp:
                                    if batch_resp.status == 200:
                                        batch_body = await batch_resp.text()
                                        if isinstance(json.loads(batch_body), list):
                                            findings.append(NormalizedFinding(
                                                scan_id=scan_id, tool="aarchai-api",
                                                finding_type="graphql_batching",
                                                title=f"GraphQL Query Batching Enabled: {path}",
                                                severity=Severity.medium,
                                                host=host, url=url,
                                                description="GraphQL query batching is enabled. "
                                                            "Attackers can send thousands of queries in one request (DoS/brute-force amplification).",
                                                remediation="Limit batch query size. Implement query complexity limits and rate limiting.",
                                                raw_output=batch_body[:500],
                                                fingerprint_hash=make_hash("graphql_batching", host, path),
                                            ))
                except Exception:
                    pass
    except Exception as e:
        jm.log_warn(f"GraphQL: {e}")
    return findings, []


async def _jwt_test(host, base_url, scan_id, jm, auth):
    """Test for JWT vulnerabilities: alg:none, weak keys."""
    jm.log_info("JWT vulnerability test →")
    if not tool_available("jwt_tool"):
        return [], []
    findings = []
    # Get a JWT token if available via auth profile
    if auth and hasattr(auth, "headers"):
        auth_header = auth.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            r = await run_async(
                ["jwt_tool", token, "-M", "at"],  # all tests
                timeout=60
            )
            if "VULNERABLE" in r.stdout:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="jwt_tool",
                    finding_type="jwt_vulnerability",
                    title=f"JWT Vulnerability Detected on {host}",
                    severity=Severity.critical,
                    host=host, url=base_url,
                    description=r.stdout[:2000],
                    remediation="Use strong HMAC keys (256-bit minimum). Never accept algorithm:none. Validate JWT expiry.",
                    raw_output=r.stdout[:3000],
                    fingerprint_hash=make_hash("jwt_vuln", host),
                ))
                jm.log_finding("critical", findings[-1].title)
    return findings, []


async def _cors_test(host, base_url, scan_id, jm, auth):
    """Test for CORS misconfiguration."""
    jm.log_info("CORS test →")
    import aiohttp
    findings = []
    origins_to_test = [
        f"https://evil.com",
        f"https://attacker.com",
        f"null",
        f"https://{host}.evil.com",
    ]
    try:
        async with aiohttp.ClientSession() as sess:
            for origin in origins_to_test:
                try:
                    async with sess.get(base_url, headers={"Origin": origin},
                                        timeout=aiohttp.ClientTimeout(total=8), ssl=False) as resp:
                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                        if acao == origin or acao == "*":
                            sev = Severity.high if acac.lower() == "true" else Severity.medium
                            findings.append(NormalizedFinding(
                                scan_id=scan_id, tool="aarchai-api",
                                finding_type="cors_misconfiguration",
                                title=f"CORS Misconfiguration: {acao} (credentials: {acac})",
                                severity=sev,
                                host=host, url=base_url,
                                description=f"Origin '{origin}' is reflected in ACAO header: '{acao}'.
"
                                            f"Credentials allowed: {acac}
"
                                            f"Attackers can perform cross-origin requests with user credentials.",
                                remediation="Use strict CORS allowlists. Never use wildcard '*' with credentials. Validate Origin headers server-side.",
                                raw_output=f"ACAO: {acao}, ACAC: {acac}",
                                fingerprint_hash=make_hash("cors", host, origin),
                            ))
                            jm.log_finding("high" if acac else "medium", findings[-1].title)
                            break
                except Exception:
                    pass
    except Exception as e:
        jm.log_warn(f"CORS: {e}")
    return findings, []


async def _arjun_scan(host, base_url, scan_id, jm, auth):
    """Hidden HTTP parameter discovery using arjun."""
    jm.log_info("arjun parameter discovery →")
    if not tool_available("arjun"):
        jm.log_warn("arjun not installed: pip3 install arjun")
        return [], []
    findings = []
    r = await run_async(
        ["arjun", "-u", base_url, "--json", "/tmp/arjun_out.json", "-q"],
        timeout=180
    )
    import pathlib
    arjun_out = pathlib.Path("/tmp/arjun_out.json")
    if arjun_out.exists():
        try:
            data = json.loads(arjun_out.read_text())
            for url_result in data:
                params = url_result.get("params", [])
                if params:
                    findings.append(NormalizedFinding(
                        scan_id=scan_id, tool="arjun",
                        finding_type="hidden_parameters",
                        title=f"Hidden API parameters discovered: {', '.join(params[:5])}",
                        severity=Severity.medium,
                        host=host, url=url_result.get("url", base_url),
                        description=f"arjun discovered {len(params)} hidden parameter(s):
{', '.join(params)}",
                        remediation="Review hidden parameters for injection vulnerabilities. Remove undocumented parameters.",
                        raw_output=str(params),
                        fingerprint_hash=make_hash("arjun", host, str(sorted(params)[:3])),
                    ))
                    jm.log_ok(f"arjun: {len(params)} parameters found")
        except Exception:
            pass
    return findings, []


async def _kiterunner_scan(host, base_url, scan_id, jm, auth):
    """API route discovery using kiterunner."""
    jm.log_info("kiterunner API route discovery →")
    if not tool_available("kr"):
        jm.log_warn("kiterunner not installed: see https://github.com/assetnote/kiterunner")
        return [], []
    r = await run_async(
        ["kr", "scan", base_url, "-w", "routes-small.kite", "--json", "/tmp/kr_out.json"],
        timeout=240
    )
    findings = []
    import pathlib
    kr_out = pathlib.Path("/tmp/kr_out.json")
    if kr_out.exists():
        try:
            data = json.loads(kr_out.read_text())
            routes = len(data)
            if routes > 0:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="kiterunner",
                    finding_type="api_routes_discovered",
                    title=f"kiterunner: {routes} hidden API route(s) discovered",
                    severity=Severity.medium,
                    host=host, url=base_url,
                    description=f"kiterunner discovered {routes} undocumented API endpoints.
"
                                f"Routes: {[d.get('path') for d in data[:10]]}",
                    remediation="Audit discovered routes. Remove or protect undocumented endpoints.",
                    raw_output=str(data[:20]),
                    fingerprint_hash=make_hash("kiterunner", host, str(routes)),
                ))
                jm.log_ok(f"kiterunner: {routes} routes found")
        except Exception:
            pass
    return findings, []
