"""Parse sslscan XML output."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash

WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "ADH", "aNULL", "IDEA"
}
WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}


def parse_sslscan(xml_path: str, host: str, scan_id: int):
    findings = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return findings

    for ssltest in root.findall(".//ssltest"):
        target = ssltest.get("host", host)
        port   = int(ssltest.get("port", 443))

        # Weak protocols
        for proto in ssltest.findall(".//protocol"):
            name    = proto.get("type", "") + proto.get("version", "")
            enabled = proto.get("enabled", "0")
            if enabled == "1" and name in WEAK_PROTOCOLS:
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="sslscan",
                    finding_type="weak_ssl_protocol",
                    title=f"Weak protocol enabled: {name}",
                    severity=Severity.high,
                    host=target, port=port,
                    description=f"The server supports {name} which is considered insecure.",
                    remediation=f"Disable {name} on the server and enforce TLS 1.2+.",
                    raw_output=f"protocol:{name} enabled",
                    fingerprint_hash=make_hash("sslscan_proto", target, str(port), name),
                ))

        # Weak ciphers
        for cipher in ssltest.findall(".//cipher"):
            if cipher.get("status") != "accepted":
                continue
            cipher_name = cipher.get("cipher", "")
            for weak in WEAK_CIPHERS:
                if weak in cipher_name.upper():
                    findings.append(NormalizedFinding(
                        scan_id=scan_id, tool="sslscan",
                        finding_type="weak_cipher",
                        title=f"Weak cipher accepted: {cipher_name}",
                        severity=Severity.medium,
                        host=target, port=port,
                        description=f"Server accepts weak cipher suite: {cipher_name}",
                        remediation="Remove weak cipher suites from server SSL/TLS config.",
                        raw_output=cipher_name,
                        fingerprint_hash=make_hash("sslscan_cipher", target, str(port), cipher_name),
                    ))
                    break

        # Self-signed cert
        cert = ssltest.find(".//certificate")
        if cert is not None:
            self_signed = cert.find(".//self-signed")
            if self_signed is not None and self_signed.text == "true":
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="sslscan",
                    finding_type="self_signed_cert",
                    title="Self-signed SSL certificate",
                    severity=Severity.medium,
                    host=target, port=port,
                    description="The server is using a self-signed certificate which will trigger browser warnings.",
                    remediation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
                    raw_output="self-signed: true",
                    fingerprint_hash=make_hash("sslscan_selfsigned", target, str(port)),
                ))

    return findings
