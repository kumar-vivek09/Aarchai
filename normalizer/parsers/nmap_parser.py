"""Parse nmap XML output into findings and assets."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from normalizer.schema import NormalizedFinding, Severity
from normalizer.dedup import make_hash


DANGEROUS_PORTS = {
    21: ("FTP", "low"),
    22: ("SSH", "info"),
    23: ("Telnet", "high"),
    25: ("SMTP", "low"),
    53: ("DNS", "info"),
    80: ("HTTP", "info"),
    110: ("POP3", "low"),
    135: ("MS-RPC", "medium"),
    139: ("NetBIOS", "medium"),
    443: ("HTTPS", "info"),
    445: ("SMB", "high"),
    1433: ("MSSQL", "high"),
    1521: ("Oracle DB", "high"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    6379: ("Redis", "high"),
    8080: ("HTTP-Alt", "info"),
    8443: ("HTTPS-Alt", "info"),
    27017: ("MongoDB", "high"),
}


def parse_nmap_xml(xml_path: str, scan_id: int):
    findings = []
    assets   = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception:
        return findings, assets

    for host in root.findall(".//host"):
        addr_el = host.find(".//address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find(".//address[@addrtype='ipv6']")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")

        for port_el in host.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid   = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")
            svc_el   = port_el.find("service")
            service  = svc_el.get("name", "") if svc_el is not None else ""
            product  = svc_el.get("product", "") if svc_el is not None else ""
            version  = svc_el.get("version", "") if svc_el is not None else ""
            banner   = f"{product} {version}".strip()

            assets.append({
                "type": "port", "value": ip, "port": portid,
                "protocol": protocol, "service": service,
                "banner": banner[:500], "source_tool": "nmap"
            })

            # Flag dangerous ports as findings
            sev_info = DANGEROUS_PORTS.get(portid)
            if sev_info:
                svc_label, sev = sev_info
                title = f"Open port {portid}/{protocol} ({svc_label})"
                if banner:
                    title += f" — {banner}"
                findings.append(NormalizedFinding(
                    scan_id=scan_id, tool="nmap",
                    finding_type="open_port",
                    title=title,
                    severity=Severity(sev),
                    host=ip, port=portid,
                    description=f"{ip}:{portid}/{protocol} is open and running {service} {banner}.",
                    raw_output=f"{ip}:{portid} {service} {banner}",
                    fingerprint_hash=make_hash("nmap", ip, str(portid), protocol),
                ))

            # Script output findings
            for script in port_el.findall(".//script"):
                script_id = script.get("id", "")
                output    = script.get("output", "")
                if output and len(output) > 5:
                    findings.append(NormalizedFinding(
                        scan_id=scan_id, tool="nmap",
                        finding_type=f"nmap_script_{script_id}",
                        title=f"NSE {script_id} on {ip}:{portid}",
                        severity=Severity.info,
                        host=ip, port=portid,
                        description=output[:1000],
                        raw_output=output,
                        fingerprint_hash=make_hash("nmap_script", ip, str(portid), script_id),
                    ))

    return findings, assets
