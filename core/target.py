"""Parse raw target string into a typed ParsedTarget."""
from __future__ import annotations
import re
import ipaddress
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ParsedTarget:
    value: str          # cleaned value (domain/IP/CIDR)
    type:  str          # domain | ip | cidr | url | host_port
    host:  str          # hostname or IP without port
    port:  int | None   # explicit port if given


def parse_target(raw: str) -> ParsedTarget:
    raw = raw.strip()

    # URL
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        host = parsed.hostname or ""
        port = parsed.port
        return ParsedTarget(value=raw, type="url", host=host, port=port)

    # CIDR
    try:
        net = ipaddress.ip_network(raw, strict=False)
        return ParsedTarget(value=str(net), type="cidr", host=str(net.network_address), port=None)
    except ValueError:
        pass

    # host:port
    if re.match(r"^.+:\d+$", raw):
        host, port_str = raw.rsplit(":", 1)
        try:
            port = int(port_str)
            host = host.strip("[]")   # handle [::1]:port
            try:
                ipaddress.ip_address(host)
                return ParsedTarget(value=raw, type="host_port", host=host, port=port)
            except ValueError:
                return ParsedTarget(value=raw, type="host_port", host=host, port=port)
        except ValueError:
            pass

    # Plain IP
    try:
        ipaddress.ip_address(raw)
        return ParsedTarget(value=raw, type="ip", host=raw, port=None)
    except ValueError:
        pass

    # Domain (default)
    return ParsedTarget(value=raw, type="domain", host=raw, port=None)
