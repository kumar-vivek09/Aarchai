"""Scope management — include/exclude patterns for legal compliance."""
from __future__ import annotations
import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
import json


@dataclass
class ScopeConfig:
    includes: list[str] = field(default_factory=list)   # e.g. ["*.example.com", "10.0.0.0/8"]
    excludes: list[str] = field(default_factory=list)   # e.g. ["internal.example.com"]
    notes:    str       = ""

    def is_in_scope(self, value: str) -> bool:
        """Return True if value is in scope (not excluded, matches includes)."""
        v = value.lower().strip()

        # Check excludes first
        for ex in self.excludes:
            ex = ex.lower()
            if fnmatch.fnmatch(v, ex):
                return False
            if _ip_in_cidr(v, ex):
                return False

        # If no includes defined → everything not excluded is in scope
        if not self.includes:
            return True

        for inc in self.includes:
            inc = inc.lower()
            if fnmatch.fnmatch(v, inc):
                return True
            if _ip_in_cidr(v, inc):
                return True

        return False

    def filter_assets(self, assets: list[dict]) -> list[dict]:
        """Filter a list of asset dicts to only in-scope ones."""
        return [a for a in assets if self.is_in_scope(a.get("value", ""))]

    def to_dict(self) -> dict:
        return {"includes": self.includes, "excludes": self.excludes, "notes": self.notes}

    @classmethod
    def from_dict(cls, d: dict) -> "ScopeConfig":
        return cls(
            includes=d.get("includes", []),
            excludes=d.get("excludes", []),
            notes=d.get("notes", ""),
        )

    @classmethod
    def from_file(cls, path: str) -> "ScopeConfig":
        return cls.from_dict(json.loads(Path(path).read_text()))

    def save(self, path: str):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))


def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in ipaddress.ip_network(cidr_str, strict=False)
    except ValueError:
        return False


# ── CLI helpers ──────────────────────────────────────────────────────────
def print_scope(scope: ScopeConfig, console):
    console.print(f"[cyan]Scope:[/]")
    console.print(f"  Includes: {scope.includes or ['(all)']}")
    console.print(f"  Excludes: {scope.excludes or ['(none)']}")
