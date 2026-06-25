"""Auth profile loader — cookies/headers for authenticated scans."""
from __future__ import annotations
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


AUTH_PROFILES_DIR = Path(__file__).parent.parent / "auth_profiles"


@dataclass
class AuthProfile:
    cookies:     str              = ""   # "session=abc; token=xyz"
    headers:     dict[str, str]   = field(default_factory=dict)
    bearer_token: Optional[str]  = None
    basic_user:  Optional[str]   = None
    basic_pass:  Optional[str]   = None

    def httpx_flags(self) -> list[str]:
        flags = []
        if self.cookies:
            flags += ["-H", f"Cookie: {self.cookies}"]
        for k, v in self.headers.items():
            flags += ["-H", f"{k}: {v}"]
        if self.bearer_token:
            flags += ["-H", f"Authorization: Bearer {self.bearer_token}"]
        return flags

    def nuclei_flags(self) -> list[str]:
        return self.httpx_flags()  # nuclei uses same -H format

    def sqlmap_flags(self) -> list[str]:
        flags = []
        if self.cookies:
            flags += ["--cookie", self.cookies]
        for k, v in self.headers.items():
            flags += ["--headers", f"{k}: {v}"]
        return flags

    def requests_kwargs(self) -> dict:
        kw: dict = {}
        if self.cookies:
            kw["cookies"] = dict(c.split("=", 1) for c in self.cookies.split(";") if "=" in c)
        if self.headers:
            kw["headers"] = self.headers
        if self.bearer_token:
            kw.setdefault("headers", {})["Authorization"] = f"Bearer {self.bearer_token}"
        if self.basic_user:
            kw["auth"] = (self.basic_user, self.basic_pass or "")
        return kw


def load_auth(profile_name: Optional[str]) -> Optional[AuthProfile]:
    if not profile_name:
        return None
    path = AUTH_PROFILES_DIR / f"{profile_name}.json"
    if not path.exists():
        print(f"[auth] Profile not found: {path}")
        return None
    data = json.loads(path.read_text())
    return AuthProfile(**data)


def save_auth_template():
    AUTH_PROFILES_DIR.mkdir(exist_ok=True)
    template = {
        "cookies":      "session=YOUR_SESSION; csrf=YOUR_CSRF",
        "headers":      {"X-Custom-Header": "value"},
        "bearer_token": None,
        "basic_user":   None,
        "basic_pass":   None,
    }
    p = AUTH_PROFILES_DIR / "example.json"
    if not p.exists():
        p.write_text(json.dumps(template, indent=2))
        print(f"[auth] Template written to {p}")
