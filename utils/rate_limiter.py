"""Rate limiting + exponential-backoff retry for free-tier APIs."""
from __future__ import annotations
import time
import functools
import threading
from typing import Callable, Any
from tenacity import (
    retry, stop_after_attempt, wait_exponential,
    retry_if_exception_type, before_sleep_log
)
import logging
import requests

log = logging.getLogger("aarchai.rate_limiter")


class RateLimiter:
    """Token-bucket rate limiter (thread-safe)."""
    def __init__(self, calls_per_window: int, window_seconds: float):
        self.calls_per_window = calls_per_window
        self.window_seconds   = window_seconds
        self._lock            = threading.Lock()
        self._calls: list[float] = []

    def wait(self):
        with self._lock:
            now = time.monotonic()
            # Remove calls outside the window
            self._calls = [t for t in self._calls if now - t < self.window_seconds]
            if len(self._calls) >= self.calls_per_window:
                sleep_for = self.window_seconds - (now - self._calls[0])
                if sleep_for > 0:
                    time.sleep(sleep_for)
            self._calls.append(time.monotonic())


# Shared rate limiters for each API (free tier)
_nvd_limiter  = RateLimiter(calls_per_window=5,  window_seconds=30)
_vt_limiter   = RateLimiter(calls_per_window=4,  window_seconds=60)
_shodan_limiter = RateLimiter(calls_per_window=1, window_seconds=1)


class Http429Error(Exception):
    pass


def _raise_on_429(response: requests.Response):
    if response.status_code == 429:
        raise Http429Error(f"Rate limited: {response.url}")
    response.raise_for_status()


def nvd_get(url: str, **kwargs) -> dict:
    """Rate-limited + retrying GET for NVD API."""
    @retry(
        stop=stop_after_attempt(4),
        wait=wait_exponential(multiplier=2, min=6, max=60),
        retry=retry_if_exception_type((Http429Error, requests.ConnectionError)),
        reraise=True,
    )
    def _call():
        _nvd_limiter.wait()
        resp = requests.get(url, timeout=20, **kwargs)
        _raise_on_429(resp)
        return resp.json()
    return _call()


def virustotal_get(url: str, headers: dict, **kwargs) -> dict:
    """Rate-limited + retrying GET for VirusTotal API."""
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=15, max=120),
        retry=retry_if_exception_type((Http429Error, requests.ConnectionError)),
        reraise=True,
    )
    def _call():
        _vt_limiter.wait()
        resp = requests.get(url, headers=headers, timeout=15, **kwargs)
        _raise_on_429(resp)
        return resp.json()
    return _call()


def shodan_search(api, query: str) -> dict:
    """Rate-limited Shodan search."""
    _shodan_limiter.wait()
    return api.search(query)
