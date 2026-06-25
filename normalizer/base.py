"""Base parser interface."""
from __future__ import annotations
from abc import ABC, abstractmethod
from normalizer.schema import NormalizedFinding


class BaseParser(ABC):
    tool_name: str = "unknown"

    @abstractmethod
    def parse(self, raw: str, host: str, scan_id: int) -> list[NormalizedFinding]:
        ...
