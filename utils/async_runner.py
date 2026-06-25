"""Async subprocess runner — replaces sync stages/base.py for speed."""
from __future__ import annotations
import asyncio
import shutil
from dataclasses import dataclass, field
from typing import Optional
from config import TOOL_TIMEOUT


@dataclass
class ToolResult:
    tool:       str
    stdout:     str
    stderr:     str
    returncode: int
    timed_out:  bool = False

    @property
    def success(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


async def run_async(
    cmd: list[str],
    timeout: Optional[int] = None,
    input_data: Optional[str] = None,
    cwd: Optional[str] = None,
) -> ToolResult:
    """Run a tool asynchronously. Returns ToolResult."""
    tool_name = cmd[0]
    timeout   = timeout or TOOL_TIMEOUT

    if not tool_available(tool_name):
        return ToolResult(tool_name, "", f"{tool_name} not found in PATH", 127)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            cwd=cwd,
        )
        stdin_bytes = input_data.encode() if input_data else None
        try:
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=stdin_bytes), timeout=timeout
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            return ToolResult(tool_name, "", f"timed out after {timeout}s", 124, timed_out=True)

        return ToolResult(
            tool_name,
            stdout_b.decode(errors="replace"),
            stderr_b.decode(errors="replace"),
            proc.returncode or 0,
        )
    except FileNotFoundError:
        return ToolResult(tool_name, "", f"{tool_name} not found", 127)
    except Exception as exc:
        return ToolResult(tool_name, "", str(exc), 1)


async def run_parallel(*coros) -> list[ToolResult]:
    """Run multiple async tool calls simultaneously."""
    return list(await asyncio.gather(*coros, return_exceptions=False))
