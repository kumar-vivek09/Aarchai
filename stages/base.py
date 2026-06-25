"""Base tool runner — wraps subprocess calls with timeout and logging."""
from __future__ import annotations
import subprocess
import shlex
import shutil
from typing import Optional
from config import TOOL_TIMEOUT


class ToolResult:
    def __init__(self, tool: str, stdout: str, stderr: str, returncode: int, timed_out: bool = False):
        self.tool       = tool
        self.stdout     = stdout
        self.stderr     = stderr
        self.returncode = returncode
        self.timed_out  = timed_out
        self.success    = returncode == 0 and not timed_out

    def __repr__(self):
        status = "ok" if self.success else f"rc={self.returncode}"
        return f"<ToolResult tool={self.tool} {status} len={len(self.stdout)}>"


def tool_available(name: str) -> bool:
    """Return True if the binary is on PATH."""
    return shutil.which(name) is not None


def run_tool(
    cmd: list[str],
    timeout: Optional[int] = None,
    input_data: Optional[str] = None,
    cwd: Optional[str] = None,
) -> ToolResult:
    """Run an external tool via subprocess and return a ToolResult."""
    tool_name = cmd[0]
    timeout   = timeout or TOOL_TIMEOUT

    if not tool_available(tool_name):
        return ToolResult(tool_name, "", f"{tool_name} not found in PATH", 127)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data,
            cwd=cwd,
        )
        return ToolResult(tool_name, proc.stdout, proc.stderr, proc.returncode)
    except subprocess.TimeoutExpired:
        return ToolResult(tool_name, "", f"timed out after {timeout}s", 124, timed_out=True)
    except FileNotFoundError:
        return ToolResult(tool_name, "", f"{tool_name} not found", 127)
    except Exception as exc:
        return ToolResult(tool_name, "", str(exc), 1)
