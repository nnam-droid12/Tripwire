"""Ending a remote-access session by terminating the remote-access tool.

Only ever called for a judge-authorised ``hard_stop``. Never touches a tool
whose current session came from a trusted family ID. ``only`` restricts which
executables may be terminated, which tests and demos use to aim at a
stand-in program rather than a real AnyDesk install; ``dry_run`` reports
what would be terminated without doing it.
"""

from __future__ import annotations

from dataclasses import dataclass

import psutil

from agent.watchers import match_remote_tool


@dataclass(frozen=True)
class KillResult:
    tool: str
    exe: str
    pid: int
    outcome: str  # terminated | killed | dry_run | access_denied | gone


def terminate_remote_tools(
    *,
    trusted_tools: set[str] | None = None,
    only: set[str] | None = None,
    extra_tools: dict[str, str] | None = None,
    dry_run: bool = False,
    timeout_s: float = 3.0,
) -> list[KillResult]:
    trusted_tools = trusted_tools or set()
    only_lower = {o.lower() for o in only} if only else None
    targets: list[tuple[psutil.Process, str]] = []
    for proc in psutil.process_iter(["pid", "name"]):
        name = proc.info["name"] or ""
        tool = match_remote_tool(name, extra_tools)
        if not tool or tool in trusted_tools:
            continue
        if only_lower is not None and name.lower() not in only_lower:
            continue
        targets.append((proc, tool))

    results: list[KillResult] = []
    for proc, tool in targets:
        exe, pid = proc.info["name"], proc.info["pid"]
        if dry_run:
            results.append(KillResult(tool, exe, pid, "dry_run"))
            continue
        try:
            proc.terminate()
            try:
                proc.wait(timeout=timeout_s)
                results.append(KillResult(tool, exe, pid, "terminated"))
            except psutil.TimeoutExpired:
                proc.kill()
                results.append(KillResult(tool, exe, pid, "killed"))
        except psutil.NoSuchProcess:
            results.append(KillResult(tool, exe, pid, "gone"))
        except psutil.AccessDenied:
            # e.g. the AnyDesk *service* when Tripwire is not elevated; the user
            # session process is usually enough to drop the remote connection
            results.append(KillResult(tool, exe, pid, "access_denied"))
    return results
