"""Bounded external process execution with cancellation-safe tree cleanup."""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

from app.core.config import settings

logger = logging.getLogger("core.subprocess_runner")

_subprocess_semaphore: Optional[asyncio.Semaphore] = None


@dataclass(frozen=True)
class BoundedProcessResult:
    command: tuple[str, ...]
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    stdout_truncated: bool
    stderr_truncated: bool
    duration_seconds: float
    pid: Optional[int]


def _get_semaphore() -> asyncio.Semaphore:
    global _subprocess_semaphore
    if _subprocess_semaphore is None:
        _subprocess_semaphore = asyncio.Semaphore(max(1, settings.max_subprocesses))
    return _subprocess_semaphore


async def _read_limited(
    stream: Optional[asyncio.StreamReader],
    max_bytes: int,
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    retained = bytearray()
    total = 0
    while True:
        chunk = await stream.read(64 * 1024)
        if not chunk:
            break
        total += len(chunk)
        remaining = max_bytes - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained), total > max_bytes


def _terminate_children_sync(pid: int, force: bool = False) -> None:
    try:
        import psutil

        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in reversed(children):
            try:
                child.kill() if force else child.terminate()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        psutil.wait_procs(children, timeout=1.5)
    except Exception:
        pass


async def _terminate_process_tree(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is not None:
        return
    await asyncio.to_thread(_terminate_children_sync, proc.pid, False)
    try:
        proc.terminate()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
        return
    except asyncio.TimeoutError:
        pass

    await asyncio.to_thread(_terminate_children_sync, proc.pid, True)
    try:
        proc.kill()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        logger.error("External process %s did not exit after forced termination.", proc.pid)


async def run_bounded_subprocess(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    max_output_bytes: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> BoundedProcessResult:
    """Execute an argv-only command with bounded concurrency, output, and lifetime."""
    argv = tuple(str(part) for part in command if str(part))
    if not argv:
        raise ValueError("External process command cannot be empty.")
    timeout = max(1.0, float(timeout_seconds))
    output_limit = max(64 * 1024, int(max_output_bytes or settings.subprocess_max_output_bytes))
    started = time.monotonic()
    proc: Optional[asyncio.subprocess.Process] = None

    spawn_kwargs: dict = {}
    if os.name == "nt":
        spawn_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        spawn_kwargs["start_new_session"] = True

    async with _get_semaphore():
        try:
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=dict(env) if env is not None else None,
                **spawn_kwargs,
            )
            stdout_task = asyncio.create_task(_read_limited(proc.stdout, output_limit))
            stderr_task = asyncio.create_task(_read_limited(proc.stderr, output_limit))
            timed_out = False
            try:
                await asyncio.wait_for(proc.wait(), timeout=timeout)
            except asyncio.TimeoutError:
                timed_out = True
                await _terminate_process_tree(proc)
            except asyncio.CancelledError:
                await _terminate_process_tree(proc)
                raise

            stdout_result, stderr_result = await asyncio.gather(stdout_task, stderr_task)
            stdout, stdout_truncated = stdout_result
            stderr, stderr_truncated = stderr_result
            return BoundedProcessResult(
                command=argv,
                returncode=proc.returncode if proc.returncode is not None else -1,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                duration_seconds=time.monotonic() - started,
                pid=proc.pid,
            )
        except asyncio.CancelledError:
            if proc is not None:
                await _terminate_process_tree(proc)
            raise


def reset_subprocess_semaphore_for_tests() -> None:
    """Reset the loop-bound semaphore between isolated async test loops."""
    global _subprocess_semaphore
    _subprocess_semaphore = None
