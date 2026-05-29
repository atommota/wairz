"""Compute dispatch seam for heavy Ghidra jobs.

Decouples *where* a Ghidra worker runs from the MCP tools that kick it off.
Both ``start_binary_analysis`` and ``start_function_decompile`` hand off to a
``ComputeDispatcher`` instead of spawning a subprocess directly.

- ``local`` (default): spawn a detached worker subprocess on the backend host.
  This is the standard docker-compose behavior, byte-for-byte unchanged.
- ``aws_batch``: submit the same worker module as an AWS Batch job. Wired up in
  enterprise/PLAN.md Phase 2; raises NotImplementedError until then.

The async job protocol is unaffected — the worker still writes its result to
the ``ghidra_analysis_run`` / ``analysis_cache`` rows that the status tools
poll. Only the launch mechanism varies by backend.
"""

from __future__ import annotations

import subprocess
import sys
import uuid
from dataclasses import dataclass

from app.config import get_settings


@dataclass
class JobHandle:
    """Reference to a dispatched analysis job.

    ``pid`` is the local OS pid for the ``local`` backend (used by the status
    tools' liveness check). For remote backends there is no host pid: ``pid``
    is None and ``ref`` carries the provider job id (e.g. a Batch job id).
    """

    pid: int | None = None
    ref: str | None = None


class ComputeDispatcher:
    """Launches detached Ghidra workers. One concrete impl per compute backend."""

    def dispatch_analysis(
        self, firmware_id: uuid.UUID, binary_path: str, sha256: str,
    ) -> JobHandle:
        raise NotImplementedError

    def dispatch_decompile(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        sha256: str,
        function_name: str,
    ) -> JobHandle:
        raise NotImplementedError


class LocalDispatcher(ComputeDispatcher):
    """Spawn detached worker subprocesses on the backend host (default).

    ``start_new_session=True`` makes the worker survive the wairz-mcp process
    dying (e.g. an MCP client reconnect mid-analysis); stdio is detached so the
    parent keeps no pipes open.
    """

    def _spawn(self, module_args: list[str]) -> JobHandle:
        proc = subprocess.Popen(
            [sys.executable, "-m", *module_args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
        return JobHandle(pid=proc.pid)

    def dispatch_analysis(
        self, firmware_id: uuid.UUID, binary_path: str, sha256: str,
    ) -> JobHandle:
        return self._spawn([
            "app.workers.run_ghidra_analysis",
            "--firmware-id", str(firmware_id),
            "--binary-path", binary_path,
            "--sha256", sha256,
        ])

    def dispatch_decompile(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        sha256: str,
        function_name: str,
    ) -> JobHandle:
        return self._spawn([
            "app.workers.run_function_decompile",
            "--firmware-id", str(firmware_id),
            "--binary-path", binary_path,
            "--sha256", sha256,
            "--function-name", function_name,
        ])


def get_dispatcher() -> ComputeDispatcher:
    """Return the dispatcher for the configured ``compute_backend``."""
    backend = get_settings().compute_backend
    if backend == "local":
        return LocalDispatcher()
    if backend == "aws_batch":
        raise NotImplementedError(
            "compute_backend='aws_batch' dispatch is not implemented yet — "
            "it lands in enterprise Phase 2 (see enterprise/PLAN.md, change C2)."
        )
    raise ValueError(f"unknown compute_backend: {backend!r}")
