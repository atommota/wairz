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

import hashlib
import logging
import subprocess
import sys
import uuid
from dataclasses import dataclass

from app.config import get_settings

logger = logging.getLogger(__name__)


def _job_name(prefix: str, *parts: str) -> str:
    """Build a Batch-legal job name (^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$)."""
    digest = hashlib.sha1(":".join(parts).encode("utf-8")).hexdigest()[:24]
    return f"{prefix}-{digest}"


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


class BatchDispatcher(ComputeDispatcher):
    """Submit the Ghidra worker as an AWS Batch job (enterprise cloud mode).

    Both workers run the SAME image (it bundles Ghidra + the worker code); the
    per-binary command is supplied as a container override, and the EFS mounts /
    env / secrets come from the Batch job definition (Terraform). The job writes
    its result to the EFS project store + Aurora cache, exactly like the local
    worker, so the status/poll protocol is unchanged.
    """

    def _client(self):
        import boto3  # lazy: only the cloud path needs boto3

        region = get_settings().aws_region or None
        return boto3.client("batch", region_name=region)

    def _submit(self, job_name: str, command: list[str]) -> JobHandle:
        settings = get_settings()
        resp = self._client().submit_job(
            jobName=job_name,
            jobQueue=settings.batch_job_queue,
            jobDefinition=settings.batch_job_definition,
            containerOverrides={"command": command},
        )
        job_id = resp["jobId"]
        logger.info("Submitted Batch job %s (%s)", job_id, job_name)
        return JobHandle(ref=job_id)

    def dispatch_analysis(
        self, firmware_id: uuid.UUID, binary_path: str, sha256: str,
    ) -> JobHandle:
        return self._submit(
            _job_name("wairz-an", sha256),
            [
                "python", "-m", "app.workers.run_ghidra_analysis",
                "--firmware-id", str(firmware_id),
                "--binary-path", binary_path,
                "--sha256", sha256,
            ],
        )

    def dispatch_decompile(
        self,
        firmware_id: uuid.UUID,
        binary_path: str,
        sha256: str,
        function_name: str,
    ) -> JobHandle:
        return self._submit(
            _job_name("wairz-dec", sha256, function_name),
            [
                "python", "-m", "app.workers.run_function_decompile",
                "--firmware-id", str(firmware_id),
                "--binary-path", binary_path,
                "--sha256", sha256,
                "--function-name", function_name,
            ],
        )


# Normalized job states the status tools understand.
def describe_batch_job_state(job_ref: str | None) -> str:
    """Map an AWS Batch job's status to queued|starting|running|failed|
    succeeded|unknown. Best-effort: any error → 'unknown' (the cache row, not
    this lookup, is the source of truth for completion)."""
    if not job_ref:
        return "unknown"
    try:
        import boto3  # lazy

        region = get_settings().aws_region or None
        resp = boto3.client("batch", region_name=region).describe_jobs(
            jobs=[job_ref],
        )
        jobs = resp.get("jobs", [])
        if not jobs:
            return "unknown"
        status = jobs[0].get("status", "")
        return {
            "SUBMITTED": "queued",
            "PENDING": "queued",
            "RUNNABLE": "queued",
            "STARTING": "starting",
            "RUNNING": "running",
            "SUCCEEDED": "succeeded",
            "FAILED": "failed",
        }.get(status, "unknown")
    except Exception:
        logger.warning("Batch describe_jobs failed for %s", job_ref, exc_info=True)
        return "unknown"


def get_dispatcher() -> ComputeDispatcher:
    """Return the dispatcher for the configured ``compute_backend``."""
    backend = get_settings().compute_backend
    if backend == "local":
        return LocalDispatcher()
    if backend == "aws_batch":
        return BatchDispatcher()
    raise ValueError(f"unknown compute_backend: {backend!r}")
