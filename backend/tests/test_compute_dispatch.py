"""Tests for the compute dispatch seam — focused on the per-firmware Batch
concurrency cap (shared-instance fairness guardrail, enterprise PLAN §7)."""

from types import SimpleNamespace
from uuid import UUID

import pytest

from app.services import compute_dispatch
from app.services.compute_dispatch import (
    BatchDispatcher,
    ConcurrencyLimitError,
    JobHandle,
    _firmware_token,
)

FW = UUID("12345678-1234-5678-1234-567812345678")


def _settings(cap: int) -> SimpleNamespace:
    return SimpleNamespace(
        batch_job_queue="q",
        batch_job_definition="def",
        batch_max_jobs_per_firmware=cap,
        aws_region="us-east-1",
    )


class FakeBatchClient:
    """Records submit_job calls; returns a scripted active-job count per status."""

    def __init__(self, active_by_status: dict | None = None):
        self.active_by_status = active_by_status or {}
        self.submitted: list[dict] = []
        self.list_calls: list[dict] = []

    def list_jobs(self, **kwargs):
        self.list_calls.append(kwargs)
        n = self.active_by_status.get(kwargs["jobStatus"], 0)
        return {"jobSummaryList": [{"jobId": f"j{i}"} for i in range(n)]}

    def submit_job(self, **kwargs):
        self.submitted.append(kwargs)
        return {"jobId": "job-xyz"}


@pytest.fixture
def patch_dispatch(monkeypatch):
    """Wire a BatchDispatcher to a FakeBatchClient and fake settings."""

    def _apply(cap: int, active_by_status: dict | None = None):
        client = FakeBatchClient(active_by_status)
        monkeypatch.setattr(compute_dispatch, "get_settings", lambda: _settings(cap))
        d = BatchDispatcher()
        monkeypatch.setattr(d, "_client", lambda: client)
        return d, client

    return _apply


def test_firmware_token_is_stable_and_name_safe():
    tok = _firmware_token(FW)
    assert tok == FW.hex[:12]
    assert tok.isalnum() and len(tok) == 12


def test_under_cap_submits_with_firmware_scoped_name_and_tag(patch_dispatch):
    d, client = patch_dispatch(cap=8, active_by_status={"RUNNING": 2})
    handle = d.dispatch_analysis(FW, "/bin/sh", "abc123")
    assert isinstance(handle, JobHandle) and handle.ref == "job-xyz"
    assert len(client.submitted) == 1
    sub = client.submitted[0]
    assert sub["jobName"].startswith(f"wairz-{_firmware_token(FW)}-an-")
    assert sub["tags"] == {"wairz:firmware": str(FW)}


def test_at_cap_rejects_before_submitting(patch_dispatch):
    # 8 in flight across two statuses == cap 8 → reject, no submit.
    d, client = patch_dispatch(cap=8, active_by_status={"RUNNING": 5, "RUNNABLE": 3})
    with pytest.raises(ConcurrencyLimitError) as exc:
        d.dispatch_decompile(FW, "/bin/sh", "abc123", "main")
    assert "in flight" in str(exc.value)
    assert client.submitted == []


def test_count_sums_all_active_statuses_and_filters_by_firmware(patch_dispatch):
    d, client = patch_dispatch(cap=99, active_by_status={"RUNNING": 1, "STARTING": 2})
    d.dispatch_analysis(FW, "/bin/sh", "abc123")
    # One list_jobs per active status, each scoped to this firmware's name prefix.
    assert len(client.list_calls) == len(compute_dispatch._ACTIVE_BATCH_STATUSES)
    for call in client.list_calls:
        assert call["jobQueue"] == "q"
        assert call["filters"] == [
            {"name": "JOB_NAME", "values": [f"wairz-{_firmware_token(FW)}-*"]}
        ]


def test_cap_zero_disables_check(patch_dispatch):
    d, client = patch_dispatch(cap=0, active_by_status={"RUNNING": 1000})
    d.dispatch_analysis(FW, "/bin/sh", "abc123")
    assert client.list_calls == []  # no counting when disabled
    assert len(client.submitted) == 1


def test_count_paginates(patch_dispatch):
    """nextToken is followed until exhausted."""
    d, client = patch_dispatch(cap=99)

    pages = {"RUNNING": [3, 2]}  # two pages then stop

    def list_jobs(**kwargs):
        client.list_calls.append(kwargs)
        status = kwargs["jobStatus"]
        remaining = pages.get(status)
        if not remaining:
            return {"jobSummaryList": []}
        n = remaining.pop(0)
        out = {"jobSummaryList": [{"jobId": "x"} for _ in range(n)]}
        if remaining:
            out["nextToken"] = "more"
        return out

    client.list_jobs = list_jobs
    assert d._count_active_jobs(_firmware_token(FW)) == 5
