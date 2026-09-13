"""The scan capability has two transports and one behaviour.

Extraction must not care whether scanning happens in-process or in another
container, so both paths return the same `ScanOutcome` shape and a remote failure
degrades exactly like a local one.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aegis_contracts.domain import ScanRecord
from services.scan import client
from services.scan.runner import ScanOutcome, ScanRequest, probe


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n", encoding="utf-8")
    return root


def test_default_is_in_process(monkeypatch: pytest.MonkeyPatch, workspace: Path) -> None:
    monkeypatch.delenv(client.ENV_SCAN_SERVICE_URL, raising=False)
    assert client.scanning_is_remote() is False
    assert client.scan_service_url() is None


def test_a_url_switches_to_remote(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(client.ENV_SCAN_SERVICE_URL, "http://scan:8101/")
    assert client.scanning_is_remote() is True
    assert client.scan_service_url() == "http://scan:8101"  # trailing slash trimmed


def test_in_process_scan_runs_the_real_runner(
    monkeypatch: pytest.MonkeyPatch, workspace: Path, tmp_path: Path
) -> None:
    """With no URL configured, the in-process path is used and the runner is invoked."""
    monkeypatch.delenv(client.ENV_SCAN_SERVICE_URL, raising=False)

    calls: dict = {}

    def fake_runner_run_scan(request: ScanRequest) -> ScanOutcome:
        calls["request"] = request
        return ScanOutcome(
            engine="opengrep",
            engine_version="9.9.9",
            findings=[],
            warnings=[],
            scan_record=ScanRecord(engine="opengrep", configured=True, returncode=0),
        )

    monkeypatch.setattr(client, "run_scan", fake_runner_run_scan)
    outcome = client.run_scan_anywhere(
        ScanRequest(workspace=workspace, rule_config="auto", out_dir=tmp_path / "out")
    )

    assert "request" in calls, "the local runner was not used"
    assert calls["request"].rule_config == "auto"
    assert outcome.engine_version == "9.9.9"
    assert outcome.sarif_path is None  # the fake returned no SARIF


def test_probe_reports_a_missing_engine() -> None:
    assert probe("definitely-not-installed", fallback=None)["available"] is False


def test_remote_scan_parses_the_service_response(
    monkeypatch: pytest.MonkeyPatch, workspace: Path
) -> None:
    """The wire shape must map onto the same ScanOutcome the local path returns."""
    monkeypatch.setenv(client.ENV_SCAN_SERVICE_URL, "http://scan:8101")

    body = {
        "engine": "opengrep",
        "engine_version": "1.16.0",
        "sarif_path": "/tmp/remote.sarif",
        "findings": [
            {
                "finding_id": "F-abc",
                "rule_id": "r1",
                "message": "m",
                "severity": "error",
                "path": "app.py",
                "region": {"path": "app.py", "start_line": 0, "start_char": 0,
                           "end_line": 0, "end_char": 5},
                "snippet": "x = 1",
                "provider": "opengrep",
            }
        ],
        "scan_record": {
            "engine": "opengrep",
            "engine_version": "1.16.0",
            "returncode": 1,
            "configured": True,
            "rule_counts": {"r1": 1},
        },
        "warnings": [],
        "degraded": False,
    }

    import httpx

    captured: dict = {}

    class FakeResponse:
        def __init__(self, body: dict, status_code: int = 200) -> None:
            self._body = body
            self.status_code = status_code

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self._body

    class FakeClient:
        """The job protocol: accept, poll until terminal, hand back the result."""

        def __init__(self, **kwargs) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

        def post(self, url: str, json: dict):  # noqa: A002 - mirrors httpx
            captured["post_url"] = url
            captured["payload"] = json
            return FakeResponse({"job_id": "S-abc", "state": "queued", "status_url": "/x"})

        def get(self, url: str):
            captured.setdefault("get_urls", []).append(url)
            polls = len(captured["get_urls"])
            if polls == 1:
                return FakeResponse({"job_id": "S-abc", "state": "running", "result": None})
            return FakeResponse(
                {"job_id": "S-abc", "state": "succeeded", "result": body}
            )

        def delete(self, url: str):  # pragma: no cover - not used in this test
            raise AssertionError("a successful scan must not be cancelled")

    monkeypatch.setattr(httpx, "Client", FakeClient)

    outcome = client.run_scan_anywhere(
        ScanRequest(workspace=workspace, rule_config="auto", out_dir=None)
    )

    assert captured["post_url"] == "http://scan:8101/v1/scan/jobs"
    assert captured["payload"]["workspace"] == str(workspace)
    assert captured["payload"]["rule_config"] == "auto"
    assert captured["get_urls"] == [
        "http://scan:8101/v1/scan/jobs/S-abc",
        "http://scan:8101/v1/scan/jobs/S-abc",
    ], "the caller must poll, not block on one long request"
    # Short per-request timeouts are the mechanism: no single call may park the caller.
    limits = captured["client_kwargs"]["timeout"]
    assert limits.read is not None and limits.read <= 30.0

    assert outcome.engine == "opengrep"
    assert outcome.engine_version == "1.16.0"
    assert len(outcome.findings or []) == 1
    assert outcome.findings[0].rule_id == "r1"  # type: ignore[union-attr]
    assert isinstance(outcome.scan_record, ScanRecord)
    assert outcome.degraded is False
    # the remote path is recorded but marked as not-ours: opening it here would fail
    assert outcome.scan_record.location == "remote"
    assert client.local_sarif_readable(outcome) is False
    assert outcome.sarif_path is not None  # kept for the record


def test_sarif_readability_depends_on_where_the_scan_ran(tmp_path: Path) -> None:
    """A local scan's SARIF is ours to attach; a remote one is not."""
    sarif = tmp_path / "s.sarif"
    sarif.write_text("{}", encoding="utf-8")

    local = ScanOutcome(
        engine="opengrep",
        sarif_path=sarif,
        scan_record=ScanRecord(engine="opengrep", location="in-process"),
    )
    assert client.local_sarif_readable(local) is True

    remote = ScanOutcome(
        engine="opengrep",
        sarif_path=sarif,
        scan_record=ScanRecord(engine="opengrep", location="remote"),
    )
    assert client.local_sarif_readable(remote) is False


def test_remote_failure_degrades_like_a_local_one(
    monkeypatch: pytest.MonkeyPatch, workspace: Path
) -> None:
    """An unreachable scan service must not raise; it must be recorded."""
    monkeypatch.setenv(client.ENV_SCAN_SERVICE_URL, "http://scan:8101")

    import httpx

    class FailingClient:
        def __init__(self, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

        def post(self, url: str, json: dict):  # noqa: A002 - mirrors httpx
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "Client", FailingClient)

    outcome = client.run_scan_anywhere(ScanRequest(workspace=workspace, rule_config="auto"))

    assert outcome.findings == []
    assert outcome.degraded is True
    assert outcome.scan_record is not None
    assert outcome.scan_record.failure_mode is not None
    assert "connection refused" in outcome.scan_record.failure_mode
    # `configured=True` here because the request asked for rules: a *configured* scan that
    # produced nothing is the suspicious case, and that distinction is carried from the
    # request rather than assumed.
    assert outcome.scan_record.configured is True
    assert outcome.scan_record.zero_findings_is_suspicious is False
    assert outcome.warnings and "扫描服务" in outcome.warnings[0]


def test_remote_cancel_sends_a_delete_and_reports_a_cancellation(
    monkeypatch: pytest.MonkeyPatch, workspace: Path
) -> None:
    """The point of the job protocol: a cancel stops the *remote* work, not just our wait.

    Before this, cancelling a delegated scan left the scanner running in the other container
    for the rest of its timeout, and the caller could not even notice the cancel request
    until the blocking HTTP call returned. The DELETE is what makes it real.
    """
    import threading

    monkeypatch.setenv(client.ENV_SCAN_SERVICE_URL, "http://scan:8101")
    # No sleeping between polls: the test drives the cancel itself.
    monkeypatch.setenv(client.ENV_SCAN_JOB_POLL_MS, "50")

    import httpx

    cancel_event = threading.Event()
    seen: dict = {"polls": 0}

    class FakeClient:
        def __init__(self, **kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc) -> None:
            return None

        def post(self, url, json):  # noqa: A002
            class R:
                status_code = 202

                def raise_for_status(self):
                    return None

                def json(self):
                    return {"job_id": "S-cancel", "state": "queued", "status_url": "/x"}

            return R()

        def get(self, url):
            seen["polls"] += 1
            cancel_event.set()  # the user's cancel arrives while the scan runs

            class R:
                status_code = 200

                def raise_for_status(self):
                    return None

                def json(self):
                    return {"job_id": "S-cancel", "state": "running", "result": None}

            return R()

        def delete(self, url):
            seen["deleted"] = url

            class R:
                status_code = 200

                def json(self):
                    return {"job_id": "S-cancel", "state": "canceled"}

            return R()

    monkeypatch.setattr(httpx, "Client", FakeClient)

    outcome = client.run_scan_anywhere(
        ScanRequest(workspace=workspace, rule_config="auto", cancel_event=cancel_event)
    )

    assert seen.get("deleted") == "http://scan:8101/v1/scan/jobs/S-cancel", (
        "a cancel must tell the scan service to stop, not merely stop waiting"
    )
    assert outcome.canceled is True
    assert outcome.scan_record is not None
    assert outcome.scan_record.failure_mode == "scan_aborted"
    assert outcome.scan_record.location == "remote"
    assert outcome.findings == []


def test_both_transports_return_the_same_type(
    monkeypatch: pytest.MonkeyPatch, workspace: Path
) -> None:
    """A caller must be able to ignore which transport it got."""
    monkeypatch.delenv(client.ENV_SCAN_SERVICE_URL, raising=False)
    local = client.run_scan_anywhere(ScanRequest(workspace=workspace, rule_config="auto"))
    assert isinstance(local, ScanOutcome)
    assert local.scan_record is not None


def test_scan_service_health_shape() -> None:
    """The gateway reads these keys; a rename must not break it silently."""
    result = probe("definitely-not-installed-opengrep", fallback=None)
    assert set(result) >= {"available", "reason"}
    assert result["available"] is False
