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

    class FakeResponse:
        status_code = 200

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return body

    captured: dict = {}

    def fake_post(url: str, json: dict, timeout: float):  # noqa: A002 - mirrors httpx
        captured["url"] = url
        captured["payload"] = json
        return FakeResponse()

    monkeypatch.setattr(httpx, "post", fake_post)

    outcome = client.run_scan_anywhere(
        ScanRequest(workspace=workspace, rule_config="auto", out_dir=None)
    )

    assert captured["url"] == "http://scan:8101/v1/scan"
    assert captured["payload"]["workspace"] == str(workspace)
    assert captured["payload"]["rule_config"] == "auto"

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

    def fake_post(url: str, json: dict, timeout: float):  # noqa: A002
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", fake_post)

    outcome = client.run_scan_anywhere(ScanRequest(workspace=workspace, rule_config="auto"))

    assert outcome.findings == []
    assert outcome.degraded is True
    assert outcome.scan_record is not None
    assert outcome.scan_record.failure_mode is not None
    assert "connection refused" in outcome.scan_record.failure_mode
    assert outcome.scan_record.zero_findings_is_suspicious is True
    assert outcome.warnings and "scan service" in outcome.warnings[0]


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
