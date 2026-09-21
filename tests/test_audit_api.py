"""The audit HTTP surface: submit, watch, read the report.

The one property everything here is built around: **an audit is long**. Half an hour and 150 agent
runs, which makes the read side the point of the feature rather than a convenience. So the tests are
about what a console polling every second sees -- a page of events that only ever grows, an honest
answer before the first event exists, and a 404 that means "not finished yet" rather than "broken".

The trail is written by hand here, not by a worker: this file is about the route's contract with the
bytes on disk (paging by `seq`, tolerating a torn line, refusing an id that could escape the audit
root), and running a real audit to produce them would test the harness instead -- which the
orchestration suite already does.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_contracts.jobs import FailureMode, JobKind, JobRequest, JobResult, JobState
from aegis_core.config import get_settings
from app.api import deps
from app.main import create_app
from services.harness import trail as trail_mod
from services.queue.jobs import JobStore
from services.queue.keys import QueueKeys
from services.queue.streams import JobStream


@pytest.fixture()
def audit_client(tmp_path: Path, monkeypatch, workspace: Path, fake_redis):
    """A gateway with a fakeredis queue and a real `work_dir` under tmp_path."""
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setenv("API_KEY", "test-key")
    get_settings.cache_clear()
    deps.set_queue_client(fake_redis)

    settings = get_settings()
    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    store = JobStore(fake_redis, settings.queue, keys=keys)
    stream = JobStream(fake_redis, settings.queue, keys=keys)
    stream.ensure_group()

    application = create_app()
    with TestClient(application) as client:
        client.queue = (store, stream)  # type: ignore[attr-defined]
        yield client

    deps.set_queue_client(None)
    get_settings.cache_clear()


def _store(client) -> JobStore:
    store, _ = client.queue  # type: ignore[attr-defined]
    return store


def _submit_audit(client, workspace: Path, **kwargs) -> str:
    response = client.post("/v1/audit", json={"workspace": str(workspace)}, **kwargs)
    assert response.status_code == 202, response.text
    return response.json()["job_id"]


def _write_trail(settings, job_id: str, events: list[dict]) -> Path:
    path = settings.work_dir / "audit" / job_id / trail_mod.TRAIL_NAME
    path.parent.mkdir(parents=True, exist_ok=True)
    with trail_mod.JsonlSink(path) as sink:
        writer = trail_mod.Trail([sink], base={"run_id": job_id})
        for event in events:
            writer.emit(event.pop("kind"), **event)
    return path


def test_task_snapshots_are_available_before_agent_start(audit_client, workspace: Path) -> None:
    from aegis_contracts.harness import WorkItem

    job_id = _submit_audit(audit_client, workspace)
    task = WorkItem(work_id="W-1", scope_id="scope-a", title="文件权限", rationale="外部入口")
    _write_trail(get_settings(), job_id, [{"kind": "work_item", "work": task.model_dump(mode="json")}])
    response = audit_client.get(f"/v1/audit/{job_id}/trail?after_seq=0")
    assert response.status_code == 200
    events = response.json()["events"]
    assert events[0]["kind"] == "work_item"
    assert events[0]["work"]["state"] == "planned"
    assert events[0]["work"]["title"] == "文件权限"


def test_submitting_an_audit_queues_a_job_of_that_kind(audit_client, workspace: Path) -> None:
    """An audit is a job like any other, so it inherits dedup, force and cancel for free."""
    job_id = _submit_audit(audit_client, workspace)

    job = _store(audit_client).get(job_id)
    assert job is not None
    assert job.kind is JobKind.AUDIT
    assert job.state.value == "queued"
    # The stages this job will never run say so from the start, instead of looking pending.
    states = {stage.stage: stage.state for stage in job.progress.stages}
    assert states["ai"] == "pending"
    assert states["scan"] == "skipped"
    assert states["package"] == "skipped"


def test_resubmitting_the_same_audit_attaches_instead_of_running_twice(
    audit_client, workspace: Path
) -> None:
    """The fingerprint is what makes a second click cheap; two audits of one repo are the same work.

    It also has to be a *different* fingerprint from the other job kinds for the same workspace --
    measured on the live stack, sharing one made an AI job attach to an earlier scan job and report
    success without doing anything.
    """
    first = _submit_audit(audit_client, workspace)
    second = audit_client.post("/v1/audit", json={"workspace": str(workspace)})

    assert second.status_code == 202
    assert second.json()["job_id"] == first
    assert second.json()["deduplicated"] is True

    store = _store(audit_client)
    audit = store.get(first)
    assert audit is not None
    plain = store.new_submission(JobRequest(workspace=str(workspace), lsp=False))
    assert plain.fingerprint != audit.submission.fingerprint


def test_the_trail_is_an_honest_empty_page_before_the_run_starts(
    audit_client, workspace: Path
) -> None:
    """`exists: false` is an answer; an error here would show a failure for the first two seconds."""
    job_id = _submit_audit(audit_client, workspace)

    body = audit_client.get(f"/v1/audit/{job_id}/trail").json()

    assert body["exists"] is False
    assert body["events"] == []
    assert body["last_seq"] == 0
    assert body["more"] is False
    assert body["trail"].endswith(f"audit\\{job_id}\\trail.jsonl") or body["trail"].endswith(
        f"audit/{job_id}/trail.jsonl"
    )


def test_the_trail_pages_by_seq_so_a_poll_only_carries_what_is_new(
    audit_client, workspace: Path
) -> None:
    """Incremental paging is what makes a one-second poll affordable for 30 minutes.

    The console keeps `last_seq` and asks for what is after it, so a run with 4000 tool calls costs
    one small request per tick instead of resending the whole log every time.
    """
    job_id = _submit_audit(audit_client, workspace)
    settings = get_settings()
    _write_trail(
        settings,
        job_id,
        [
            {"kind": "stage", "stage": "recon", "state": "start"},
            {"kind": "agent_start", "agent": "recon", "scope": "workspace", "run_id": "recon:x"},
            {"kind": "agent_step", "agent": "recon", "scope": "workspace", "run_id": "recon:x",
             "index": 1, "thought": "看一下目录", "tool": "list_files", "arguments": {"path": "."},
             "ok": True, "summary": "12 files"},
            {"kind": "candidate", "candidate_id": "C-1", "file": "a.java", "line": 3},
            {"kind": "summary", "closed": True, "counters": {"candidates": 1}},
        ],
    )

    first = audit_client.get(f"/v1/audit/{job_id}/trail", params={"limit": 2}).json()
    assert [event["kind"] for event in first["events"]] == ["stage", "agent_start"]
    assert first["more"] is True
    assert first["exists"] is True

    rest = audit_client.get(
        f"/v1/audit/{job_id}/trail", params={"after_seq": first["last_seq"], "limit": 100}
    ).json()
    assert [event["kind"] for event in rest["events"]] == ["agent_step", "candidate", "summary"]
    assert rest["more"] is False
    assert rest["last_seq"] == 5

    # The interesting payload: an agent's step carries what it thought, called, and got back.
    step = rest["events"][0]
    assert step["tool"] == "list_files" and step["arguments"] == {"path": "."}
    assert step["thought"] and step["summary"] == "12 files"
    assert step["run_id"] == "recon:x", "the trail's base fields survive the round trip"

    nothing_new = audit_client.get(
        f"/v1/audit/{job_id}/trail", params={"after_seq": rest["last_seq"]}
    ).json()
    assert nothing_new["events"] == [] and nothing_new["more"] is False


def test_a_torn_last_line_does_not_hide_the_events_before_it(
    audit_client, workspace: Path
) -> None:
    """A killed worker leaves a half-written line, and the record before it is still the record."""
    job_id = _submit_audit(audit_client, workspace)
    path = _write_trail(
        get_settings(), job_id, [{"kind": "stage", "stage": "recon", "state": "start"}]
    )
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 2, "kind": "agent_st')

    body = audit_client.get(f"/v1/audit/{job_id}/trail").json()

    assert len(body["events"]) == 1
    assert body["damaged"] == 1, "damage is reported, not swallowed and not raised"


def test_a_finished_audit_is_returned_not_re_run(audit_client, workspace: Path) -> None:
    """A second click must not buy a second half-hour run.

    The deduplication rule for a *succeeded* job is "return it, unless its output is gone" -- and the
    output marker is per-kind. An audit has no bundle and no `manifest.json`, so a naive check
    answered "gone" every time and every resubmission re-ran the whole review: the most expensive
    possible way to get the same answer.
    """
    job_id = _submit_audit(audit_client, workspace)
    store = _store(audit_client)
    job = store.get(job_id)
    assert job is not None

    run_dir = get_settings().work_dir / "audit" / job_id
    run_dir.mkdir(parents=True, exist_ok=True)

    # Succeeded, but with no report on disk yet: the honest answer is "run it again".
    store.mark_succeeded(
        job_id,
        result=JobResult(run_id=job_id, package_path=str(run_dir)),
    )
    missing = audit_client.post("/v1/audit", json={"workspace": str(workspace)})
    assert missing.status_code == 202
    assert missing.json()["deduplicated"] is False, "nothing to return, so it was redriven"

    # Now with the report where the worker leaves it: the finished job is the answer.
    (run_dir / "report.md").write_text("# 报告\n", encoding="utf-8")
    job = store.get(job_id)
    assert job is not None
    store.mark_succeeded(job_id, result=JobResult(run_id=job_id, package_path=str(run_dir)))

    found = audit_client.post("/v1/audit", json={"workspace": str(workspace)})
    assert found.status_code == 200
    assert found.json()["job_id"] == job_id
    assert found.json()["state"] == "succeeded"


def test_the_report_route_answers_404_until_there_is_one(audit_client, workspace: Path) -> None:
    """A missing report is "not finished yet", and the detail says where to look instead."""
    job_id = _submit_audit(audit_client, workspace)

    missing = audit_client.get(f"/v1/audit/{job_id}/report")
    assert missing.status_code == 404
    assert f"/v1/audit/{job_id}/trail" in missing.json()["detail"]

    run_dir = get_settings().work_dir / "audit" / job_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("# Aegis harness 报告\n\n结论\n", encoding="utf-8")

    found = audit_client.get(f"/v1/audit/{job_id}/report")
    assert found.status_code == 200
    body = found.json()
    assert body["markdown"].startswith("# Aegis harness 报告")
    assert body["run_dir"] == str(run_dir)


def test_the_audit_routes_refuse_an_id_that_could_escape_the_audit_root(
    audit_client, workspace: Path
) -> None:
    """The job id comes from the URL and is used to build a path, so it is validated.

    `../` in a path segment is one request away from reading a file outside the audit root; a
    non-audit job id is refused too, because reading a scan job's "trail" would report an empty run
    where the honest answer is "this job is not an audit".
    """
    traversals = ["..%2F..%2Fetc", "J-..-x", "not-a-job-id", "J-abc!def"]
    for bad in traversals:
        response = audit_client.get(f"/v1/audit/{bad}/trail")
        assert response.status_code in (400, 404), (bad, response.status_code, response.text)

    store = _store(audit_client)
    plain, _ = store.create(
        store.new_submission(JobRequest(workspace=str(workspace), lsp=False), kind=JobKind.SCAN)
    )
    assert audit_client.get(f"/v1/audit/{plain.job_id}/trail").status_code == 400

    assert audit_client.get("/v1/audit/J-0000000000000000/trail").status_code == 404


def test_the_trail_json_never_carries_the_api_key(audit_client, workspace: Path) -> None:
    """The trail is served over HTTP and read by a browser, so it must not carry credentials.

    Checked here rather than trusted: the trail is written by the harness, and the harness does not
    know the key -- but "the layer that cannot leak it" is a claim about code that changes.
    """
    job_id = _submit_audit(audit_client, workspace)
    _write_trail(
        get_settings(),
        job_id,
        [{"kind": "agent_step", "agent": "recon", "scope": "workspace", "thought": "没有密钥"}],
    )

    body = audit_client.get(f"/v1/audit/{job_id}/trail").text

    assert "test-key" not in body
    assert json.loads(body)["events"][0]["thought"] == "没有密钥"


# --- a redrive must not serve the previous attempt's artifacts ------------
#
# The job id is a fingerprint of the workspace, so a redrive reuses the id *and* the run
# directory. Between the redrive being accepted and the new attempt's first write, `report.md`
# and `trail.jsonl` were still the previous attempt's -- and `GET /v1/audit/{id}/report` served
# them as this attempt's conclusion. The worker is no help: it only truncates the trail when the
# harness attaches, which is after a worker picks the job up.


def _audit_run_dir(job_id: str) -> Path:
    return get_settings().work_dir / "audit" / job_id


def _finish_audit(audit_client, workspace: Path) -> str:
    """Submit an audit and leave a *finished* attempt's artifacts in its run directory.

    The files are what a real run writes, written by hand here: the point under test is what the
    gateway does to them on a redrive, not how the harness produced them.
    """
    job_id = _submit_audit(audit_client, workspace)
    store = _store(audit_client)
    job = store.get(job_id)
    assert job is not None
    store.set_running(job_id, worker_id="w-1")
    run_dir = _audit_run_dir(job_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / trail_mod.TRAIL_NAME).write_text('{"seq": 1, "kind": "summary"}\n', encoding="utf-8")
    (run_dir / "blackboard.json").write_text('{"candidates": []}', encoding="utf-8")
    (run_dir / "report.md").write_text("# 报告：第一次尝试\n", encoding="utf-8")
    store.mark_succeeded(job_id, result=JobResult(run_id=job_id, package_path=str(run_dir)))
    return job_id


def test_a_forced_re_run_archives_the_previous_attempts_artifacts(
    audit_client, workspace: Path
) -> None:
    """The stale report and trail must be gone the moment the redrive is accepted.

    Otherwise a console polling `/v1/audit/{id}/report` between the acceptance and the new
    attempt's first write shows the previous attempt's conclusion as this attempt's -- and that
    window is as long as the queue is deep.
    """
    job_id = _finish_audit(audit_client, workspace)
    run_dir = _audit_run_dir(job_id)
    (run_dir / "notes.txt").write_text("unrelated\n", encoding="utf-8")

    forced = audit_client.post("/v1/audit?force=true", json={"workspace": str(workspace)})

    assert forced.status_code == 202, forced.text
    assert not (run_dir / "report.md").exists(), "the live report must not still be attempt 1's"
    assert not (run_dir / trail_mod.TRAIL_NAME).exists(), "a stale trail reads as this attempt"
    assert not (run_dir / "blackboard.json").exists()

    archived = list(run_dir.glob("report.attempt1-*.md"))
    assert len(archived) == 1, sorted(path.name for path in run_dir.iterdir())
    assert archived[0].read_text(encoding="utf-8").startswith("# 报告：第一次尝试")
    boards = list(run_dir.glob("blackboard.attempt1-*.json"))
    assert len(boards) == 1 and boards[0].read_text(encoding="utf-8") == '{"candidates": []}'

    # Everything else in the run directory is none of this route's business.
    assert (run_dir / "notes.txt").read_text(encoding="utf-8") == "unrelated\n"

    job = _store(audit_client).get(job_id)
    assert job is not None and job.state is JobState.QUEUED
    assert job.progress.attempt == 2, "attempt 1 is the attempt that was replaced"

    # The report route now answers "not finished yet" instead of serving attempt 1's markdown.
    assert audit_client.get(f"/v1/audit/{job_id}/report").status_code == 404


def test_a_re_run_archives_under_the_attempt_being_replaced(
    audit_client, workspace: Path
) -> None:
    """Attempt *N*'s report is archived as `attemptN`, not as the attempt starting now."""
    job_id = _finish_audit(audit_client, workspace)
    run_dir = _audit_run_dir(job_id)
    first = audit_client.post("/v1/audit?force=true", json={"workspace": str(workspace)})
    assert first.status_code == 202, first.text

    # Attempt 2 ran and finished; redriving it must name what it replaces.
    store = _store(audit_client)
    store.set_running(job_id, worker_id="w-2", attempt=2)
    (run_dir / "report.md").write_text("# 报告：第二次尝试\n", encoding="utf-8")
    store.mark_succeeded(job_id, result=JobResult(run_id=job_id, package_path=str(run_dir)))

    again = audit_client.post("/v1/audit?force=true", json={"workspace": str(workspace)})

    assert again.status_code == 202, again.text
    second = list(run_dir.glob("report.attempt2-*.md"))
    assert len(second) == 1, sorted(path.name for path in run_dir.iterdir())
    assert second[0].read_text(encoding="utf-8").startswith("# 报告：第二次尝试")


def test_a_redrive_of_another_job_kind_leaves_audit_artifacts_alone(
    audit_client, workspace: Path
) -> None:
    """Only an audit has this run directory; a scan or assemble bundle must not be touched."""
    job_id = _finish_audit(audit_client, workspace)
    run_dir = _audit_run_dir(job_id)
    before = sorted(path.name for path in run_dir.iterdir())

    created = audit_client.post("/v1/jobs?force=true", json={"workspace": str(workspace), "lsp": False})
    assert created.status_code == 202, created.text

    assert sorted(path.name for path in run_dir.iterdir()) == before
    assert (run_dir / "report.md").is_file() and (run_dir / trail_mod.TRAIL_NAME).is_file()


def test_a_redrive_with_no_run_directory_is_still_accepted(
    audit_client, workspace: Path
) -> None:
    """An attempt that wrote nothing has nothing to archive, and that must not be an error."""
    job_id = _submit_audit(audit_client, workspace)
    store = _store(audit_client)
    job = store.get(job_id)
    assert job is not None
    store.set_running(job_id, worker_id="w-1")
    store.mark_succeeded(job_id, result=JobResult(run_id=job_id, package_path=""))
    assert not _audit_run_dir(job_id).exists()

    forced = audit_client.post("/v1/audit?force=true", json={"workspace": str(workspace)})

    assert forced.status_code == 202, forced.text
    assert forced.json()["deduplicated"] is False
    assert not _audit_run_dir(job_id).exists()
    restarted = store.get(job_id)
    assert restarted is not None and restarted.progress.attempt == 2


def test_a_redrive_of_a_failed_audit_archives_the_previous_attempts_artifacts(
    audit_client, workspace: Path
) -> None:
    """The failed branch writes into the same run directory, so it needs the same treatment.

    A crash halfway through leaves a partial report and a trail of what it managed to do; the
    redrive replaces both.
    """
    job_id = _submit_audit(audit_client, workspace)
    store = _store(audit_client)
    job = store.get(job_id)
    assert job is not None
    store.set_running(job_id, worker_id="w-1")
    run_dir = _audit_run_dir(job_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("# 半途而废\n", encoding="utf-8")
    (run_dir / trail_mod.TRAIL_NAME).write_text('{"seq": 1, "kind": "stage"}\n', encoding="utf-8")
    store.mark_failed(job_id, mode=FailureMode.INTERNAL_ERROR, message="worker died")

    forced = audit_client.post("/v1/audit?force=true", json={"workspace": str(workspace)})

    assert forced.status_code == 202, forced.text
    assert not (run_dir / "report.md").exists() and not (run_dir / trail_mod.TRAIL_NAME).exists()
    archived = list(run_dir.glob("report.attempt1-*.md"))
    assert len(archived) == 1 and archived[0].read_text(encoding="utf-8") == "# 半途而废\n"


def test_an_archiving_failure_does_not_fail_the_redrive(
    audit_client, workspace: Path, monkeypatch
) -> None:
    """Losing a stale artifact is not a reason to refuse a valid re-run.

    The failure is injected at `Path.replace`, which is where the archiving really moves a file;
    the request must still be accepted and the job still re-queued.
    """
    job_id = _finish_audit(audit_client, workspace)
    run_dir = _audit_run_dir(job_id)

    def refuse(self, target):  # pragma: no cover - the arguments are not the point
        raise OSError("sharing violation")

    monkeypatch.setattr(Path, "replace", refuse)

    forced = audit_client.post("/v1/audit?force=true", json={"workspace": str(workspace)})

    assert forced.status_code == 202, forced.text
    # Nothing was moved, so the old report is still readable -- worse than archived, but the
    # redrive the caller asked for still happened.
    assert (run_dir / "report.md").is_file()
    job = _store(audit_client).get(job_id)
    assert job is not None and job.state is JobState.QUEUED and job.progress.attempt == 2
    assert not (run_dir / trail_mod.TRAIL_NAME).exists(), "the delete is attempted independently"
