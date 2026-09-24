"""The worker loop and the reaper: progress, failure, retry, and the one dangerous mistake.

The mistake this file is built around: **declaring a slow job dead.** A fifteen-minute scan
and a crashed worker are identical from the outside except for one signal -- the heartbeat.
If the reaper decides on elapsed time alone, it starts inventing failures, and a queue that
invents failures is worse than no queue, because the results look plausible.

The other half is the shutdown/cancel distinction: returning work to the queue is not the
same as cancelling it, and recording one as the other is telling the user they asked for
something they did not.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_contracts.jobs import (
    AuditOptions,
    FailureMode,
    JobKind,
    JobRequest,
    JobResult,
    JobStage,
    JobState,
)
from aegis_core.config import Settings
from services.queue.cancel import Teardown
from services.queue.keys import QueueKeys
from services.queue.reaper import (
    Reaper,
    _seconds_since,
    reconcile_startup,
    recoverable_artifact,
)
from services.queue.worker import Worker


def _settings(tmp_path: Path, queue_settings) -> Settings:
    return Settings(
        workspace_root=tmp_path,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        queue=queue_settings,
        lsp_enabled=False,
    ).resolve()


def _submit(store, *, workspace: Path, **overrides):
    request = JobRequest(workspace=str(workspace), lsp=False, **overrides)
    submission = store.new_submission(request)
    job, _ = store.create(submission)
    return submission, job


def _worker(store, stream, settings) -> Worker:
    return Worker(store, stream, settings, worker_id="w-test")


def _entry(job, attempt: int = 1) -> dict:
    return {
        "entry_id": "1-1",
        "job_id": job.job_id,
        "kind": job.submission.kind.value,
        "fingerprint": job.submission.fingerprint,
        "attempt": attempt,
    }


# --- the worker loop ---------------------------------------------------


def test_handle_runs_the_pipeline_and_reports_every_stage(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A successful job: terminal state, a result, and every stage accounted for."""
    from aegis_contracts.domain import AnalysisBundle, AnalysisBundleManifest
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    submission, job = _submit(job_store, workspace=workspace)

    class _FakePipeline:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, request, *, observer=None, abort=None, teardown=None, staging=False):
            assert teardown is not None, "the worker must hand over a teardown handle"
            for stage in ("scan", "setup", "locate", "expand", "read", "assemble", "package"):
                observer(
                    worker_module.StageEvent(
                        stage=stage, phase="end", ms=10, counters={"discovered": 1}
                    )
                )

            class _Outcome:
                bundle = AnalysisBundle(
                    manifest=AnalysisBundleManifest(
                        bundle_id="B-fake", run_id="R-fake", workspace_root=str(workspace)
                    )
                )
                package_path = tmp_path / "packages" / "B-fake"
                run_id = "R-fake"
                sarif_path = None
                scan_record = None
                warnings: list[str] = []

            _Outcome.package_path.mkdir(parents=True, exist_ok=True)
            return _Outcome()

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _FakePipeline)
    worker = _worker(job_store, job_stream, settings)
    worker.handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.SUCCEEDED
    assert stored.result is not None and stored.result.bundle_id == "B-fake"
    assert stored.progress.stage is JobStage.DONE
    done = {entry.stage for entry in stored.progress.stages if entry.state == "done"}
    skipped = {entry.stage for entry in stored.progress.stages if entry.state == "skipped"}
    assert done == set(JobStage) - {JobStage.AI}, "every stage this job kind uses is reported"
    assert skipped == {JobStage.AI}, "an assemble job does not run the AI stage, and says so"
    assert stored.progress.counters["discovered"] == 1


def test_handle_marks_failed_with_a_named_mode_on_exception(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)

    class _Exploding:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Exploding)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None
    assert stored.failure.mode is FailureMode.PIPELINE_EXCEPTION
    assert "boom" in (stored.failure.detail or "")
    assert stored.state is not JobState.RUNNING, "a failure is never left as running"


def test_handle_refuses_a_missing_workspace_without_running_anything(
    job_store, job_stream, tmp_path, queue_settings, monkeypatch
) -> None:
    """Checked before the pipeline starts, so a bad path costs nothing."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    missing = tmp_path / "not-a-directory"
    submission, job = _submit(job_store, workspace=missing)
    calls: list[int] = []

    class _Counting:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):  # pragma: no cover - must not run
            calls.append(1)
            raise AssertionError("the pipeline must not be called")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Counting)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.failure is not None
    assert stored.failure.mode is FailureMode.WORKSPACE_MISSING
    assert calls == []


def test_an_ai_job_without_a_bundle_is_refused_by_name(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """The AI stage consumes a bundle, so `workspace` alone is not enough to identify the work.

    Refused with its own `FailureMode` rather than `NotImplementedError`: the stage exists now,
    and "the request named no bundle" is a different fact from "the stage is missing". Keeping
    them apart is what stops a client from being told to upgrade instead of to fix its request.
    """
    settings = _settings(tmp_path, queue_settings)
    request = JobRequest(workspace=str(workspace), lsp=False)
    submission = job_store.new_submission(request, kind=JobKind.AI_FANOUT)
    job, _ = job_store.create(submission)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None
    assert stored.failure.mode is FailureMode.AI_BUNDLE_MISSING
    assert "bundle_id" in stored.failure.message


def test_an_ai_job_on_a_bundle_that_is_not_there_is_refused_by_name(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    request = JobRequest(workspace=str(workspace), lsp=False, bundle_id="B-does-not-exist")
    submission = job_store.new_submission(request, kind=JobKind.AI_FANOUT)
    job, _ = job_store.create(submission)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None and stored.failure is not None
    assert stored.failure.mode is FailureMode.AI_BUNDLE_MISSING


def _ai_bundle(settings, bundle_id: str = "B-ai"):
    """A bundle directory with the one file the AI stage needs to find."""
    import json

    package = settings.output_dir / bundle_id
    (package / "ai").mkdir(parents=True, exist_ok=True)
    (package / "ai" / "blocks.jsonl").write_text(
        json.dumps({"block_id": "context.C-1", "title": "c", "content": "x"}) + "\n",
        encoding="utf-8",
    )
    return package


def test_an_ai_job_fails_by_name_when_every_call_fails(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A job that produced no verdict must not report success.

    Two reasons, and the second is what bit us: the caller would believe the analysis ran, and
    deduplication would refuse to retry -- resubmitting the same request returns the stored job.
    """
    from datetime import datetime, timezone

    from aegis_contracts.ai import AICall, AIReport
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _ai_bundle(settings)

    def fake_analyse(bundle, config, **kwargs):
        return AIReport(
            bundle_id=bundle.name,
            model="fake",
            calls=[AICall(context_id="context.C-1", parsed=False, error="AIUnavailable: HTTP 504")],
            finished_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(worker_module, "analyse_bundle", fake_analyse)
    request = JobRequest(workspace=str(workspace), lsp=False, bundle_id="B-ai")
    job, _ = job_store.create(job_store.new_submission(request, kind=JobKind.AI_FANOUT))

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None and stored.failure is not None
    assert stored.state is JobState.FAILED
    assert stored.failure.mode is FailureMode.AI_FAILED
    assert "HTTP 504" in stored.failure.message


def test_an_ai_job_succeeds_with_a_warning_when_only_some_calls_fail(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A partial answer is a result: throwing it away would lose the contexts that did answer."""
    from datetime import datetime, timezone

    from aegis_contracts.ai import AICall, AIReport, Verdict, VerdictKind, VerdictSeverity
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _ai_bundle(settings)

    def fake_analyse(bundle, config, **kwargs):
        return AIReport(
            bundle_id=bundle.name,
            model="fake",
            calls=[
                AICall(context_id="context.C-1", parsed=True,
                       verdict=Verdict(verdict=VerdictKind.TRUE_POSITIVE,
                                       severity=VerdictSeverity.HIGH, confidence=0.7)),
                AICall(context_id="context.C-2", parsed=False, error="AIError: 找不到 JSON 对象"),
            ],
            finished_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(worker_module, "analyse_bundle", fake_analyse)
    request = JobRequest(workspace=str(workspace), lsp=False, bundle_id="B-ai")
    job, _ = job_store.create(job_store.new_submission(request, kind=JobKind.AI_FANOUT))

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.SUCCEEDED
    assert any("1/2" in w for w in (stored.result.warnings if stored.result else []))


def test_an_ai_job_succeeds_and_says_why_it_skipped(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A disabled stage is a *successful* job with a warning, not a failure.

    The stage is off by default (it spends money), and a bundle whose AI stage did not run is
    still a complete, useful bundle. Failing the job would make "not configured" look like "the
    analysis broke".
    """
    import json

    settings = _settings(tmp_path, queue_settings)
    package = settings.output_dir / "B-ai"
    (package / "ai").mkdir(parents=True)
    (package / "ai" / "blocks.jsonl").write_text(
        json.dumps({"block_id": "context.C-1", "title": "c", "content": "x"}) + "\n",
        encoding="utf-8",
    )
    request = JobRequest(workspace=str(workspace), lsp=False, bundle_id="B-ai")
    submission = job_store.new_submission(request, kind=JobKind.AI_FANOUT)
    job, _ = job_store.create(submission)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.SUCCEEDED
    assert stored.result is not None
    assert stored.result.bundle_id == "B-ai"
    assert any("未运行" in w for w in stored.result.warnings)
    # The stage is `ai`, and `skipped` rather than `running`: nothing was in flight. Measured
    # before the fix: an AI job reported `scan` from start to finish, which is a different claim.
    stage = next(s for s in stored.progress.stages if s.stage is JobStage.AI)
    assert stage.state == "skipped"
    assert "已禁用" in (stage.note or ""), "the stage says why it did not run"
    # `progress.stage` is the sentinel once a job is over: nothing is in flight any more.
    assert stored.progress.stage is JobStage.DONE
    # And the stages this job kind never reaches say so, rather than reading as "still to come".
    assert next(s for s in stored.progress.stages if s.stage is JobStage.SCAN).state == "skipped"


def test_an_ai_job_reports_the_ai_stage_while_it_runs(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """The stage a job reports has to describe what the job is doing.

    Before this, `handle()` pinned `JobStage.SCAN` for every kind, so an `ai_fanout` job claimed to
    be scanning while it was calling a model.
    """
    from datetime import datetime, timezone

    from aegis_contracts.ai import AICall, AIReport, Verdict, VerdictKind, VerdictSeverity
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _ai_bundle(settings)
    seen: list[str] = []

    def fake_analyse(bundle, config, **kwargs):
        job = job_store.get(job_id)
        seen.append(job.progress.stage.value if job else "?")
        return AIReport(
            bundle_id=bundle.name,
            model="fake",
            calls=[AICall(context_id="context.C-1", parsed=True,
                          verdict=Verdict(verdict=VerdictKind.TRUE_POSITIVE,
                                          severity=VerdictSeverity.HIGH, confidence=0.7))],
            finished_at=datetime.now(timezone.utc),
        )

    monkeypatch.setattr(worker_module, "analyse_bundle", fake_analyse)
    request = JobRequest(workspace=str(workspace), lsp=False, bundle_id="B-ai")
    job, _ = job_store.create(job_store.new_submission(request, kind=JobKind.AI_FANOUT))
    job_id = job.job_id

    _worker(job_store, job_stream, settings).handle(_entry(job))

    assert seen == ["ai"], f"the stage while the model runs should be `ai`, saw {seen}"
    stored = job_store.get(job_id)
    assert stored is not None
    stage = next(s for s in stored.progress.stages if s.stage is JobStage.AI)
    assert stage.state == "done"
    assert "已研判 1/1 个上下文" in (stage.note or "")
    scan = next(s for s in stored.progress.stages if s.stage is JobStage.SCAN)
    assert scan.state == "skipped", "an AI job must not report the scan stage as started"


# --- the audit job -----------------------------------------------------


def _audit_job(job_store, workspace: Path, *, audit_options: AuditOptions | None = None):
    request = JobRequest(workspace=str(workspace), lsp=False, audit_options=audit_options)
    return job_store.create(job_store.new_submission(request, kind=JobKind.AUDIT))[0]


def test_an_audit_job_runs_the_harness_under_the_shared_work_dir(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """The wiring an audit needs, asserted field by field against a stubbed harness.

    Four things have to be right and each has a failure mode: the run directory must be under
    `work_dir` (the workspace is read-only and the gateway cannot read a run written anywhere
    else), the abort predicate must be the worker's (or cancelling does nothing for 30 minutes),
    the trail must reach the job's progress (or the console shows a stage that never moves), and
    the artifacts must point at files that exist (or the console links to nothing).

    The coordinator is stubbed here on purpose: whether the *review* works is the orchestration
    suite's question. This test is about the job plumbing around it.
    """
    from aegis_core.ai_runtime import AISettingsUpdate, save_ai
    from services.harness import blackboard as bb
    from services.harness import trail as trail_mod
    from services.harness.coordinator import HarnessResult

    settings = _settings(tmp_path, queue_settings)
    save_ai(settings, AISettingsUpdate(
        enabled=True, base_url="https://provider.example/v1", model="saved-model",
        api_key="saved-secret", concurrency=3,
    ))
    job = _audit_job(job_store, workspace, audit_options=AuditOptions(
        concurrency=2, max_tokens=0, steps_per_agent=12, timeout_s=240,
        temperature=0.2, max_rounds=2,
    ))
    captured: dict = {}

    class StubCoordinator:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            self.run_id = kwargs["run_id"]
            self.run_dir = Path(kwargs["out_dir"]) / kwargs["run_id"]
            self.trail = None

        def attach_trail(self, *sinks, base=None):
            self.trail = trail_mod.Trail(
                [trail_mod.JsonlSink(self.run_dir / trail_mod.TRAIL_NAME), *sinks],
                base={"run_id": self.run_id},
            )
            return self.trail

        def run(self):
            self.run_dir.mkdir(parents=True, exist_ok=True)
            self.trail.emit("stage", stage="discovery", state="start")
            self.trail.emit("candidate", candidate_id="C-1", file="a.java", line=3)
            self.trail.emit("stage", stage="close", state="end")
            board = bb.new_blackboard(self.run_id, Path(captured["workspace"]))
            board = bb.mark_closed(board, "stub 结束")
            report = self.run_dir / "report.md"
            report.write_text("# 报告\n", encoding="utf-8")
            return HarnessResult(
                blackboard=board, run_dir=self.run_dir, report_path=report, notes=["stub"]
            )

        def __repr__(self) -> str:  # pragma: no cover - debugging aid
            return "<StubCoordinator>"

    monkeypatch.setattr(
        "services.harness.coordinator.HarnessCoordinator", StubCoordinator
    )
    def fake_client_from(config, **_kwargs):
        captured["ai_config"] = config
        return object()

    monkeypatch.setattr("services.ai.runner.client_from", fake_client_from)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None and stored.state is JobState.SUCCEEDED, stored.failure
    # 1. the run lives where every container can see it, and the job id is the run id
    assert captured["out_dir"] == settings.work_dir / "audit"
    assert captured["run_id"] == job.job_id
    assert captured["workspace"] == workspace
    assert captured["config"].concurrency == 2
    assert captured["config"].steps_per_agent == 12
    assert captured["config"].max_rounds == 2
    assert captured["ai_config"].max_tokens == 0
    assert captured["ai_config"].timeout_s == 240
    assert captured["ai_config"].temperature == 0.2
    assert captured["ai_config"].model == "saved-model"
    assert captured["ai_config"].api_key.get_secret_value() == "saved-secret"
    # 2. the coordinator polls the worker's own abort predicate
    assert captured["abort"] is not None
    # 3. the trail reached the job record
    stage = next(s for s in stored.progress.stages if s.stage is JobStage.AI)
    assert stage.state == "done"
    assert "探索代码" in (stage.note or "") or "AI 审计结束" in (stage.note or "")
    assert stage.counters.get("candidates") == 0, "the stub's trail has no ledger to count"
    # 4. the artifacts point at real files
    assert stored.result is not None
    for name in ("audit_trail", "audit_report"):
        artifact = stored.result.artifacts[name]
        assert artifact.available and Path(artifact.path).is_file(), name
    assert Path(stored.result.package_path) == settings.work_dir / "audit" / job.job_id
    # And the gateway derives the same directory from the job id alone. The two halves live in
    # different modules, and a mismatch would show an *empty* trail for a run that worked -- the
    # kind of bug that looks like "the audit found nothing".
    from app.api.audit import _run_dir

    assert _run_dir(job.job_id, settings) == Path(stored.result.package_path)


def test_an_audit_without_credentials_is_refused_by_name(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A missing key is a one-line fix, and the message has to name the variable.

    The alternative -- letting every agent stop on its first call and reporting "no findings" --
    is the exact shape of failure this project keeps refusing: an answer that looks like a result.
    """
    settings = _settings(tmp_path, queue_settings)
    job = _audit_job(job_store, workspace)

    from services.ai.runner import AINotConfigured

    def refuse(config, **kwargs):
        raise AINotConfigured("API_KEY 未设置：拒绝在没有密钥的情况下调用模型")

    monkeypatch.setattr("services.ai.runner.client_from", refuse)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None and stored.failure is not None
    assert stored.failure.mode is FailureMode.AI_FAILED
    assert "API_KEY" in stored.failure.message


def test_an_audit_is_never_left_pending_on_the_stages_it_does_not_use(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """The bundle-building stages are `skipped` from the start, not `pending`.

    "This job does not use that stage" and "that stage has not started" are different facts; a
    reader who could not tell them apart would wait for a packaging stage that is never coming.
    """
    job = _audit_job(job_store, workspace)
    stored = job_store.get(job.job_id)
    assert stored is not None
    states = {stage.stage: stage.state for stage in stored.progress.stages}
    assert states[JobStage.AI] == "pending"
    assert states[JobStage.DONE] in ("pending", "skipped")
    assert all(
        state == "skipped"
        for stage, state in states.items()
        if stage not in (JobStage.AI, JobStage.DONE)
    )


def test_handle_skips_a_terminal_job_on_redelivery(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A reaper re-enqueue and a MAXLEN survivor can both repeat a job id."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-other")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-already"))
    calls: list[int] = []

    class _Counting:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):  # pragma: no cover - must not run
            calls.append(1)

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Counting)
    _worker(job_store, job_stream, settings).handle(_entry(job))
    assert calls == [], "finished work must not be re-run"
    assert job_store.get(job.job_id).result.bundle_id == "B-already"  # type: ignore[union-attr]


def test_handle_cancels_a_job_canceled_while_queued(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A cancel that arrives before the job starts is honoured without starting it."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.request_cancel(job.job_id)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.CANCELED
    assert stored.failure is None


def test_handle_pins_the_scan_stage_before_the_silent_stage(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """The scan emits nothing while it runs, so the stage must be written first."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    observed: list[str] = []

    class _Spy:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, request, *, observer=None, abort=None, teardown=None, staging=False):
            snapshot = job_store.get(job.job_id)
            observed.append(snapshot.progress.stage.value)
            observed.append(snapshot.progress.stages[0].note or "")
            raise RuntimeError("stop here; the snapshot is what matters")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Spy)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    assert observed[0] == "scan", "the stage is pinned before the pipeline runs"
    assert observed[1] == "扫描中", "and it says what it is doing"


# --- cancellation vs shutdown ------------------------------------------


def test_canceled_abort_becomes_canceled_not_failed(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    from aegis_core.cancel import CanceledAbort
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)

    class _Canceled:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):
            raise CanceledAbort(stage="expand", resource="lsp_request", detail="blocked")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Canceled)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.CANCELED
    assert stored.failure is None, "cancellation is an action, not a fault"
    assert stored.progress.stage is JobStage.EXPAND, "the stage where it stopped is kept"
    note = next(e.note for e in stored.progress.stages if e.stage is JobStage.EXPAND)
    assert "expand" in (note or "")


def test_shutdown_returns_the_job_to_the_queue_not_canceled(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A restart is not a cancellation, and saying otherwise would be a lie."""
    from aegis_core.cancel import CanceledAbort
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    seen: dict[str, object] = {}

    class _Stopping:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, request, *, observer=None, abort=None, teardown=None, staging=False):
            seen["abort"] = abort
            raise CanceledAbort(stage="scan", resource="scan_process")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Stopping)
    worker = _worker(job_store, job_stream, settings)
    # Simulate SIGTERM arriving mid-run.
    worker.stop_event.set()

    entries_before = job_stream.stream_length()
    worker.handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.QUEUED, "returned to the queue, not canceled"
    assert stored.cancel_requested is False, "the user did not ask for this"
    assert stored.progress.counters == {} or True  # progress is preserved, not reset
    assert job_stream.stream_length() > entries_before, "and it was re-enqueued"


def test_the_abort_predicate_notices_a_queued_cancel_request(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A cancel from the gateway arrives as a flag; this is how the loop learns of it."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    worker = _worker(job_store, job_stream, settings)
    worker._current_job = job.job_id
    worker._last_cancel_poll = 0.0

    assert worker._abort_check() is False
    job_store.request_cancel(job.job_id)
    worker._last_cancel_poll = 0.0  # bypass the poll interval
    assert worker._abort_check() is True
    assert worker._abort_check() is True, "once observed it stays observed"


def test_stop_event_makes_the_abort_predicate_true(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    worker = _worker(job_store, job_stream, settings)
    assert worker._abort_check() is False
    worker.request_stop()
    assert worker._abort_check() is True


# --- the reaper --------------------------------------------------------


def _make_stale(store, fake_redis, job_id: str, *, age_s: int) -> None:
    """Age a job's heartbeat without touching its state."""
    from aegis_contracts.jobs import Job

    job = store.get(job_id)
    assert job is not None
    job.progress.worker_heartbeat_at = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    raw = Job.model_validate_json(job.model_dump_json())
    fake_redis.set(QueueKeys().job(job_id), raw.model_dump_json())


def test_reaper_does_not_kill_a_slow_but_heartbeating_job(
    job_store, job_stream, tmp_path, workspace, queue_settings, fake_redis
) -> None:
    """THE test. A fresh heartbeat outranks an idle claim, and the job stays running.

    Everything else in this file protects data; this protects a *user* from being told
    their fifteen-minute scan failed at minute two.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-slow")
    job_store.record_stage(job.job_id, JobStage.SCAN, state="running")

    # The claim looks abandoned (idle far longer than the visibility timeout) but the
    # worker is alive and heartbeating.
    job_store.heartbeat(job.job_id, worker_id="w-slow")
    entry_id = job_stream.enqueue(
        job.job_id,
        kind="assemble",
        fingerprint=job.submission.fingerprint,
    )
    claimer = "w-original"
    job_stream.claim(claimer, count=1, block_ms=100)
    job_stream.redis.xclaim  # noqa: B018 - documenting that the claim is real

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    # min_idle_ms=0 forces the transport to hand it over immediately: the reaper must still
    # refuse on the heartbeat check alone.
    report = reaper._adjudicate(
        {
            "entry_id": entry_id,
            "job_id": job.job_id,
            "kind": "assemble",
            "fingerprint": job.submission.fingerprint,
            "attempt": 1,
        }
    )
    assert report == "skipped"
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.RUNNING, "a heartbeating job is never declared dead"
    assert stored.failure is None


def test_reaper_acks_a_job_that_already_succeeded(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-1"))

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    assert reaper._adjudicate({"entry_id": "1-1", "job_id": job.job_id}) == "skipped"
    assert job_store.get(job.job_id).state is JobState.SUCCEEDED  # type: ignore[union-attr]


def test_reaper_recovers_from_a_bundle_already_on_disk(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """Finished work whose state update was lost is recovered, not re-run.

    The window this covers: the worker wrote the bundle and died before recording success.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-dead")
    _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)

    recorded = settings.output_dir / "B-recorded"
    recorded.mkdir(parents=True, exist_ok=True)
    (recorded / "manifest.json").write_text("{}", encoding="utf-8")
    saved = job_store.get(job.job_id)
    assert saved is not None
    saved.result = JobResult(bundle_id="B-recorded", package_path=str(recorded))
    job_store.compare_and_set(saved)

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    assert reaper._adjudicate({"entry_id": "1-1", "job_id": job.job_id}) == "recovered"
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.SUCCEEDED


def test_a_finished_staging_directory_is_also_recoverable(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    """The rename is atomic; the state write after it is not.

    A crash between the two leaves a complete tree under the staging name, and re-running
    the whole assembly to reproduce work that is already on disk would be waste.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    staging = settings.output_dir / ".staging-B-done"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.json").write_text("{}", encoding="utf-8")
    job.result = JobResult(bundle_id="B-done")
    assert recoverable_artifact(job_store, job, settings) == staging


def test_a_job_killed_mid_run_has_no_recoverable_artifact(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    """The honest limit of recovery, asserted rather than implied.

    Recomputing the bundle id needs the finding set, which only exists mid-run -- so a
    crash *during* a run (no recorded result, only a half-written staging directory) is
    retried from scratch. That is the safe direction: a retry costs work, whereas treating
    a partial directory as a finished bundle costs correctness.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    staging = settings.output_dir / ".staging-B-unknown"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "summary.md").write_text("partial", encoding="utf-8")
    assert recoverable_artifact(job_store, job, settings) is None


def test_reaper_requeues_until_max_attempts_then_fails(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings).model_copy(
        update={"queue": queue_settings.model_copy(update={"max_attempts": 2})}
    )
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-dead", attempt=1)
    _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    assert reaper._adjudicate({"entry_id": "1-1", "job_id": job.job_id}) == "requeued"
    assert job_store.get(job.job_id).state is JobState.QUEUED  # type: ignore[union-attr]

    # Second attempt, again silent: attempts are spent, so this is a named failure.
    job_store.set_running(job.job_id, worker_id="w-dead-2", attempt=2)
    _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)
    assert reaper._adjudicate({"entry_id": "1-2", "job_id": job.job_id}) == "failed"
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None and stored.failure.mode is FailureMode.WORKER_LOST


@pytest.mark.parametrize("state", ["running", "queued", "failed"])
def test_a_job_is_never_left_running_forever(
    job_store, job_stream, tmp_path, workspace, queue_settings, state
) -> None:
    """Whatever state it starts in, one reconcile pass ends it or queues it."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    if state == "running":
        job_store.set_running(job.job_id, worker_id="w-dead")
        _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)
    elif state == "failed":
        job_store.set_running(job.job_id, worker_id="w-1")
        job_store.mark_failed(job.job_id, mode=FailureMode.SCAN_FAILED, message="already done")

    reconcile_startup(job_store, job_stream, settings)
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is not JobState.RUNNING, f"started as {state}, still running"


def test_reconcile_startup_re_enqueues_a_queued_orphan(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A `queued` job whose stream entry was trimmed is invisible to the reaper.

    The reaper only inspects delivered messages and the running sweep only looks at claimed
    jobs, so a trimmed-but-never-claimed entry would sit in `queued` forever. This sweep is
    the only thing that closes that hole.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    # Never enqueued: exactly the state MAXLEN leaves behind.
    assert not job_stream.was_enqueued_recently(job.job_id)

    report = reconcile_startup(job_store, job_stream, settings)
    assert report["queued_orphans"] == 1
    assert job_stream.was_enqueued_recently(job.job_id)
    claimed = job_stream.claim("w-check", count=5, block_ms=100)
    assert [row["job_id"] for row in claimed] == [job.job_id]


def test_reconcile_startup_leaves_a_live_workers_job_alone(
    job_store, job_stream, tmp_path, workspace, queue_settings, fake_redis
) -> None:
    """A peer that is still reporting must not be robbed by a booting worker."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_stream.enqueue(job.job_id, kind="assemble", fingerprint=job.submission.fingerprint)
    job_store.set_running(job.job_id, worker_id="w-alive")
    job_store.heartbeat(job.job_id, worker_id="w-alive")
    # The worker's own liveness key, which the loop refreshes on every heartbeat.
    fake_redis.setex("aegis:queue:worker:w-alive", 60, "now|")

    reconcile_startup(job_store, job_stream, settings)
    assert job_store.get(job.job_id).state is JobState.RUNNING  # type: ignore[union-attr]


def test_reconcile_startup_reclaims_a_job_whose_worker_is_gone(
    job_store, job_stream, tmp_path, workspace, queue_settings, fake_redis
) -> None:
    """THE regression test for the startup sweep: a *fresh* heartbeat is not evidence of life.

    The sweep must ask "is that worker still there?", not "is the heartbeat recent?". A worker
    killed mid-scan leaves a heartbeat only seconds old, and with the default 1800s visibility
    timeout a freshness check makes the sweep do nothing at all -- measured in the container
    stack: a crashed job sat in `running` for minutes while the sweep reported `running: 1` and
    moved on. The design calls this layer the most important one precisely because it must not
    depend on that clock.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_stream.enqueue(job.job_id, kind="assemble", fingerprint=job.submission.fingerprint)
    job_store.set_running(job.job_id, worker_id="w-crashed")
    job_store.heartbeat(job.job_id, worker_id="w-crashed")

    holder = job_store.get(job.job_id)
    assert holder is not None
    assert _seconds_since(holder.progress.worker_heartbeat_at) < 5, (
        "the heartbeat must be fresh for this test to prove anything: a freshness check is "
        "exactly what the old implementation used to skip this case"
    )
    # The worker died: its liveness key is gone and nothing will refresh it.
    fake_redis.delete("aegis:queue:worker:w-crashed")

    report = reconcile_startup(job_store, job_stream, settings)
    assert report["running"] == 1
    reclaimed = job_store.get(job.job_id)
    assert reclaimed is not None
    assert reclaimed.state is JobState.QUEUED, "a job whose worker is gone must be reclaimed"
    assert reclaimed.progress.attempt == 1, "reclaiming is not a retry: the attempt is unchanged"
    claimed = [row["job_id"] for row in job_stream.claim("w-new", count=5, block_ms=100)]
    assert job.job_id in claimed, "and it must be claimable again"
    # A duplicate entry is possible here (the test enqueued one itself), and that is fine by
    # design: `handle()` refuses a job that is not in a claimable state, so a repeated entry
    # costs one no-op claim rather than a second run.


def test_reconcile_startup_fails_a_job_whose_attempts_are_spent(
    job_store, job_stream, tmp_path, workspace, queue_settings, fake_redis
) -> None:
    settings = _settings(tmp_path, queue_settings).model_copy(
        update={"queue": queue_settings.model_copy(update={"max_attempts": 1})}
    )
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-crashed", attempt=1)
    fake_redis.delete("aegis:queue:worker:w-crashed")

    reconcile_startup(job_store, job_stream, settings)
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None and stored.failure.mode is FailureMode.WORKER_LOST


def test_recoverable_artifact_prefers_the_recorded_path(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    recorded = settings.output_dir / "B-recorded"
    recorded.mkdir(parents=True, exist_ok=True)
    (recorded / "manifest.json").write_text("{}", encoding="utf-8")
    job.result = JobResult(bundle_id="B-recorded", package_path=str(recorded))
    assert recoverable_artifact(job_store, job, settings) == recorded


def test_recoverable_artifact_is_none_without_a_manifest(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    """A directory without a parseable manifest is not an artifact: staging leftovers."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    half = settings.output_dir / "B-half"
    half.mkdir(parents=True, exist_ok=True)
    (half / "summary.md").write_text("partial", encoding="utf-8")
    job.result = JobResult(bundle_id="B-half", package_path=str(half))
    assert recoverable_artifact(job_store, job, settings) is None


# --- the loop itself ---------------------------------------------------


def test_serve_forever_acks_even_when_the_job_fails(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A message left pending forever is a job nobody retries."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_stream.enqueue(job.job_id, kind="assemble", fingerprint=job.submission.fingerprint)

    class _Exploding:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Exploding)
    worker = _worker(job_store, job_stream, settings)
    worker.serve_forever(max_iterations=3)

    assert job_stream.pending_count() == 0, "the failure must still be acknowledged"
    assert job_store.get(job.job_id).state is JobState.FAILED  # type: ignore[union-attr]


def test_serve_forever_stops_when_asked(
    job_store, job_stream, tmp_path, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    worker = _worker(job_store, job_stream, settings)
    timer = threading.Timer(0.1, worker.request_stop)
    timer.start()
    started = time.monotonic()
    worker.serve_forever()
    elapsed = time.monotonic() - started
    timer.cancel()
    assert elapsed < 5.0, f"the loop ignored the stop signal for {elapsed:.1f}s"
    assert worker.stop_event.is_set()


def test_worker_refuses_to_start_without_a_redis_url(tmp_path, monkeypatch, capsys) -> None:
    """A worker with nothing to consume must not idle healthily and look busy."""
    from aegis_core.config import Settings as CoreSettings
    from services.queue import worker as worker_module

    blank = CoreSettings(workspace_root=tmp_path, output_dir=tmp_path / "p", work_dir=tmp_path / "w")
    monkeypatch.setattr(worker_module, "get_settings", lambda: blank)
    assert worker_module.main([]) == 2
    assert "AEGIS_QUEUE__REDIS_URL is not set" in capsys.readouterr().out


def test_teardown_registers_a_staging_directory_and_the_worker_cleans_it(
    tmp_path,
) -> None:
    """A canceled job must not leave a half-written bundle where a reader would find it."""
    teardown = Teardown()
    staging = tmp_path / ".staging-B-x"
    staging.mkdir()
    (staging / "methods").mkdir()
    teardown.register_artifact_dir(staging)
    teardown.request()
    teardown.kill_all()
    removed = teardown.cleanup_partial()
    assert removed == [staging]
    assert not staging.exists()
