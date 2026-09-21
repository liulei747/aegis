"""The worker's main loop: claim a job, run the pipeline in-process, report honestly.

Two design decisions here are the difference between a queue and a queue that lies:

**Extraction runs in this process, not over HTTP to the `extract` container.** Delegating
would cost three things at once, and each is fatal on its own: the gateway's HTTP call
blocks for up to 30 minutes so this loop could not heartbeat (the reaper would then
declare a healthy job dead), `services/extraction/routes.py` exposes no progress or cancel
channel (so stage progress collapses to two coarse phases and a cancel becomes impossible),
and the handle to the language servers would live in another container. `extract` remains
the entry point for *synchronous* callers; the worker is a second caller of the same code,
not a second implementation.

**`queued -> running` is written before the pipeline starts, and the stage is pinned to
`scan`.** The scan stage is the one stage that emits nothing while it runs -- it is a
synchronous subprocess wait -- so a job that only marked itself running on the first event
would appear stuck in `queued` for up to 900 seconds. Writing that snapshot first is what
makes "it is scanning" visible instead of "nothing is happening".
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from aegis_contracts.jobs import (
    STAGE_DONE,
    STAGE_SKIPPED,
    TERMINAL_STATES,
    ArtifactRef,
    FailureMode,
    Job,
    JobKind,
    JobResult,
    JobStage,
    first_stage,
)
from aegis_core.cancel import CanceledAbort
from aegis_core.config import BudgetConfig, Settings, get_settings
from aegis_core.logging import get_logger, setup_logging
from services.ai.runner import analyse_bundle, write_report
from services.extraction.pipeline.assemble import (
    AssemblyPipeline,
    PipelineRequest,
    ScanOnlyPipeline,
    StageEvent,
)
from services.queue.cancel import Teardown
from services.queue.jobs import JobStore
from services.queue.reaper import Reaper, stage_from_name
from services.queue.streams import JobStream, consumer_name

log = get_logger(__name__)

#: A job's stage name is the pipeline's, so the observer's stage string maps 1:1 onto the
#: contract's enum. Kept as a lookup rather than a cast so an unexpected name is visible.
_STAGES = {stage.value: stage for stage in JobStage}

#: The harness phases, in Chinese, for the job's single `ai` stage note. The job contract carries
#: one AI stage -- an audit is that stage -- so these are what tell a reader *inside* it what is
#: happening: "正在验证候选 12/56" is the difference between a job that is working and one that is
#: stuck. Unknown names fall back to the raw id, so a new phase shows up rather than showing blank.
_AUDIT_STAGE_LABEL = {
    "prep": "结构勘察",
    "security_inventory": "AI 安全清单",
    "recon": "勘察仓库",
    "threat_model": "建立威胁模型",
    "plan": "规划调查范围",
    "discovery": "探索代码",
    "validation": "验证候选",
    "attack_path": "推导攻击路径",
    "findings": "汇总发现",
    "close": "收尾",
}


class Worker:
    """One consumer of the job stream. There may be several; none of them coordinate."""

    def __init__(
        self,
        store: JobStore,
        stream: JobStream,
        settings: Settings,
        *,
        worker_id: str | None = None,
    ) -> None:
        self.store = store
        self.stream = stream
        self.settings = settings
        self.worker_id = worker_id or consumer_name()
        self.stop_event = threading.Event()
        self._cancel_watch = threading.Event()
        self._current_job: str | None = None
        self._current_stage: str = JobStage.SCAN.value
        self._lock = threading.Lock()
        self._last_heartbeat = 0.0
        self._last_reap = 0.0
        self._poisoned = False
        self.reaper = Reaper(store, stream, settings, worker_id=self.worker_id)

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def request_stop(self, *_args) -> None:
        """Signal handler. Sets the flag and nothing else -- no I/O in a handler.

        Draining happens in the loop, which is also watching this job's abort predicate, so
        a shutdown reaches a running job through exactly the same path a cancel does.
        """
        self.stop_event.set()
        self._cancel_watch.set()

    def install_signal_handlers(self) -> None:
        for name in ("SIGTERM", "SIGINT"):
            sig = getattr(signal, name, None)
            if sig is not None:
                try:
                    signal.signal(sig, self.request_stop)
                except ValueError:  # pragma: no cover - not the main thread
                    log.debug("cannot install %s handler outside the main thread", name)

    def serve_forever(self, *, max_iterations: int | None = None) -> None:
        """Claim and run until stopped. `max_iterations` exists for tests."""
        iterations = 0
        log.info("worker %s ready (group=%s)", self.worker_id, self.stream.group)
        while not self.stop_event.is_set() and not self._poisoned:
            iterations += 1
            if max_iterations is not None and iterations > max_iterations:
                break
            try:
                self._maybe_reap()
                self._maybe_heartbeat()
                entries = self.stream.claim(self.worker_id, count=1)
            except Exception as exc:  # Redis unreachable: back off, do not die
                log.error("worker loop could not reach the queue: %s", exc)
                self._sleep_interruptibly(5.0)
                continue
            if not entries:
                continue
            entry = entries[0]
            try:
                self.handle(entry)
            finally:
                # Always ACK: a message left pending forever is a job nobody will retry,
                # and the retry decision belongs to the reaper, not to the transport.
                try:
                    self.stream.ack(entry["entry_id"])
                except Exception:  # pragma: no cover - Redis trouble
                    log.error("failed to ACK %s", entry["entry_id"], exc_info=True)

    # ------------------------------------------------------------------
    # one job
    # ------------------------------------------------------------------
    def handle(self, entry: dict) -> None:
        job_id = entry["job_id"]
        job = self.store.get(job_id)
        if job is None:
            log.warning("job %s vanished (expired?) before it ran", job_id)
            return
        if job.state in TERMINAL_STATES:
            # Redelivery of finished work: the same job_id can arrive twice (reaper
            # re-enqueue, MAXLEN survivors). Re-running it would be pure waste.
            log.info("job %s is already %s; nothing to do", job_id, job.state.value)
            return
        if job.cancel_requested:
            # Cancelled while queued: never start it.
            self.store.mark_canceled(job_id, note="启动前已取消")
            return

        attempt = entry.get("attempt") or 1
        with self._lock:
            self._current_job = job_id
            self._current_stage = first_stage(job.kind).value
        self._cancel_watch.clear()

        teardown = Teardown(reason="cancel")
        try:
            claimed = self.store.set_running(job_id, worker_id=self.worker_id, attempt=attempt)
            if claimed is None:
                log.warning("job %s disappeared between read and claim", job_id)
                return
            if claimed.state in TERMINAL_STATES:
                return

            # Pin the stage before the first silent one: the scan emits nothing while it
            # runs, so this snapshot is the only "it is scanning" the user can see. An AI job
            # has the same problem with its model calls, and the same answer.
            opening = first_stage(claimed.kind)
            self._current_stage = opening.value
            self.store.pin_stage(
                job_id, opening, note="扫描中" if opening is JobStage.SCAN else opening.value
            )
            teardown.begin()

            result = self._run(claimed, teardown)
            self.store.mark_succeeded(job_id, result=result)
            log.info("job %s succeeded (%s)", job_id, result.bundle_id)

        except CanceledAbort as exc:
            # Must precede `except Exception`: CanceledAbort is a BaseException, so the
            # order is already safe, but stating it keeps the intent visible.
            self._finish_canceled(job_id, exc, teardown)
        except Exception as exc:
            log.exception("job %s failed", job_id)
            self.store.mark_failed(
                job_id,
                mode=_mode_for(exc),
                message=str(exc) or exc.__class__.__name__,
                detail=repr(exc),
                recoverable=True,
            )
        finally:
            with self._lock:
                self._current_job = None
            self._cancel_watch.clear()

    def _run(self, job: Job, teardown: Teardown) -> JobResult:
        request = job.submission.request
        if job.kind is JobKind.AI_FANOUT:
            return self._run_ai_fanout(job)
        if job.kind is JobKind.AUDIT:
            return self._run_audit(job)

        workspace = Path(request.workspace).expanduser()
        if not workspace.is_dir():
            raise _JobRefused(
                FailureMode.WORKSPACE_MISSING, f"工作区不是目录：{workspace}"
            )
        sarif_path = Path(request.sarif_path) if request.sarif_path else None
        if sarif_path is not None and not sarif_path.is_file():
            raise _JobRefused(FailureMode.SARIF_MISSING, f"未找到 SARIF：{sarif_path}")

        budget = BudgetConfig(**request.budget) if request.budget else self.settings.budget
        pipeline_request = PipelineRequest(
            workspace=workspace,
            sarif_path=sarif_path,
            rules=request.rules,
            rule_config=request.rule_config,
            include_globs=request.include_globs,
            exclude_globs=request.exclude_globs,
            budget=budget,
            max_findings=request.max_findings,
            lsp=request.lsp,
            package_name=request.package_name,
        )

        if job.kind is JobKind.SCAN:
            return self._run_scan_only(pipeline_request)

        pipeline = AssemblyPipeline(self.settings)
        outcome = _run_async(
            pipeline.run(
                pipeline_request,
                observer=self._on_event,
                abort=self._abort_check,
                teardown=teardown,
                staging=True,
            )
        )
        if outcome.bundle is None or outcome.package_path is None:  # pragma: no cover
            raise RuntimeError("流水线未产出分析包")
        manifest = outcome.bundle.manifest
        return JobResult(
            bundle_id=manifest.bundle_id,
            package_path=str(outcome.package_path),
            run_id=outcome.run_id,
            sarif_path=str(outcome.sarif_path) if outcome.sarif_path else None,
            scan_record=outcome.scan_record,
            warnings=list(outcome.warnings),
            artifacts={
                "bundle": {
                    "kind": "bundle",
                    "ref": manifest.bundle_id,
                    "path": str(outcome.package_path),
                    "available": True,
                }
            },
        )

    def _run_ai_fanout(self, job: Job) -> JobResult:
        """Analyse an already-finished bundle with the model.

        This job *consumes* a bundle instead of producing one, which is why it needs
        `bundle_id`: `workspace` alone does not say which artifact to read.

        A model failure never fails the job *on its own*: the verdicts are an addition to a bundle
        that was already complete and already useful, so a partial result is reported through
        `warnings` -- "1 of 3 contexts answered" belongs in the record, not in an exception that
        would throw away the contexts that did answer.

        But if **every** call failed, the job has produced nothing, and reporting `succeeded`
        would be a false success twice over: the caller would believe the analysis ran, and
        request deduplication would refuse to retry it. Measured on the live stack -- a job whose
        only context failed to parse reported `succeeded`, and resubmitting returned that same
        useless job with a 200 instead of doing the work.
        """
        request = job.submission.request
        if not request.bundle_id:
            raise _JobRefused(
                FailureMode.AI_BUNDLE_MISSING,
                "ai_fanout 任务需要 bundle_id：要分析的分析包",
            )
        bundle = self.settings.output_dir / request.bundle_id
        if not (bundle / "ai" / "blocks.jsonl").is_file():
            raise _JobRefused(
                FailureMode.AI_BUNDLE_MISSING,
                f"未找到包含 AI 块的分析包：{bundle}",
            )

        config = self.settings.ai
        report = analyse_bundle(bundle, config)
        warnings: list[str] = []
        # Close the stage out with an outcome, not just the "running" pin set before the call:
        # `pin_stage` says a stage is current, `record_stage` says what it produced. Without this
        # the job's stage list would show `ai` stuck at running on a job that had succeeded.
        #
        # A disabled stage is `skipped`, not `running`: nothing is in flight, and the note says
        # why -- the same vocabulary the rest of the job record uses.
        self.store.record_stage(
            job.job_id,
            JobStage.AI,
            state=STAGE_SKIPPED if report.skipped else STAGE_DONE,
            note=(
                f"已跳过：{report.skipped}"
                if report.skipped
                else f"已研判 {len(report.parsed_calls)}/{len(report.calls)} 个上下文"
            ),
            units_done=len(report.parsed_calls),
            units_total=len(report.calls),
            unit_label="上下文",
        )
        if report.skipped:
            warnings.append(f"AI 阶段未运行：{report.skipped}")
        else:
            write_report(bundle, report)
            failed = report.failed_calls
            if failed and not report.parsed_calls:
                reasons = "; ".join(
                    f"{call.context_id or 'bundle'}: {call.error}" for call in failed[:3]
                )
                raise _JobRefused(
                    FailureMode.AI_FAILED,
                    f"全部 {len(failed)} 个上下文调用失败：{reasons}",
                )
            if failed:
                warnings.append(
                    f"{len(failed)}/{len(report.calls)} 个上下文调用未产出可用的研判结论；"
                    "它们的原始回答在 ai/answers/ 中，原因在 ai/report.json 中"
                )
        return JobResult(
            bundle_id=request.bundle_id,
            package_path=str(bundle),
            warnings=warnings,
            artifacts={
                "verdicts": {
                    "kind": "ai_verdicts",
                    "ref": request.bundle_id,
                    "path": str(bundle / "ai" / "verdicts.jsonl"),
                    "available": not report.skipped,
                }
            },
        )

    def _run_audit(self, job: Job) -> JobResult:
        """Run the agent harness over a repository, as a job the console can watch.

        Three decisions worth stating, because each one has a failure mode behind it:

        * **The run directory is under `work_dir`, not under the workspace.** The workspace is
          mounted read-only in every container, and the gateway has to be able to read the trail to
          serve it. `work_dir` is the one path the gateway, the worker and the extractor all mount
          at the same place, which is the same reason SARIF lives there.
        * **The trail's second sink writes job progress.** The JSONL is the detailed record the
          console polls; the callback mirror is what makes `/v1/jobs/{id}` show a moving stage
          without the console having to parse the trail to render a progress bar. Every write goes
          through `record_stage`, which already ignores terminal jobs and swallows Redis trouble --
          a progress write must never sink a run.
        * **The abort predicate is `_abort_check`.** Without it, cancelling an audit would do
          nothing until the run ended by itself: the coordinator checks between agent runs, so a
          cancel lands within one agent (measured at 1-3 minutes on the Java benchmark) instead of
          in the 30 the whole run takes.
        """
        from services.ai.runner import AINotConfigured, client_from
        from services.harness import trail as trail_mod
        from services.harness.coordinator import HarnessCoordinator

        request = job.submission.request
        workspace = Path(request.workspace).expanduser()
        if not workspace.is_dir():
            raise _JobRefused(FailureMode.WORKSPACE_MISSING, f"工作区不是目录：{workspace}")
        try:
            client = client_from(self.settings.ai)
        except AINotConfigured as exc:
            # A refusal, not a crash: the operator has one environment variable to set, and the
            # message has to name it rather than failing 40 minutes later with no findings.
            raise _JobRefused(FailureMode.AI_FAILED, f"AI 审计未配置：{exc}") from exc

        run_root = self.settings.work_dir / "audit"
        coordinator = HarnessCoordinator(
            workspace=workspace,
            config=self._audit_config(),
            client=client,
            out_dir=run_root,
            run_id=job.job_id,
            abort=self._abort_check,
        )
        self.store.record_stage(
            job.job_id, JobStage.AI, state="running", note="AI 审计：正在做仓库勘察",
        )
        trail = coordinator.attach_trail(
            trail_mod.CallbackSink(lambda event: self._audit_event(job.job_id, event))
        )
        try:
            result = coordinator.run()
        finally:
            # Closed on every path, including a cancel: the trail is the only record a killed run
            # leaves, so the handle must not be skipped by the exception that made it matter.
            trail.close()

        run_dir = result.run_dir
        trail_path = run_dir / trail_mod.TRAIL_NAME
        report_path = result.report_path
        warnings = list(result.notes)
        if result.fatal:
            warnings.append(result.fatal)
        counts = trail.counters(result.blackboard)
        incomplete = sum(
            item.state.value not in {"done", "canceled"}
            for item in result.blackboard.work
        )
        # The terminal stage write is inside `_audit_event`/`_finish` already, but the *summary* is
        # the one place that knows the run is over and what it produced, so it is written here
        # rather than inferred from the last stage event.
        self.store.record_stage(
            job.job_id,
            JobStage.AI,
            state=STAGE_DONE if not result.fatal else "failed",
            note=(
                f"AI 审计结束：{counts.get('scopes', 0)} 个 scope、"
                f"{counts.get('candidates', 0)} 个候选、{counts.get('findings', 0)} 条发现"
                + (f"；{incomplete} 项任务未完成" if incomplete else "；覆盖任务已完成")
            ),
            units_done=counts.get("scopes", 0),
            units_total=counts.get("scopes", 0),
            unit_label="scope",
            counters={
                "candidates": counts.get("candidates", 0),
                "verdicts": counts.get("verdicts", 0),
                "confirmed": counts.get("confirmed", 0),
                "findings": counts.get("findings", 0),
                "agent_runs": counts.get("agent_runs", 0),
                "rounds": counts.get("rounds", 0),
            },
        )
        if result.fatal:
            raise _JobRefused(FailureMode.AI_FAILED, result.fatal)
        if incomplete:
            warnings.append(
                f"审计结果不完整：仍有 {incomplete} 项任务未完成；"
                "不能把当前 0 条发现解释为项目没有漏洞，详情见任务清单和覆盖表"
            )
        elif not result.blackboard.closed:
            warnings.append("审计没有正常收敛关闭；见报告里的关闭说明与覆盖表")

        return JobResult(
            run_id=result.blackboard.run_id,
            package_path=str(run_dir),
            warnings=warnings,
            artifacts={
                "audit_trail": ArtifactRef(
                    kind="audit_trail",
                    ref=job.job_id,
                    path=str(trail_path),
                    available=trail_path.is_file(),
                ),
                "audit_report": ArtifactRef(
                    kind="audit_report",
                    ref=job.job_id,
                    path=str(report_path) if report_path else None,
                    available=bool(report_path and report_path.is_file()),
                ),
            },
        )

    def _audit_config(self):
        """The harness bounds for a queued audit.

        Only the model concurrency is taken from settings; the rest keep the harness defaults,
        because they are the bounds the Java benchmark was measured with and a job that quietly
        used different ones would produce a different answer from the CLI run of the same command.

        One exception, and it is named rather than hidden: `AEGIS_HARNESS_CLAIM_BATCH_SIZE` lets a
        deployment judge several *different* claims in one run, in validation and in the attack-path
        stage. `1` (the default) is the historical behaviour. Measured on `upp-module-infra`: 139
        validation runs decided 98 claims at 196 s each -- 110 of the run's 274 minutes -- with
        `FileController.java` alone read 261 times, plus 72 attack-path runs for 161 confirmed
        candidates; file-overlap packing alone takes those 98 claims to ~44 runs, and every claim still
        gets its own verdict. It is off by default because it changes what a judging run is.
        """
        from services.harness.budget import environment_limits
        from services.harness.coordinator import HarnessConfig

        raw = os.environ.get("AEGIS_HARNESS_CLAIM_BATCH_SIZE", "").strip()
        try:
            batch_size = int(raw) if raw else 1
        except ValueError:
            log.warning(
                "worker: AEGIS_HARNESS_CLAIM_BATCH_SIZE=%r is not an integer; using 1", raw
            )
            batch_size = 1
        return HarnessConfig(
            concurrency=max(1, self.settings.ai.concurrency),
            claim_batch_size=max(1, batch_size),
            **environment_limits(),
        )

    def _audit_event(self, job_id: str, event: dict) -> None:
        """Mirror one trail event into the job's record -- coarsely, on purpose.

        The trail is where the detail lives; this is a progress bar. It writes only on the events
        that change what a reader sees (`stage`, and the ledger counts when a stage ends), so a run
        with 4000 tool calls does not become 4000 Redis writes.
        """
        kind = event.get("kind")
        if kind == "stage":
            stage = event.get("stage", "")
            state = event.get("state", "")
            counters = event.get("counters") or {}
            self.store.record_stage(
                job_id,
                JobStage.AI,
                state="running",
                note=f"{_AUDIT_STAGE_LABEL.get(stage, stage)}"
                + (f"（第 {event['round']} 轮）" if event.get("round") is not None else "")
                + ("" if state != "start" else "…"),
                # The counters ride along on every stage event, because this is what a reader
                # watching `/v1/jobs/{id}` sees. Without them the job page showed zero candidates
                # for the whole run while the trail already held thirty -- measured on the first
                # real audit, which is the only way that gap was ever going to be noticed.
                units_done=counters.get("scopes", 0),
                unit_label="scope",
                counters={
                    key: counters.get(key, 0)
                    for key in ("candidates", "verdicts", "confirmed", "findings", "agent_runs", "rounds")
                },
            )
            return
        if kind == "summary":
            counters = event.get("counters") or {}
            phase = event.get("phase")
            self.store.record_stage(
                job_id,
                JobStage.AI,
                state="running",
                note=(
                    str(event.get("note") or "AI 安全清单完成")
                    if phase == "security_inventory"
                    else "AI 审计：正在写报告"
                ),
                # No total here on purpose: the plan's scope count is not in the run's counters, and
                # `units_done == units_total` would draw a progress bar that is always full -- a
                # fabricated 100%. `formatUnits` says "总数未知" instead, which is true.
                units_done=counters.get("scopes", 0),
                unit_label="scope",
                counters={
                    key: counters.get(key, 0)
                    for key in ("candidates", "verdicts", "confirmed", "findings", "agent_runs", "rounds")
                },
            )
            return
        if kind == "error":
            log.warning("audit %s: %s", job_id, event.get("message") or event)

    def _run_scan_only(self, pipeline_request: PipelineRequest) -> JobResult:
        """A scan job: findings and a ledger, no bundle.

        Runs `ScanOnlyPipeline` rather than calling `run_scan` directly so the job inherits
        the existing semantics of `run_id`, `sarif_path` and `warnings` -- the same reason
        the synchronous `/v1/scan` route uses it.
        """
        result = ScanOnlyPipeline(self.settings).run(pipeline_request)
        return JobResult(
            bundle_id=None,
            run_id=result.run_id,
            sarif_path=str(result.sarif_path) if result.sarif_path else None,
            scan_record=result.scan_record,
            warnings=list(result.warnings),
        )

    # ------------------------------------------------------------------
    # progress
    # ------------------------------------------------------------------
    def _on_event(self, event: StageEvent) -> None:
        """Turn one pipeline event into one durable state write.

        The observer runs on the pipeline's thread, which is the same thread the loop runs
        on, so there is no cross-thread write here. If that ever changes, this becomes the
        place to hand events to a queue instead.
        """
        with self._lock:
            job_id, self._current_stage = self._current_job, event.stage
        if job_id is None:  # pragma: no cover - an event without a job cannot happen
            return
        stage = _STAGES.get(event.stage)
        if stage is None:  # pragma: no cover - the pipeline's vocabulary is fixed
            return
        try:
            if event.phase == "start":
                self.store.record_stage(job_id, stage, state="running", note=event.note)
            else:
                self.store.record_stage(
                    job_id,
                    stage,
                    state="done",
                    duration_ms=event.ms,
                    note=event.note,
                    counters=event.counters,
                    units_done=event.units_done,
                    units_total=event.units_total,
                    unit_label=event.unit_label,
                )
        except Exception:  # a progress write must never sink a run
            log.error("failed to record stage %s for %s", event.stage, job_id, exc_info=True)

    def _abort_check(self) -> bool:
        """The predicate the pipeline polls. Cheap, and includes a queued cancel request.

        Deliberately not one Redis round trip per poll: the local flag covers shutdown and
        any cancel this worker accepted, and the durable `cancel_requested` is consulted on
        a short interval rather than continuously. A missed poll costs one interval of
        latency; polling Redis from inside a scan loop would cost the scan.
        """
        if self._cancel_watch.is_set():
            return True
        now = time.monotonic()
        if now - getattr(self, "_last_cancel_poll", 0.0) < 1.0:
            return False
        self._last_cancel_poll = now
        job_id = self._current_job
        if job_id is None:
            return False
        try:
            job = self.store.get(job_id)
        except Exception:  # pragma: no cover - Redis trouble must not abort a run
            return False
        if job is not None and job.cancel_requested:
            self._cancel_watch.set()
            return True
        return False

    def _finish_canceled(self, job_id: str, exc: CanceledAbort, teardown: Teardown) -> None:
        """Terminal state for an interrupted run. Two different endings, same mechanism.

        A shutdown returns the job to the queue (the user still wants it); a cancel marks
        it canceled (the user does not). Recording a shutdown as a cancellation would be
        telling the user they asked for something they did not.
        """
        teardown.kill_all(
            terminate_grace_s=self.settings.queue.cancel_terminate_grace_s,
            kill_grace_s=self.settings.queue.cancel_kill_grace_s,
        )
        teardown.cleanup_partial()
        detail = f"在 {exc.stage} 阶段已取消（{exc.resource}）" + (
            f"：{exc.detail}" if exc.detail else ""
        )
        if self.stop_event.is_set():
            self.store.requeue(job_id, note="worker 正在重启；任务已退回队列")
            self._reenqueue(job_id)
            log.info("job %s returned to the queue for a restart", job_id)
            return
        # The exception is the more accurate witness of where the run stopped: the pipeline
        # can raise from inside a stage before it has had a chance to report that stage.
        self.store.mark_canceled(job_id, note=detail, stage=stage_from_name(exc.stage))
        log.info("job %s canceled at %s", job_id, exc.stage)

    def _reenqueue(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None:  # pragma: no cover - it was just written
            return
        try:
            self.stream.ensure_group()
            self.stream.enqueue(
                job_id,
                kind=job.submission.kind.value,
                fingerprint=job.submission.fingerprint,
                attempt=job.progress.attempt,
                submitted_at=job.submission.submitted_at,
            )
        except Exception:  # pragma: no cover - Redis trouble
            log.error("failed to re-enqueue %s", job_id, exc_info=True)

    # ------------------------------------------------------------------
    # periodic work
    # ------------------------------------------------------------------
    def _maybe_heartbeat(self) -> None:
        interval = self.settings.queue.heartbeat_interval_s
        now = time.monotonic()
        if now - self._last_heartbeat < interval:
            return
        self._last_heartbeat = now
        with self._lock:
            job_id = self._current_job
            stage = _STAGES.get(self._current_stage)
        if job_id is not None:
            try:
                self.store.heartbeat(job_id, worker_id=self.worker_id, stage=stage)
            except Exception:  # pragma: no cover - Redis trouble
                log.error("heartbeat failed for %s", job_id, exc_info=True)
        try:
            self.stream.redis.setex(
                f"aegis:queue:worker:{self.worker_id}",
                max(interval * 4, 60),
                f"{datetime.now(timezone.utc).isoformat()}|{job_id or ''}",
            )
        except Exception:  # pragma: no cover - Redis trouble
            pass

    def _maybe_reap(self) -> None:
        interval = self.settings.queue.reaper_interval_s
        now = time.monotonic()
        if now - self._last_reap < interval:
            return
        self._last_reap = now
        try:
            self.reaper.reap_once()
        except Exception:  # pragma: no cover - the reaper must never kill the worker
            log.error("reaper pass failed", exc_info=True)

    def _sleep_interruptibly(self, seconds: float) -> None:
        self.stop_event.wait(seconds)


class _JobRefused(Exception):
    """A pre-flight refusal with a mode already chosen. Not a crash: a diagnosis."""

    def __init__(self, mode: FailureMode, message: str) -> None:
        super().__init__(message)
        self.mode = mode


def _mode_for(exc: Exception) -> FailureMode:
    if isinstance(exc, _JobRefused):
        return exc.mode
    if isinstance(exc, NotImplementedError):
        return FailureMode.INTERNAL_ERROR
    return FailureMode.PIPELINE_EXCEPTION


def _run_async(coro):
    """Run the pipeline's coroutine to completion from this synchronous loop."""
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Already inside a loop (tests, or a future async worker): use a private one.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def main(argv: list[str] | None = None) -> int:
    """Entry point for `aegis-worker`.

    Refusing to start without a Redis URL is deliberate: a worker with nothing to consume
    would idle healthily forever while operators assume jobs are being processed.
    """
    import argparse

    import redis

    parser = argparse.ArgumentParser(prog="aegis-worker", description="Aegis job worker")
    parser.add_argument("--once", action="store_true", help="run one claim cycle and exit")
    parser.add_argument("--no-reap", action="store_true", help="skip the periodic reaper")
    args = parser.parse_args(argv)

    setup_logging(get_settings().log_level)
    settings = get_settings()
    if settings.queue.redis_url is None:
        print(
            "AEGIS_QUEUE__REDIS_URL is not set: there is no queue to consume.\n"
            "Set it (e.g. redis://redis:6379/0) or use the synchronous API instead.",
            flush=True,
        )
        return 2

    client = redis.Redis.from_url(settings.queue.redis_url)
    from services.queue.keys import QueueKeys

    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    store = JobStore(client, settings.queue, keys=keys)
    stream = JobStream(client, settings.queue, keys=keys)
    stream.ensure_group()
    worker = Worker(store, stream, settings)
    worker.install_signal_handlers()
    if args.no_reap:
        worker.reaper.enabled = False

    # Layer 1 of crash recovery: anything left `running` by a dead worker is dealt with
    # before this one claims new work, so a restart is enough to clear the state even when
    # the visibility timeout has not elapsed.
    report = store.reconcile_startup(stream, settings)
    log.info("startup reconcile: %s", report)

    if args.once:
        entries = stream.claim(worker.worker_id, count=1, block_ms=settings.queue.block_ms)
        if entries:
            worker.handle(entries[0])
            stream.ack(entries[0]["entry_id"])
        return 0

    worker.serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(main())
