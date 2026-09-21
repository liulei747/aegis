"""Lifecycle of the coordinator's existing work items; the trail is a read-only projection.

One batch model run may serve several tasks. Attempts belong to each task, while completion
comes from that task's own coverage decision, verdict or attack-path result, never the batch end.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from aegis_contracts.harness import (
    Blackboard,
    WorkAttempt,
    WorkItem,
    WorkItemState,
)
from services.harness import blackboard as bb
from services.harness.trail import Trail


def now():
    return datetime.now(timezone.utc)


def explain_failure(error: str, stop_reason: str) -> str:
    """Turn an agent's raw failure into a task-level reason a user can act on.

    The raw value is still retained on ``WorkAttempt.error`` for diagnostics.  This
    sentence is the operational explanation shown in the task list.
    """
    detail = (error or "").strip()
    lowered = detail.lower()
    if "unexpected_eof_while_reading" in lowered or "ssl" in lowered and "eof" in lowered:
        return f"模型服务的 HTTPS/TLS 连接被提前关闭；本任务可重试。具体错误：{detail}"
    if "aiunavailable" in lowered or "model call failed" in lowered:
        return f"模型服务不可用，Agent 无法继续分析；本任务可重试。具体错误：{detail}"
    if stop_reason == "budget":
        return f"本轮执行预算已耗尽，任务尚未完成。{('具体错误：' + detail) if detail else ''}"
    if stop_reason == "aborted":
        return f"审计被取消，任务未完成。{('具体原因：' + detail) if detail else ''}"
    if detail:
        return f"Agent 执行失败，任务未完成。具体错误：{detail}"
    return f"Agent 未正常完成（stop_reason={stop_reason or 'unknown'}），没有返回具体错误"


class TaskLedger:
    def __init__(self, board: Blackboard, trail: Trail):
        self.board = board
        self.trail = trail
        self.lock = threading.RLock()

    def _emit(self, item: WorkItem) -> None:
        self.board.revision += 1
        self.board.updated_at = now()
        self.trail.emit("work_item", scope=item.scope_id, work=item.model_dump(mode="json"))

    def get(self, work_id: str) -> WorkItem | None:
        return next((item for item in self.board.work if item.work_id == work_id), None)

    def add(self, item: WorkItem) -> WorkItem:
        with self.lock:
            existing = self.get(item.work_id)
            if existing is not None:
                return existing
            bb.add_work(self.board, [item])
            self._emit(item)
            return item

    def update(self, work_id: str, **fields) -> None:
        with self.lock:
            item = self.get(work_id)
            if item is None:
                return
            for name, value in fields.items():
                setattr(item, name, value)
            if "state" in fields:
                item.closed_at = (
                    now()
                    if item.state
                    in (
                        WorkItemState.DONE,
                        WorkItemState.CANCELED,
                    )
                    else None
                )
            self._emit(item)

    def link_candidates(self, work_id: str, ids: list[str]) -> None:
        with self.lock:
            item = self.get(work_id)
            if item is None:
                return
            merged = list(dict.fromkeys([*item.candidate_ids, *ids]))
            if merged != item.candidate_ids:
                self.update(work_id, candidate_ids=merged)

    def start(self, ids: list[str], agent: str, run_id: str) -> None:
        with self.lock:
            for work_id in ids:
                item = self.get(work_id)
                if item is None:
                    continue
                if item.state is WorkItemState.RUNNING:
                    raise RuntimeError(f"Task already running: {work_id}")
                item.attempts.append(WorkAttempt(run_id=run_id, agent=agent))
                self.update(work_id, state=WorkItemState.RUNNING, status_reason="正在执行")

    def end(self, ids: list[str], *, stop_reason: str, steps: int, error: str = "") -> None:
        with self.lock:
            for work_id in ids:
                item = self.get(work_id)
                if item is None:
                    continue
                if item.attempts and item.attempts[-1].finished_at is None:
                    attempt = item.attempts[-1]
                    attempt.finished_at = now()
                    attempt.stop_reason = stop_reason
                    attempt.steps = steps
                    attempt.error = error
                canceled = stop_reason == "aborted"
                failed = stop_reason not in ("finished", "budget") or bool(error)
                self.update(
                    work_id,
                    state=WorkItemState.CANCELED
                    if canceled
                    else (WorkItemState.BLOCKED if failed else WorkItemState.PLANNED),
                    steps_used=sum(a.steps for a in item.attempts),
                    status_reason=explain_failure(error, stop_reason)
                    if failed or canceled
                    else "执行结束，等待检查结果",
                )

    def stop(self, reason: str, *, canceled: bool = False) -> None:
        with self.lock:
            for item in self.board.work:
                if item.state in (WorkItemState.DONE, WorkItemState.CANCELED):
                    continue
                self.update(
                    item.work_id,
                    state=WorkItemState.CANCELED if canceled else WorkItemState.BLOCKED,
                    status_reason=f"{reason}；{item.status_reason}"
                    if item.status_reason
                    else reason,
                )
