"""One agent execution, separate from the coordinator's audit scheduling decisions.

The coordinator owns *which* task runs and when. This boundary owns one task's role,
tool permissions, model budget, protocol call, and progress callbacks. The protocol
and tool implementations remain in ``react`` and ``tools`` respectively.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from aegis_contracts.harness import AgentRun, AgentStep, Blackboard, ToolName
from services.harness import agents
from services.harness.budget import AgentBudget, BudgetClient, RunBudget


@dataclass(frozen=True)
class AgentTask:
    agent: str
    scope_id: str
    task: str = ""
    context: Any = None
    client: Any = None
    max_steps: int = 0
    blackboard: Blackboard | None = None
    run_id: str | None = None
    extra_system: str = ""
    initial_steps: list[AgentStep] | None = None

    @property
    def tools(self) -> tuple[ToolName, ...]:
        """Role permissions come from the immutable agent spec, never model output."""
        return tuple(agents.spec(self.agent).tools)


class AgentRunner:
    def __init__(
        self,
        *,
        run_budget: RunBudget,
        check_abort: Callable[[str], None],
        on_step: Callable[[AgentRun, AgentStep], None],
        on_progress: Callable[[dict[str, Any]], None],
        on_context: Callable[[dict[str, Any]], None],
    ) -> None:
        self.run_budget = run_budget
        self.check_abort = check_abort
        self.on_step = on_step
        self.on_progress = on_progress
        self.on_context = on_context

    def run(self, task: AgentTask, *, agent_budget: AgentBudget) -> agents.AgentOutcome:
        # Permissions stay in the role spec, which agents.run applies to the tool loop.
        client = (
            BudgetClient(
                task.client, self.run_budget, self.check_abort,
                on_progress=self.on_progress, agent_budget=agent_budget,
            ) if task.client is not None else None
        )
        return agents.run(
            agent=task.agent, scope_id=task.scope_id, task=task.task,
            context=task.context, client=client, max_steps=task.max_steps,
            blackboard=task.blackboard, run_id=task.run_id,
            extra_system=task.extra_system, initial_steps=task.initial_steps,
            on_step=self.on_step, on_context=self.on_context,
        )
