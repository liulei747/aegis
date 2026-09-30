"""The per-agent execution boundary keeps role permissions and progress out of scheduling."""

from types import SimpleNamespace

from aegis_contracts.harness import ToolName
from services.ai.client import ChatResult
from services.harness.agent_runner import AgentRunner, AgentTask
from services.harness.budget import AgentBudget, RunBudget
from services.harness.coordinator import HarnessConfig


def test_runner_reports_one_bounded_agent_result_and_role_tools():
    steps = []
    progress = []
    calls = []
    client = SimpleNamespace(
        model="scripted", streaming=False,
        complete=lambda *_: calls.append(1) or ChatResult(
            text='{"thought":"reviewed","final":{"candidates":[]}}', model="scripted"
        ),
    )
    task = AgentTask(
        agent="discovery", scope_id="scope-a", task="review", context=None,
        client=client, max_steps=1, run_id="discovery:scope-a",
    )
    assert ToolName.READ in task.tools
    runner = AgentRunner(
        run_budget=RunBudget(HarnessConfig()), check_abort=lambda _: None,
        on_step=lambda run, step: steps.append((run.run_id, step.index)),
        on_progress=progress.append, on_context=lambda _: None,
    )
    outcome = runner.run(task, agent_budget=AgentBudget())
    assert outcome.run.stop_reason == "finished"
    assert outcome.parsed == []
    assert calls == [1]
    assert steps == [("discovery:scope-a", 1)]
    assert progress and progress[0]["status"] == "waiting"
