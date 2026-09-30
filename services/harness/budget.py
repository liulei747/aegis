"""Shared run limits. Calls are reserved atomically; usage is measured after responses.

Token and cost limits stop subsequent calls; already in-flight requests can exceed them.
Missing provider usage is explicit and stops runs that require usage-based limits.
"""
from __future__ import annotations

import math
import os
import threading
import time
from contextlib import contextmanager

LIMIT_FIELDS = {
    "max_run_seconds": float, "max_model_calls": int, "max_model_tokens": int,
    "max_cost_usd": float, "input_usd_per_million": float, "output_usd_per_million": float,
    "max_claim_attempts": int, "max_gap_continuations": int, "max_no_progress_continuations": int,
    "agent_max_model_calls": int, "agent_max_model_tokens": int,
}


def environment_limits():
    limits = {}
    for name, convert in LIMIT_FIELDS.items():
        raw = os.environ.get("AEGIS_HARNESS_" + name.upper(), "").strip()
        if raw:
            value = convert(raw)
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"AEGIS_HARNESS_{name.upper()} must be a finite nonnegative number")
            limits[name] = value
    return limits


class BudgetStop(BaseException):
    """Must survive per-agent Exception handlers, like cancellation, without being cancellation."""


class AgentBudgetStop(BudgetStop):
    """One agent run hit *its own* cap. The audit continues; this run ends with `stop_reason=budget`.

    A subclass so the shared handlers that treat `BudgetStop` as "the run is over" keep working
    unchanged, while `react` can catch this narrower one and finish the agent gracefully.
    """


class AgentBudget:
    """The per-agent-run layer: calls and tokens this one run may spend, inside the audit's caps.

    Three layers, as batch 3 asks for: the request (`max_tokens`, `context_input_tokens`), the
    agent run (this), and the audit (`RunBudget`). Retries and every attempt of a request count
    here exactly as they count in `RunBudget`, because `BudgetClient` reserves and accounts on
    both for every attempt. Zero caps disable the layer; `usage()` is reported either way, so
    `agent_end` can carry what the run actually cost even when nothing bounded it.
    """

    def __init__(self, *, max_model_calls: int = 0, max_model_tokens: int = 0):
        self.max_model_calls = max(0, int(max_model_calls))
        self.max_model_tokens = max(0, int(max_model_tokens))
        self.lock = threading.Lock()
        self.calls = 0
        self.tokens = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.unknown_usage = 0
        self.reason = ""

    def reserve(self):
        with self.lock:
            if self.reason:
                raise AgentBudgetStop(self.reason)
            if self.max_model_calls > 0 and self.calls >= self.max_model_calls:
                self.reason = f"agent 模型调用预算耗尽（{self.max_model_calls} 次）"
                raise AgentBudgetStop(self.reason)
            if self.max_model_tokens > 0 and self.tokens >= self.max_model_tokens:
                self.reason = f"agent 模型 token 预算耗尽（{self.max_model_tokens}）"
                raise AgentBudgetStop(self.reason)
            self.calls += 1

    def release(self):
        """Undo one reservation whose request was never sent (the audit refused it after us)."""
        with self.lock:
            self.calls = max(0, self.calls - 1)

    def account(self, response):
        usage = getattr(response, "usage", None)
        def value(name):
            return usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
        prompt, completion = value("prompt_tokens"), value("completion_tokens")
        with self.lock:
            if any(type(v) is not int or v < 0 for v in (prompt, completion)):
                self.unknown_usage += 1
                if self.max_model_tokens > 0:
                    self.reason = "模型未返回完整 token 用量；停止此 agent 的后续调用以保留预算约束"
                return
            self.prompt_tokens += prompt
            self.completion_tokens += completion
            self.tokens += prompt + completion

    def usage(self):
        with self.lock:
            return dict(model_calls=self.calls, tokens=self.tokens,
                        prompt_tokens=self.prompt_tokens, completion_tokens=self.completion_tokens,
                        unknown_usage=self.unknown_usage,
                        max_model_calls=self.max_model_calls, max_model_tokens=self.max_model_tokens,
                        stop_reason=self.reason)


class RunBudget:
    def __init__(self, config, clock=time.monotonic):
        for name in LIMIT_FIELDS:
            if not math.isfinite(getattr(config, name)) or getattr(config, name) < 0:
                raise ValueError(f"{name} must be finite and nonnegative")
        self.config = config
        self.clock = clock
        self.started = clock()
        self.lock = threading.RLock()
        self.calls = 0
        self.tokens = 0
        self.cost_usd = 0.0
        self.unknown_usage = 0
        self.reason = ""

    def check(self):
        with self.lock:
            limits = [
                (self.config.max_run_seconds, self.clock() - self.started, "总时间预算耗尽"),
                (self.config.max_model_calls, self.calls, "总模型调用预算耗尽"),
                (self.config.max_model_tokens, self.tokens, "总模型 token 预算耗尽"),
                (self.config.max_cost_usd, self.cost_usd, "总模型费用预算耗尽"),
            ]
            if not self.reason:
                self.reason = next((text for cap, used, text in limits if cap > 0 and used >= cap), "")
            if self.reason:
                raise BudgetStop(self.reason)

    def check_inflight(self):
        # A reserved call may finish even when it used the last available call slot.
        with self.lock:
            cap = self.config.max_run_seconds
            if cap > 0 and self.clock() - self.started >= cap:
                self.reason = "总时间预算耗尽"
                raise BudgetStop(self.reason)

    def reserve(self):
        with self.lock:
            self.check()
            if self.config.max_cost_usd > 0 and (
                self.config.input_usd_per_million <= 0 or self.config.output_usd_per_million <= 0
            ):
                self.reason = "费用预算需要配置输入和输出 token 单价"
                raise BudgetStop(self.reason)
            self.calls += 1

    def account(self, response):
        usage = getattr(response, "usage", None)
        def value(name):
            return usage.get(name) if isinstance(usage, dict) else getattr(usage, name, None)
        prompt, completion = value("prompt_tokens"), value("completion_tokens")
        with self.lock:
            if any(type(v) is not int or v < 0 for v in (prompt, completion)):
                self.unknown_usage += 1
                if self.config.max_model_tokens > 0 or self.config.max_cost_usd > 0:
                    self.reason = "模型未返回完整 token 用量；停止后续调用以保留预算约束"
                return
            self.tokens += prompt + completion
            self.cost_usd += (prompt * self.config.input_usd_per_million
                              + completion * self.config.output_usd_per_million) / 1_000_000

    def snapshot(self):
        with self.lock:
            return dict(model_calls=self.calls, tokens=self.tokens, cost_usd=self.cost_usd,
                        cost_configured=self.config.input_usd_per_million > 0 and self.config.output_usd_per_million > 0,
                        unknown_usage=self.unknown_usage, elapsed_seconds=self.clock() - self.started,
                        stop_reason=self.reason, max_model_calls=self.config.max_model_calls,
                        max_model_tokens=self.config.max_model_tokens, max_cost_usd=self.config.max_cost_usd,
                        max_run_seconds=self.config.max_run_seconds)


class BudgetClient:
    def __init__(self, client, budget, check, on_progress=None, agent_budget=None):
        self.client, self.budget, self.check = client, budget, check
        self.on_progress = on_progress
        #: The per-run layer, or None for a caller that only wants the audit-wide caps. Reserved
        #: *before* the audit's own `reserve` and rolled back if the audit then refuses, so the
        #: agent's usage counts only requests that were actually attempted; accounted on every
        #: response, success or failure, alongside the audit's ledger.
        self.agent_budget = agent_budget

    def __getattr__(self, name):
        return getattr(self.client, name)

    def _reserve(self):
        self.check("model-call")
        if self.agent_budget is not None:
            self.agent_budget.reserve()
        try:
            self.budget.reserve()
        except BaseException:
            if self.agent_budget is not None:
                self.agent_budget.release()
            raise

    def _account(self, response):
        self.budget.account(response)
        if self.agent_budget is not None:
            self.agent_budget.account(response)

    @contextmanager
    def _waiting_progress(self):
        """Keep a non-streaming request visible while the provider holds the socket."""
        if self.on_progress is None or getattr(self.client, "streaming", False):
            yield
            return
        stopped = threading.Event()
        started = time.monotonic()

        def report() -> None:
            while not stopped.is_set():
                try:
                    self.on_progress({
                        "status": "waiting", "transport": "nonstream",
                        "elapsed_ms": int((time.monotonic() - started) * 1000),
                        "idle_ms": int((time.monotonic() - started) * 1000),
                        "content_chars": 0, "reasoning_chars": 0,
                    })
                except Exception:  # progress must not fail the model call
                    pass
                if stopped.wait(10):
                    break

        thread = threading.Thread(target=report, name="model-wait-progress", daemon=True)
        thread.start()
        try:
            yield
        finally:
            stopped.set()
            thread.join(timeout=1)

    def complete(self, system, user):
        self._reserve()
        try:
            from services.ai.client import ChatClient
            with self._waiting_progress():
                if isinstance(self.client, ChatClient):
                    response = self.client.complete(system, user, check=self.check, on_progress=self.on_progress)
                else:
                    response = self.client.complete(system, user)
        except BaseException:
            self._account(None)
            raise
        self._account(response)
        return response

    def complete_messages(self, messages, *, tools=None):
        """The native tool-calls path, with the same check/reserve/account semantics as
        `complete` — a native run that bypassed the budget would be an unaccounted spend."""
        self._reserve()
        try:
            from services.ai.client import ChatClient
            with self._waiting_progress():
                if isinstance(self.client, ChatClient):
                    response = self.client.complete_messages(
                        messages, tools=tools, check=self.check, on_progress=self.on_progress
                    )
                else:
                    response = self.client.complete_messages(messages, tools=tools)
        except BaseException:
            self._account(None)
            raise
        self._account(response)
        return response
