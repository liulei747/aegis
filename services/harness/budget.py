"""Shared run limits. Calls are reserved atomically; usage is measured after responses.

Token and cost limits stop subsequent calls; already in-flight requests can exceed them.
Missing provider usage is explicit and stops runs that require usage-based limits.
"""
from __future__ import annotations

import math
import os
import threading
import time

LIMIT_FIELDS = {
    "max_run_seconds": float, "max_model_calls": int, "max_model_tokens": int,
    "max_cost_usd": float, "input_usd_per_million": float, "output_usd_per_million": float,
    "max_claim_attempts": int, "max_gap_continuations": int, "max_no_progress_continuations": int,
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
    def __init__(self, client, budget, check):
        self.client, self.budget, self.check = client, budget, check

    def __getattr__(self, name):
        return getattr(self.client, name)

    def complete(self, system, user):
        self.check("model-call")
        self.budget.reserve()
        try:
            response = self.client.complete(system, user)
        except Exception:
            self.budget.account(None)
            raise
        self.budget.account(response)
        return response
