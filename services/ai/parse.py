"""Turning the model's answer into a `Verdict`, leniently and visibly.

The instructions demand one bare JSON object with nine keys. Models wrap it in a fence, prepend
"Here is the JSON:", or use a severity the enum does not know. None of that is worth throwing the
answer away over -- but none of it may pass silently either, so every deviation is returned as a
recorded detail rather than raised.
"""

from __future__ import annotations

import json
import re
from typing import Any

from aegis_contracts.ai import (
    DECISIVE_VERDICT_FIELDS,
    REQUIRED_VERDICT_FIELDS,
    Verdict,
    VerdictKind,
    VerdictSeverity,
)

_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)


def extract_json_object(text: str) -> str | None:
    """The JSON object inside `text`, fenced or bare. None when there is not one."""
    fenced = _FENCE.search(text)
    if fenced:
        return fenced.group(1)
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    return text[start: end + 1]


def _coerce_confidence(value: Any) -> float | None:
    """A number between 0 and 1, or None. A model that answers "0.6 (medium)" is not a number."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        match = re.search(r"-?\d+(?:\.\d+)?", value)
        if not match:
            return None
        number = float(match.group(0))
        # "85" almost certainly means 85%, not 85x.
        if number > 1.0 and number <= 100.0:
            number = number / 100.0
    else:
        return None
    return min(1.0, max(0.0, number))


def _coerce_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (int, float, bool)):
                out.append(str(item))
            elif isinstance(item, dict):
                out.append(json.dumps(item, ensure_ascii=False))
        return out
    return [json.dumps(value, ensure_ascii=False)]


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def _leading_enum(text: Any, enum_cls) -> tuple[Any | None, str]:
    """`"high -- depends on the driver"` -> `(Severity.HIGH, "depends on the driver")`.

    The instructions ask the model to put conditional reasoning *inside* the value ("if your
    severity depends on something unproven, say so in `severity` itself"), so demanding an exact
    match rejects answers that followed the instructions. Measured: a real call answered
    `"high -- SQL injection via string-concatenated query on an input-reachable handler path;
    impact could be critical if Controller.dispatch is externally exposed"` and was thrown away
    as `unknown severity`.

    The longest matching value wins, and the match must end at a word boundary -- otherwise
    `low` would capture `lower` and `medium` would be shadowed.
    """
    raw = str(text).strip()
    lowered = raw.lower()
    for candidate in sorted((item.value for item in enum_cls), key=len, reverse=True):
        if lowered == candidate:
            return enum_cls(candidate), ""
        if lowered.startswith(candidate) and not lowered[len(candidate)].isalnum():
            return enum_cls(candidate), raw[len(candidate):].strip(" \t-–—:;,.")
    return None, ""


def parse_verdict(text: str) -> tuple[Verdict | None, str | None, list[str]]:
    """`(verdict, error, missing_fields)`.

    `error` is set only when the answer cannot be a verdict at all -- no JSON object, or a
    `verdict`/`severity`/`confidence` that cannot be read. A readable verdict with keys missing is
    returned **with** the missing keys listed: the model's answer is evidence, and an incomplete
    one is still evidence.
    """
    candidate = extract_json_object(text)
    if candidate is None:
        return None, "回答中找不到 JSON 对象", []
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError as exc:
        return None, f"JSON 对象无法解析：{exc}", []
    if not isinstance(payload, dict):
        return None, f"回答的类型是 {type(payload).__name__}，不是对象", []

    missing = [name for name in REQUIRED_VERDICT_FIELDS if name not in payload]
    decisive_missing = [name for name in DECISIVE_VERDICT_FIELDS if name not in payload]
    if decisive_missing:
        return None, f"回答不是一条研判结论：缺少 {', '.join(decisive_missing)}", missing

    kind, _kind_note = _leading_enum(payload["verdict"], VerdictKind)
    if kind is None:
        allowed = ", ".join(item.value for item in VerdictKind)
        return None, f"未知的结论 {payload['verdict']!r}（应为以下之一：{allowed}）", missing
    severity, severity_note = _leading_enum(payload["severity"], VerdictSeverity)
    if severity is None:
        allowed = ", ".join(item.value for item in VerdictSeverity)
        return None, f"未知的严重度 {payload['severity']!r}（应为以下之一：{allowed}）", missing

    confidence = _coerce_confidence(payload["confidence"])
    if confidence is None:
        # `confidence` 保留英文：它是要求模型输出的**字段名**，翻成中文会让读者以为模型
        # 该输出一个叫「置信度」的键。
        return None, f"confidence 不是数字：{payload['confidence']!r}", missing

    return (
        Verdict(
            verdict=kind,
            severity=severity,
            confidence=confidence,
            severity_qualifier=severity_note,
            reachability=_coerce_text(payload.get("reachability")),
            chain=_coerce_string_list(payload.get("chain")),
            data_flow=_coerce_text(payload.get("data_flow")),
            evidence=_coerce_string_list(payload.get("evidence")),
            missing=_coerce_string_list(payload.get("missing")),
            fix=_coerce_text(payload.get("fix")),
        ),
        None,
        missing,
    )
