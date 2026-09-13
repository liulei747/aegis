"""The two small jobs every tool repeats: parsing arguments, and clipping output.

Both exist because of the same asymmetry: the model's context is small and the repository is
not. An argument parser that trusts its input turns one hallucinated field into a traceback
(which the model cannot recover from), and an output clipper that hides what it cut lets a
model conclude something about code it never actually saw.
"""

from __future__ import annotations

from typing import Any

from services.harness.tools.paths import ToolArgumentError

#: Appended in place of the text that did not fit. Chinese because it is read by the model and
#: copied into the run transcript, and it says *why* the text stopped rather than just stopping.
CLIPPED_MARK = "\n[输出已超出字符上限，后续内容被截断]"


def clip(text: str, limit: int) -> tuple[str, bool]:
    """Cut ``text`` to at most ``limit`` characters, keeping the head.

    The marker is inside the budget, so a caller can hand the result straight to the model
    without a second pass. Returns ``(text, was_clipped)``: the flag is what lets the caller
    set ``ToolResult.truncated``, because truncation that is only visible in the text is
    truncation a downstream summariser drops on the floor.
    """
    if limit <= 0:
        return ("", bool(text)) if text else ("", False)
    if len(text) <= limit:
        return text, False
    keep = max(0, limit - len(CLIPPED_MARK))
    return text[:keep] + CLIPPED_MARK, True


def int_argument(
    arguments: dict[str, Any],
    key: str,
    *,
    default: int,
    minimum: int = 1,
    label: str = "",
) -> int:
    """Read an integer argument, refusing what an integer argument cannot be.

    Numeric strings are accepted (`"10"` -> 10) because models emit quoted numbers routinely and
    refusing them would burn a step on a formatting detail rather than on the repository.
    Booleans are refused rather than coerced: ``True`` is an ``int`` in Python, and a model that
    sends ``"limit": true`` meant something the tool cannot guess.
    """
    suffix = f"（{label}）" if label else ""
    value = arguments.get(key)
    if value is None:
        return default
    if isinstance(value, str):
        text = value.strip().lstrip("+")
        if text.isdigit():
            value = int(text)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolArgumentError(f"`{key}` 必须是整数{suffix}")
    if value < minimum:
        raise ToolArgumentError(f"`{key}` 必须 >= {minimum}{suffix}")
    return value


def str_argument(
    arguments: dict[str, Any],
    key: str,
    *,
    default: str = "",
    label: str = "",
) -> str:
    """Read a string argument. ``None`` means "absent", not "empty by mistake"."""
    suffix = f"（{label}）" if label else ""
    value = arguments.get(key)
    if value is None:
        return default
    if not isinstance(value, str):
        raise ToolArgumentError(f"`{key}` 必须是字符串{suffix}")
    return value.strip()
