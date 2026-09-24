"""Shared, hot-reloaded LLM settings for gateway and worker.

The file lives under the already shared work directory. The API key is never returned by
read endpoints or copied into a job request; each worker loads it when a new job begins.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, SecretStr, model_validator

from aegis_core.config import AIConfig, Settings

_FIELDS = frozenset({"enabled", "base_url", "model", "timeout_s", "concurrency",
                     "temperature", "max_tokens", "max_contexts"})


class AISettingsUpdate(BaseModel):
    enabled: bool | None = None
    base_url: str | None = None
    model: str | None = None
    timeout_s: float | None = Field(default=None, ge=10, le=600)
    concurrency: int | None = Field(default=None, ge=1, le=16)
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_tokens: int | None = Field(default=None, ge=0, le=200_000)
    max_contexts: int | None = Field(default=None, ge=1, le=500)
    api_key: SecretStr | None = None
    clear_api_key: bool = False

    @model_validator(mode="after")
    def valid_endpoint(self) -> AISettingsUpdate:
        if self.base_url is not None and self.base_url.strip():
            parsed = urlsplit(self.base_url.strip())
            if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("模型地址必须是没有账号密码的 HTTP(S) URL")
        return self


def _path(settings: Settings) -> Path:
    return (settings.ai_runtime_dir or settings.work_dir / "settings") / "ai.json"


def _read(settings: Settings) -> dict:
    path = _path(settings)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict):
        raise ValueError("保存的 LLM 配置不是 JSON 对象")
    return value


def effective_ai(settings: Settings) -> AIConfig:
    saved = _read(settings)
    values = settings.ai.model_dump(exclude={"api_key"})
    values.update({key: saved[key] for key in _FIELDS if key in saved})
    key = saved.get("api_key")
    if isinstance(key, str) and key:
        values["api_key"] = SecretStr(key)
    return AIConfig.model_validate(values)


def ai_view(settings: Settings) -> dict:
    config = effective_ai(settings)
    return {
        "enabled": config.enabled,
        "base_url": config.base_url,
        "model": config.model,
        "timeout_s": config.timeout_s,
        "concurrency": config.concurrency,
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
        "max_contexts": config.max_contexts,
        "api_key_present": bool(config.api_key and config.api_key.get_secret_value())
            or bool(os.environ.get(config.api_key_env, "").strip()),
        "api_key_source": "saved" if config.api_key else "environment",
        "source": "saved" if _path(settings).is_file() else "environment",
    }


def save_ai(settings: Settings, update: AISettingsUpdate) -> dict:
    saved = _read(settings)
    patch = update.model_dump(exclude_none=True, exclude={"api_key", "clear_api_key"})
    saved.update({key: value.strip() if isinstance(value, str) else value
                  for key, value in patch.items() if key in _FIELDS})
    if update.api_key is not None and update.api_key.get_secret_value().strip():
        saved["api_key"] = update.api_key.get_secret_value().strip()
    elif update.clear_api_key:
        saved.pop("api_key", None)
    # Validate the merged result before replacing the active file.
    config = settings.ai.model_dump(exclude={"api_key"})
    config.update({key: saved[key] for key in _FIELDS if key in saved})
    AIConfig.model_validate(config)
    if config["enabled"] and (not config["base_url"] or not config["model"]):
        raise ValueError("启用 LLM 需要模型地址和模型名称")
    if config["enabled"] and not saved.get("api_key") and not os.environ.get(settings.ai.api_key_env, "").strip():
        raise ValueError("启用 LLM 需要 API 密钥")
    path = _path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(saved, stream, ensure_ascii=False, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return ai_view(settings)


def reset_ai(settings: Settings) -> dict:
    _path(settings).unlink(missing_ok=True)
    return ai_view(settings)
