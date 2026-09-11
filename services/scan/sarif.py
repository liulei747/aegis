"""SARIF 2.1.0 -> :class:`Finding`. Tolerant by design: opengrep/semgrep variants drift."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from aegis_contracts.domain import CodeRegion, Finding, Provider, Severity
from aegis_core.logging import get_logger
from aegis_core.utils import normalize_snippet, rebase_path, sha1

log = get_logger(__name__)

_SEVERITY_MAP = {
    "error": Severity.ERROR,
    "warning": Severity.WARNING,
    "warn": Severity.WARNING,
    "info": Severity.INFO,
    "note": Severity.NOTE,
    "none": Severity.NOTE,
    "critical": Severity.ERROR,
    "high": Severity.ERROR,
    "medium": Severity.WARNING,
    "low": Severity.INFO,
    "blocking": Severity.ERROR,
}


def _severity_from(value: Any) -> Severity | None:
    if not value:
        return None
    if isinstance(value, (int, float)):  # SARIF numeric severity
        return {0: Severity.NOTE, 1: Severity.WARNING, 2: Severity.ERROR}.get(int(value))
    return _SEVERITY_MAP.get(str(value).strip().lower())


class SarifParser:
    def __init__(self, *, workspace_root: Path | None = None) -> None:
        self.workspace_root = workspace_root

    def parse_text(self, text: str, *, source: str = "<memory>") -> list[Finding]:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            log.error("sarif parse failed", extra={"stage": "sarif"})
            raise ValueError(f"invalid SARIF json from {source}: {exc}") from exc
        return self.parse(doc, source=source)

    def parse_file(self, path: Path) -> list[Finding]:
        return self.parse_text(path.read_text(encoding="utf-8", errors="replace"), source=str(path))

    def parse(self, doc: dict[str, Any], *, source: str = "<memory>") -> list[Finding]:
        runs = doc.get("runs") or []
        findings: list[Finding] = []
        for run in runs:
            index = self._rule_index(run)
            tool = ((run.get("tool") or {}).get("driver") or {}).get("name") or "opengrep"
            for raw in run.get("results") or []:
                finding = self._one_result(raw, index, tool)
                if finding is not None:
                    findings.append(finding)
        log.info("sarif parsed", extra={"stage": "sarif"})
        return findings

    # ------------------------------------------------------------------
    @staticmethod
    def _rule_index(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        index: dict[str, dict[str, Any]] = {}
        for pos, rule in enumerate(rules):
            rid = rule.get("id") or f"rule-{pos}"
            index[rid] = rule
            for alias in rule.get("aliases") or []:
                index.setdefault(alias, rule)
        return index

    def _one_result(
        self,
        raw: dict[str, Any],
        rules: dict[str, dict[str, Any]],
        tool: str,
    ) -> Finding | None:
        rule_id = raw.get("ruleId") or ((raw.get("rule") or {}).get("id")) or "unknown"
        rule = rules.get(rule_id) or {}
        locations = raw.get("locations") or []
        if not locations:
            log.debug("sarif result without location skipped: %s", rule_id)
            return None
        physical = (locations[0].get("physicalLocation") or {})
        artifact = physical.get("artifactLocation") or {}
        uri = artifact.get("uri") or artifact.get("uriBaseId") or ""
        if not uri:
            return None

        region = physical.get("region") or {}
        start_line = int(region.get("startLine") or 1)
        end_line = int(region.get("endLine") or start_line)
        start_col = int(region.get("startColumn") or 1)
        end_col = int(region.get("endColumn") or start_col)
        path = self._resolve(uri)

        snippet = (
            ((region.get("snippet") or {}).get("text"))
            or self._first_context(raw)
            or ""
        )

        message = ((raw.get("message") or {}).get("text")) or rule_id
        severity = (
            _severity_from(raw.get("level"))
            or _severity_from((raw.get("properties") or {}).get("severity"))
            or _severity_from((raw.get("properties") or {}).get("issue_severity"))
            or _severity_from((rule.get("defaultConfiguration") or {}).get("level"))
            or self._severity_from_tags(rule)
            or Severity.WARNING
        )

        properties: dict[str, Any] = {}
        for key in ("properties", "fingerprints"):
            if isinstance(raw.get(key), dict):
                properties.update(raw[key])
        if tool:
            properties.setdefault("tool", tool)
        if rule.get("shortDescription", {}).get("text"):
            properties.setdefault("rule_summary", rule["shortDescription"]["text"])

        fingerprint = (
            (raw.get("fingerprints") or {}).get("matchBasedId/v1")
            or (raw.get("partialFingerprints") or {}).get("primaryLocationLineHash")
            or None
        )
        finding_id = "F-" + sha1(rule_id, path, str(start_line), str(start_col), length=12)

        return Finding(
            finding_id=finding_id,
            rule_id=rule_id,
            message=message,
            severity=severity,
            path=path,
            region=CodeRegion(
                path=path,
                start_line=max(0, start_line - 1),
                start_char=max(0, start_col - 1),
                end_line=max(0, end_line - 1),
                end_char=max(0, end_col - 1),
            ),
            snippet=normalize_snippet(snippet, 400),
            properties=properties,
            fingerprint=fingerprint,
            provider=Provider.OPENGREP,
        )

    @staticmethod
    def _severity_from_tags(rule: dict[str, Any]) -> Severity | None:
        props = rule.get("properties") or {}
        for tag in props.get("tags") or []:
            sev = _severity_from(tag)
            if sev is not None:
                return sev
        return None

    @staticmethod
    def _first_context(raw: dict[str, Any]) -> str:
        for ctx in raw.get("codeFlows") or []:
            for thread in ctx.get("threadFlows") or []:
                for loc in thread.get("locations") or []:
                    text = (
                        (((loc.get("location") or {}).get("physicalLocation") or {}).get("region"))
                        or {}
                    ).get("snippet", {}).get("text")
                    if text:
                        return text
        return ""

    def _resolve(self, uri: str) -> str:
        """Turn a SARIF artifact URI into a path relative to the workspace root.

        Relative URIs stay relative (SARIF artifact URIs are root-relative).
        Absolute URIs from another host or container are rebased onto our root so
        that later stages can actually read the file.
        """
        if self.workspace_root is None:
            return Path(uri).as_posix()
        return rebase_path(uri, self.workspace_root)
