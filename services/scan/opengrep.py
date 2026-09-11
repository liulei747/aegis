"""Opengrep process runner.

Opengrep is a Semgrep-CE fork, so the CLI surface is intentionally compatible.
We probe for the native binary first and fall back to a configured alternative
(``semgrep``) when it is absent, recording the degradation instead of failing.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from app.core.logging import get_logger

log = get_logger(__name__)


@dataclass
class ScanOutcome:
    engine: str
    returncode: int
    sarif_path: Path
    command: list[str] = field(default_factory=list)
    stderr_tail: str = ""
    degraded: bool = False
    degrade_reason: str | None = None


class OpengrepNotFound(RuntimeError):
    pass


class OpengrepRunner:
    def __init__(
        self,
        binary: str = "opengrep",
        *,
        fallback_binary: str | None = "semgrep",
        timeout_s: int = 900,
    ) -> None:
        self.binary = binary
        self.fallback_binary = fallback_binary
        self.timeout_s = timeout_s
        self._version: str | None = None

    # -- discovery ----------------------------------------------------
    def resolve_binary(self) -> tuple[str, bool]:
        """Return (executable, degraded). Raises if neither is available."""
        found = shutil.which(self.binary)
        if found:
            return found, False
        if self.fallback_binary:
            alt = shutil.which(self.fallback_binary)
            if alt:
                log.warning(
                    "opengrep missing, falling back to %s (%s)",
                    self.fallback_binary,
                    alt,
                    extra={"stage": "scan"},
                )
                return alt, True
        raise OpengrepNotFound(
            f"neither '{self.binary}' nor '{self.fallback_binary}' is on PATH"
        )

    def version(self) -> str:
        """Cached: the version probe spawns a process, so never do it per request."""
        if self._version is not None:
            return self._version
        try:
            exe, _ = self.resolve_binary()
        except OpengrepNotFound:
            self._version = "unavailable"
            return self._version
        try:
            out = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            text = (out.stdout or out.stderr or "").strip()
        except Exception as exc:  # pragma: no cover - defensive
            self._version = f"{exe} (version probe failed: {exc})"
            return self._version
        self._version = text.splitlines()[0] if text else exe
        return self._version

    # -- execution ----------------------------------------------------
    def build_command(
        self,
        exe: str,
        *,
        target: Path,
        sarif_path: Path,
        rule_config: str | None,
        rules: list[str],
        include_globs: list[str],
        exclude_globs: list[str],
    ) -> list[str]:
        # opengrep uses `scan`, semgrep infers it from the flags. Both accept
        # --sarif/--output/--quiet/--config; --metrics is semgrep-only and makes
        # opengrep exit with rc=2 (verified against opengrep 1.16.0).
        is_opengrep = Path(exe).stem.startswith("opengrep")
        cmd = [exe]
        if is_opengrep:
            cmd.append("scan")
        cmd += ["--sarif", "--output", str(sarif_path)]

        configs = list(rules)
        if rule_config:
            configs.append(rule_config)
        if not configs:
            configs = ["auto"]
        for cfg in configs:
            cmd += ["--config", cfg]

        if not is_opengrep:
            # Telemetry opt-out; opengrep has no --metrics flag (and sends nothing).
            cmd.append("--metrics=off")
        cmd.append("--quiet")
        for glob in include_globs:
            cmd += ["--include", glob]
        for glob in exclude_globs:
            cmd += ["--exclude", glob]
        cmd.append(str(target))
        return cmd

    def scan(
        self,
        target: Path,
        *,
        out_dir: Path | None = None,
        rule_config: str | None = None,
        rules: list[str] | None = None,
        include_globs: list[str] | None = None,
        exclude_globs: list[str] | None = None,
    ) -> ScanOutcome:
        exe, degraded = self.resolve_binary()
        target = target.resolve()
        if not target.exists():
            raise FileNotFoundError(f"scan target does not exist: {target}")

        holder = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="aegis-scan-"))
        holder.mkdir(parents=True, exist_ok=True)
        sarif_path = holder / "opengrep.sarif"

        cmd = self.build_command(
            exe,
            target=target,
            sarif_path=sarif_path,
            rule_config=rule_config,
            rules=rules or [],
            include_globs=include_globs or [],
            exclude_globs=exclude_globs or [],
        )
        log.info("running static scan", extra={"stage": "scan"})
        log.debug("command: %s", " ".join(cmd))

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.timeout_s,
            check=False,
        )
        tail = "\n".join((proc.stderr or "").strip().splitlines()[-20:])
        if proc.returncode not in (0, 1):  # semgrep-family: 1 == findings present
            log.error("static scan failed rc=%s: %s", proc.returncode, tail)
        elif not sarif_path.exists():
            log.error("static scan produced no SARIF: rc=%s", proc.returncode)
        return ScanOutcome(
            engine=Path(exe).stem,
            returncode=proc.returncode,
            sarif_path=sarif_path,
            command=cmd,
            stderr_tail=tail,
            degraded=degraded,
            degrade_reason=(
                f"'{self.binary}' not found on PATH; used '{Path(exe).stem}' instead"
                if degraded
                else None
            ),
        )
