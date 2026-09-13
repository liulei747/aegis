# Third-party notices

## openai/codex-security

`services/harness/skills.py` adapts textual guidance from **openai/codex-security**
(<https://github.com/openai/codex-security>), licensed under the **Apache License, Version 2.0**
(<http://www.apache.org/licenses/LICENSE-2.0>). The upstream repository's `LICENSE` file contains
the full licence text.

Upstream files consulted:

- `plugins/codex-security/references/core-scan.md` — the vulnerability-class sweep, the four
  investigator perspectives, and the severity-calibration rule.
- `plugins/codex-security/skills/finding-discovery/SKILL.md` — the finding bar (what counts as a
  candidate, and what does not).
- `plugins/codex-security/skills/security-scan/SKILL.md` and
  `plugins/codex-security/references/scan-contract.md` — read to establish the phase sequence and
  the coverage contract, which informed the design notes in `skills.py` but are not reproduced.

**Changes made.** The upstream text targets a diff-scoped, advisory-seeded, MCP-driven product with
a worker fleet. Only guidance that holds for a static whole-repository audit was kept; the wording is
rewritten for this codebase's vocabulary rather than copied verbatim. The following are deliberately
*not* ported: the artifact and scan-contract machinery (canonical `scan-manifest.json`,
`findings.json`, `coverage.json`, sealing, SDK handoff), advisory- and CVE-seeded ledger rows,
diff and patch scoping, and the issue-tracker integrations (Linear, Jira, GitHub advisories).

No upstream source code is included; the adaptation is prose guidance only.
