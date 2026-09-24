"""The five agents: a prompt, a tool allow-list, and an output schema each.

Why five and not one: the pipeline's stages answer different questions, and an agent that is asked
to do all of them at once produces a transcript nobody can audit. Recon says what the repository
*is*; threat modelling says what would be worth attacking; discovery proposes candidates under one
scope; validation decides whether one candidate is real and with which kind of evidence; the attack
path asks whether anyone could actually reach it. The types in `aegis_contracts.harness` are
shaped around exactly that split, and this module is where the split is enforced.

Two rules that are load-bearing rather than stylistic:

* **The tool allow-list is per agent and it is the real bound on blast radius.** Only validation may
  call `dataflow_verify` -- it is the only stage that has a candidate site to verify. Recon
  legitimately needs a shell for "what does this project declare"; discovery needs one to follow a
  framework convention into the files that implement it.
* **Validation's evidence is taken from the tool, not from the model's summary of it.** The model
  chooses *which kind* of evidence the candidate needs (`EvidenceKind`), and when it chose dataflow
  the returned `DataflowEvidence` is read back out of the recorded `ToolResult` and attached to the
  verdict. A model that paraphrases a derived path would otherwise produce a verdict that looks
  stronger than it is.

A "lite skill" is the small exception to all of that: a short instruction block appended to a
scope's prompt, chosen from the blackboard's architecture map by component kind. It is a dict, not
a plugin system, on purpose -- the moment it grows a registration API it becomes a place for
per-project behaviour to hide.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_contracts.harness import (
    AgentStep,
    ArchitectureMap,
    AttackPath,
    Blackboard,
    Candidate,
    CandidateVerdict,
    EvidenceKind,
    ProjectContext,
    SecurityInventory,
    ThreatModel,
    ToolCall,
    ToolName,
    ToolResult,
    VerdictKind,
    WorkItem,
)
from aegis_core.logging import get_logger
from services.harness import coverage, skills, survey
from services.harness.react import (
    AgentRun,
    dataflow_evidence,
    dataflow_unavailable_reason,
    run_agent,
)

log = get_logger(__name__)

RECON = "recon"
THREAT_MODEL = "threat_model"
SECURITY_INVENTORY = "security_inventory"
PLANNER = "planner"
PLAN_UPDATE = "plan_update"
DISCOVERY = "discovery"
VALIDATION = "validation"
#: Validation of several *different* claims in one run, each with its own verdict. Separate from
#: `VALIDATION` because the schema, the tool allow-list and the parser all differ -- a batch has no
#: `dataflow_verify` and must name the claim each verdict belongs to.
VALIDATION_BATCH = "validation_batch"
ATTACK_PATH = "attack_path"
#: Attack paths for several *different* confirmed claims in one run, each with its own path. Separate
#: from `ATTACK_PATH` for the same reason the validation batch is separate: a different schema and a
#: different parser, and the answer has to name the claim each path belongs to.
ATTACK_PATH_BATCH = "attack_path_batch"


# ─────────────────────────────────────────────────────────── output schemas
#
# Kept as plain dicts rather than generated from the pydantic models: these are sent to the model,
# so they are prompt text and deserve to be read and edited as such. The pydantic models remain the
# authority -- they are what parses the answer, and a schema that drifted from them would show up
# as a validation failure rather than as silently accepted nonsense.

RECON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["languages", "build_systems", "entry_points"],
    "properties": {
        "languages": {
            "type": "object",
            "description": "language -> file count, measured from the tree (not guessed)",
        },
        "build_systems": {
            "type": "array",
            "items": {"type": "string"},
            "description": "e.g. maven, gradle, npm, setuptools, go modules",
        },
        "entry_points": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "每一条**具体**入口：进程 main、服务器启动、路由注册。一条一个元素，带上位置，"
                "例如 `GET /search (handler.py:6)`。**这一项只写入口本身，不要写解释**"
                "（位置相同就视为同一条，两种说法不会合并）。这是一个可追加的列表：路由有几条就写几条，"
                "而组件是区域（一个目录/模块一行）——不要把每条路由写成一个组件。"
            ),
        },
        "components": {
            "type": "array",
            "description": (
                "架构区域：一个 scope / 目录 / 模块一行，id 稳定（复用预扫描给的 scope id）。"
                "每行：{id, name, kind, path, description}。若这一行确实对应某个具体文件/端点，"
                "可加 route/method/line 说明；具体端点本身请写进 entry_points。"
            ),
            "items": {
                "type": "object",
                "required": ["id", "name"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "kind": {
                        "type": "string",
                        "description": "web-route | service-layer | data-access | config | entrypoint | other",
                    },
                    "path": {"type": "string"},
                    "description": {"type": "string"},
                    "route": {
                        "type": "string",
                        "description": "可选：该行对应的具体端点，例如 `GET /search`（端点也请写进 entry_points）",
                    },
                    "line": {
                        "type": "integer",
                        "description": "可选：route 所在行号",
                    },
                },
            },
        },
        "trust_boundaries": {
            "type": "array",
            "items": {"type": "string"},
            "description": "where untrusted data crosses into trusted code (HTTP, files, sockets, CLI)",
        },
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}

THREAT_MODEL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["assets", "actors", "threats", "out_of_scope"],
    "properties": {
        "assets": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "值得偷/破坏/冒充的东西，**每条一个短名词短语**（`users 表`、`app.db 文件`、"
                "`转义契约`），不要写成句子——这里只按完全相同的字符串去重，"
                "同一件资产写成两句解释就会变成两条。解释写进对应 threat 的 `note`。"
            ),
        },
        "actors": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "攻击者模型，**每条一个短名词短语**，说明它的起点就够"
                "（`匿名互联网用户`、`同主机本地进程`、`已认证的其他租户`），不要写成长句，理由同上。"
            ),
        },
        "threats": {
            "type": "array",
            "description": "Each: {id, title, asset, actor, kind, rationale, components}",
            "items": {
                "type": "object",
                "required": ["id", "title"],
                "properties": {
                    "id": {"type": "string"},
                    "title": {"type": "string"},
                    "asset": {"type": "string"},
                    "actor": {"type": "string"},
                    "kind": {"type": "string", "description": "e.g. injection, authz, ssrf, deserialization"},
                    "rationale": {"type": "string"},
                    "components": {"type": "array", "items": {"type": "string"}},
                    "note": {
                        "type": "string",
                        "description": "这条威胁的解释、前置条件、边界情况——长内容放这里，不要塞进 assets/actors",
                    },
                },
            },
        },
        "out_of_scope": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "明确排除的东西，**每条一个短名词短语 + 一句理由**。空列表本身是一个主张："
                "若为空，在 `notes` 里说明为什么没有可排除的。"
            ),
        },
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}

_SECURITY_INVENTORY_ROW_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["name", "file", "line", "evidence", "why"],
    "properties": {
        "name": {"type": "string"},
        "file": {"type": "string"},
        "line": {"type": "integer", "minimum": 1},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
    },
}

SECURITY_INVENTORY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["entry_points", "authorization_controls", "dangerous_capabilities",
                 "configurations", "dependencies", "state_controls", "coverage_gaps",
                 "files_reviewed"],
    "properties": {
        key: {"type": "array", "items": _SECURITY_INVENTORY_ROW_SCHEMA}
        for key in ("entry_points", "authorization_controls", "dangerous_capabilities",
                    "configurations", "dependencies", "state_controls")
    } | {
        "coverage_gaps": {"type": "array", "items": {"type": "string"}},
        "files_reviewed": {"type": "array", "items": {"type": "string"}},
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}

PLANNER_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["scopes", "rationale"],
    "properties": {
        "scopes": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["scope_id", "title", "question", "rationale", "files", "completion_criteria", "priority"],
                "properties": {
                    "scope_id": {
                        "type": "string",
                        "description": (
                            "Stable descriptive investigation id; never use scope-coverage-* ids."
                        ),
                    },
                    "title": {"type": "string"},
                    "question": {"type": "string", "description": "Concrete operation/asset × security property question"},
                    "completion_criteria": {"type": "string"},
                    "priority": {"type": "integer", "minimum": 1, "maximum": 3},
                    "kind": {
                        "type": "string",
                        "description": "web-route | service-layer | data-access | config | batch-task | entrypoint | other",
                    },
                    "path": {"type": "string"},
                    "rationale": {
                        "type": "string",
                        "description": (
                            "REQUIRED. Why this area is worth budget *for this system*: which asset "
                            "or threat it carries, and what you expect to look at."
                        ),
                    },
                    "files": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Concrete source starting files, workspace-relative; not file ownership",
                    },
                },
            },
        },
        "excluded": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Areas you deliberately do NOT plan for, each stated as `path or component -- why`. "
                "These become EXCLUDED coverage rows: 'we decided not to' is a different claim from "
                "'we never looked', and a reader needs both."
            ),
        },
        "rationale": {
            "type": "string",
            "description": "The planning argument as a whole: what the threat model implies, and how the scopes cover it.",
        },
    },
}

DISCOVERY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["candidates"],
    "properties": {
        "candidates": {
            "type": "array",
            "maxItems": 8,
            "items": {
                "type": "object",
                "required": ["title", "vulnerability_type", "file"],
                "properties": {
                    "title": {"type": "string"},
                    "vulnerability_type": {
                        "type": "string",
                        "description": "e.g. sql_injection, path_traversal, command_injection, ssrf, xss",
                    },
                    "file": {"type": "string", "description": "path relative to the workspace root"},
                    "line": {"type": "integer"},
                    "method": {"type": "string"},
                    "rationale": {
                        "type": "string",
                        "description": "what in the code made this worth recording; cite what you read",
                    },
                    "evidence": {"type": "array", "items": {"type": "string"}},
                    "entry_points": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "The entries that reach this site, one string per entry, shaped "
                            "`GET /admin-api/infra/file/upload (AppFileController.java:38)` or "
                            "`channel callback POST /payment/notify/yike`. Name every entry you can "
                            "see, including the ones on other controllers or in other modules: the "
                            "harness merges candidates by sink location, and these lists are how the "
                            "differences between two records of one sink survive the merge."
                        ),
                    },
                },
            },
        },
        "notes": {"type": "array", "items": {"type": "string"}},
    },
}

VALIDATION_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["verdict", "evidence_kind", "confidence", "reasons"],
    "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "rejected"]},
        "evidence_kind": {
            "type": "string",
            "enum": ["semantic", "dataflow"],
            "description": (
                "Which kind of evidence this candidate needs. `semantic` when reading the code and "
                "its callers settles it; `dataflow` when only a traced source-to-sink path can, and "
                "then you must call dataflow_verify."
            ),
        },
        "confidence": {"type": "number", "description": "0..1"},
        "reasons": {
            "type": "array",
            "items": {"type": "string"},
            "description": "REQUIRED for both verdicts. For rejected: exactly why it is not a finding.",
        },
    },
}

#: The batched form of `VALIDATION_SCHEMA`: one run, one verdict per claim, and every verdict has to
#: name the claim it belongs to. The `needs_dataflow` verdict is what keeps batching from costing
#: capability: a claim that can only be settled by a traced path is sent back out as a single run
#: (which has `dataflow_verify`), instead of being forced into a semantic guess.
VALIDATION_BATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["verdicts"],
    "properties": {
        "verdicts": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "required": ["candidate_id", "verdict", "confidence", "reasons"],
                "properties": {
                    "candidate_id": {
                        "type": "string",
                        "description": "the candidate id this verdict is about, copied verbatim",
                    },
                    "verdict": {
                        "type": "string",
                        "enum": ["confirmed", "rejected", "needs_dataflow"],
                    },
                    "confidence": {"type": "number", "description": "0..1"},
                    "reasons": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "for this claim only. Each entry that was listed for it gets a line: "
                            "reachable or not, and at what auth level. Do not cite another claim's "
                            "evidence here."
                        ),
                    },
                },
            },
        },
    },
}

ATTACK_PATH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["reachable", "impact", "confidence"],
    "properties": {
        "reachable": {"type": "boolean"},
        "entry_points": {"type": "array", "items": {"type": "string"}},
        "preconditions": {"type": "array", "items": {"type": "string"}},
        "auth_conditions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "what an attacker must hold: anonymous, any account, admin, a specific role",
        },
        "state_conditions": {"type": "array", "items": {"type": "string"}},
        "impact": {"type": "string"},
        "alternative_paths": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number", "description": "0..1, about reachability -- not about the bug"},
    },
}


# ─────────────────────────────────────────────────────────── prompts


RECON_PROMPT = """\
You are the reconnaissance agent of a security review harness. You are looking at a repository you
did not write and must not change. Your job is to say what this system *is*, from evidence you
gathered with your tools -- never from what a project of this shape usually looks like.

Establish, with the tools available:
1. Languages actually present and how many files each (count them; do not estimate).
2. Build systems and how the project is built and started.
3. Entry points: process mains, server bootstrap, and **every** route registration, each as its own
   string with its location and nothing else -- `GET /search (handler.py:6)`, no explanation after it
   (two descriptions of the same place are not merged, so prose here reads as extra endpoints).
   `entry_points` is a flat appendable list, so a project with twenty endpoints gets twenty entries;
   that list is what "which requests can reach this code" is answered from later.
   **An entry point is where input from outside first enters the code** -- a route registration, a
   `main`, a server bootstrap, a CLI command. A helper, a service method or a repository function is
   *not* one, however public it looks: measured on the demo, six internal functions (`safe_escape`,
   `load_user`, `query_user`, `query_order`, `query_order_safe`, `connect`) were listed alongside the
   four real entries, and a list that says ten requests can arrive is what "is this reachable?"
   later reads.
4. Architecture components: the modules/packages that carry the system's responsibility, each with
   a stable id, a name, a `kind` (web-route, service-layer, data-access, config, entrypoint,
   other) and a path. These become investigation scopes later, so they must be real directories or
   classes, not themes -- **one per area, not one per endpoint**. Reuse the `scope-…` ids the pre-scan
   already put on the blackboard for the areas it named: a second row for the same area under a new id
   makes the planner treat one directory as two scopes.
5. Trust boundaries: where data from outside the trust boundary reaches code that acts on it
   (HTTP handlers, file and network reads, deserialization, shell/process invocation).

Rules:
* Read files before describing them. A component you did not open is a guess.
* Prefer breadth first: a file listing and a couple of targeted reads beat reading one file deeply.
* Write as you go. The moment a language count, a build system, an entry point, a component or a trust
  boundary is confirmed, put it on the blackboard with `record` (`component`, `entry_point`,
  `trust_boundary`, `note`). Your final JSON is your conclusion; incremental records preserve useful
  facts if the run ends before its final answer.
* Two granularities, and mixing them loses data: a `component` is an **area** (one row per directory,
  module or scope id, and reuse the `scope-…` id the pre-scan already used for it), while a concrete
  endpoint is an `entry_point` -- `GET /search (handler.py:6)`, one call per endpoint. Twenty routes are
  twenty entry points, not twenty components: a second component under an area's id becomes a *site* on
  that row, and while nothing is lost that way, the planner plans areas.
* Use `record` for notes about anything that limits what you could establish -- a generated directory, a
  vendored dependency, a language you could not parse.
* Output the JSON object described by the schema. No prose around it.
"""

THREAT_MODEL_PROMPT = """\
You are the threat-modelling agent of a security review harness. You are given the repository's
reconnaissance findings. Your job is to say what is worth attacking here and, just as importantly,
what is *not* in scope.

Produce:
* assets -- what is worth stealing, breaking or impersonating in this specific system. **One short noun
  phrase per asset** (`users 表`, `app.db 文件`, `转义契约`), not a sentence: the list is de-duplicated on
  the exact text, so the same asset described twice becomes two assets. Measured on the demo, this
  produced twelve assets for four real ones -- `app.db 中的 users 与 orders 表内容（repo.py:11/19/27 …）`,
  `app.db 中 users 表的行（repo.query_user:11 …）` and `app.db 中 orders 表的行（…）` are one sqlite file
  and its two tables. Long explanations belong in the `note` of the threat they support.
* actors -- who would try, and with what starting position (anonymous internet, authenticated user,
  another tenant, a local operator). Again one short phrase each (`匿名互联网用户`), for the same reason.
* threats -- concrete, each tied to a component from the architecture map, with a `kind` and a
  rationale grounded in what recon actually found.
* out_of_scope -- what you deliberately exclude and why. An empty list is itself a claim, so if it
  is empty, say in `notes` why nothing is excluded.

Rules:
* A threat that does not name a component is not actionable; the planner will not be able to open
  work on it.
* Do not invent a vulnerability. This stage says where to look and what would matter, not what is
  there -- discovery and validation answer that with evidence.
* Use your tools to check the architecture map against the code when a threat depends on it.
* Record as you go: an asset, an actor or a threat worth keeping goes onto the blackboard with
  `record` (`asset`, `actor`, `threat`) as soon as it is grounded, not only in your final JSON. A
  cross-scope lead you do not want to chase yourself is `record` with kind `lead`.
* Work from the supplied deterministic survey and verify any component your threat depends on directly
  in source. Reconnaissance runs independently; do not wait for it or consume its findings.
* Output the JSON object described by the schema. No prose around it.
"""

SECURITY_INVENTORY_PROMPT = """\
You are the security-inventory agent. Reconnaissance and threat modelling have each completed one
independent pass. Build the concrete security surface map that the planner will use.

Enumerate, with source locations and evidence:
* entry_points -- HTTP/RPC routes, message consumers, scheduled jobs, CLI/process entry points;
* authorization_controls -- authentication, roles, object ownership, tenant boundaries and bypasses;
* dangerous_capabilities -- SQL/query execution, command/process execution, outbound requests,
  filesystem access, parsing/deserialization, template rendering and cryptographic operations;
* configurations -- security switches, exposed management/debug surfaces, CORS/CSRF/TLS/session
  settings, credentials and environment-dependent defaults;
* dependencies -- declared direct dependencies and versions relevant to the exposed surface;
* state_controls -- transactions, state transitions, idempotency, replay, locking and concurrency.

Each row must be a JSON object with at least `name`, `file`, `line`, `evidence`, and `why`. Use an
empty list only after checking that category. Read code/manifests to close gaps in Recon; do not copy
generic threats as facts. `coverage_gaps` must state anything you could not enumerate. This inventory
is planning context, not a vulnerability list: do not claim exploitability or emit candidates.
If the task names recovery sections, enumerate only those sections and leave the other arrays empty;
the harness will merge the focused results with the earlier partial answer.
Output only the JSON object described by the schema.
"""

DISCOVERY_PROMPT = """\
You are the discovery agent of a security review harness, working one scope. You propose
*candidates*: places where untrusted data plausibly reaches a dangerous operation, or where an
authorization decision plausibly goes wrong. A candidate is not a finding -- validation decides
that -- so your job is recall with a defensible reason, not certainty.

For each candidate record:
* the file (relative to the workspace root) and the line,
* the enclosing method when you can resolve it,
* a `vulnerability_type` from a real weakness class (sql_injection, path_traversal,
  command_injection, ssrf, xss, deserialization, authz_bypass, hardcoded_secret, ...),
* and a rationale that cites what you actually read: the route or caller that reaches this code,
  the parameter that carries the data, the call that acts on it.

Rules:
* Trace inward from the scope's entry points. A sink with no path from untrusted input is worth
  recording only if you say why you think the path exists.
* Do not report a candidate in a file you did not read.
* Prefer a handful of well-argued candidates over a long list. If you find nothing, say so in
  `notes` and return an empty `candidates` list -- an honest empty scope is a result.
* Output the JSON object described by the schema. No prose around it.
"""

VALIDATION_PROMPT = """\
You are the validation agent of a security review harness. You are given exactly one candidate.
Your job is to decide whether it is real, and to name the kind of evidence that decision needs.

Decide `confirmed` or `rejected`, and choose `evidence_kind`:
* `semantic` -- reading the code, its callers and its callees settles it. Use your `read`, `grep`
  and `shell_command` tools to look at the site, the methods around it, and the callers. `grep` is
  the one to reach for when you are looking for a control, a caller or a sibling; it searches the
  workspace in one call and does not count as reading a file.
* `dataflow` -- only a traced source-to-sink path settles it. Then you MUST call
  `dataflow_verify` with the candidate's file and line. The tool derives the sink itself from the
  code; you cannot and must not tell it what the sink is.

Then answer with your verdict:
* `rejected` requires `reasons` that state exactly what makes it not a finding: the sanitizer, the
  constant input, the authorization check, the unreachable branch, the parameter that never
  reaches the sink. "Probably fine" is not a reason.
* `confirmed` requires `reasons` that state what you verified, and `confidence` that is honest
  about what you could not see.
* When you used `dataflow_verify`, its returned path is attached to your verdict by the harness --
  do not paraphrase it, and do not claim a path the tool did not return.
* If the tool failed or returned nothing usable, say so in `reasons` and lower `confidence`; do not
  upgrade a failed verification into a confirmation.
* Output the JSON object described by the schema. No prose around it.
"""

VALIDATION_BATCH_PROMPT = """\
You are the validation batch agent of a security review harness. You are given **several separate
candidates in one run**. Each one gets its own verdict, and the rules below are what keeps several
decisions from becoming one:

* Judge every candidate in the list, and answer with one entry of `verdicts` per candidate, with
  `candidate_id` copied verbatim. A candidate you leave out stays undecided and has to be paid for
  again in a separate run.
* **One candidate's evidence may never settle another.** They were put in one run because they share
  source files, not because they share a weakness: a control that defuses one leaves the other
  exactly where it was. If you find yourself writing "same as above", the entries are wrong.
* `reasons` are per candidate and must name what you verified *for that candidate*.
* You have no `dataflow_verify` in this run, and that is deliberate: one trace cannot be attributed
  to several candidates. A candidate that can only be settled by a traced path gets
  `"verdict": "needs_dataflow"` -- say so and let the harness re-run it alone, with the tool. Do not
  guess at a path and do not call a semantic reading a trace.
* `confidence` is per candidate.
* Output the JSON object described by the schema. No prose around it.

## The single-candidate standard, unchanged

""" + VALIDATION_PROMPT


#: The batched form of `ATTACK_PATH_SCHEMA`. One run, one attack path per claim, each naming its own
#: claim. Same reason as the validation batch: the reading is shared (these candidates were confirmed
#: at sinks in the same files, reached by the same entry points), the judgement is not.
ATTACK_PATH_BATCH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "required": ["paths"],
    "properties": {
        "paths": {
            "type": "array",
            "maxItems": 6,
            "items": {
                "type": "object",
                "required": ["candidate_id", "reachable", "impact", "confidence"],
                "properties": {
                    "candidate_id": {
                        "type": "string",
                        "description": "the candidate id this path is about, copied verbatim",
                    },
                    "reachable": {"type": "boolean"},
                    "entry_points": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "for THIS candidate: the union across the instances listed",
                    },
                    "preconditions": {"type": "array", "items": {"type": "string"}},
                    "auth_conditions": {"type": "array", "items": {"type": "string"}},
                    "state_conditions": {"type": "array", "items": {"type": "string"}},
                    "impact": {"type": "string"},
                    "alternative_paths": {"type": "array", "items": {"type": "string"}},
                    "confidence": {"type": "number", "description": "0..1, about reachability"},
                },
            },
        },
    },
}


ATTACK_PATH_PROMPT = """\
You are the attack-path agent of a security review harness. You are given one *confirmed*
candidate: the code does this. Your question is different and separate -- can anyone actually make
it happen, and what does that cost them?

Establish, with your tools:
* reachability -- is the vulnerable code reachable from an entry point at all?
* entry_points -- which route, job, message consumer or CLI path reaches it.
* preconditions and state_conditions -- what must already be true (a feature flag, a row, an order
  of operations, a race window).
* auth_conditions -- what an attacker must hold to get there: nothing, any account, a specific
  role, admin, a second tenant's identifier, a leaked token.
* impact -- what the attacker gains, in this system's terms, not in general.
* alternative_paths -- other ways to the same effect, which matter when the obvious one is gated.

Rules:
* `confidence` here is confidence about *reachability*, not about the bug. That distinction is the
  point of this stage: confirmed code that nothing can reach is a different report entry from
  confirmed code the internet can call.
* Read the caller chain; do not reason about the framework in the abstract.
* If you cannot establish reachability, set `reachable` false and say what you could not see in
  the fields you did establish. An honest "unknown" beats an invented path.
* Output the JSON object described by the schema. No prose around it.
"""


ATTACK_PATH_BATCH_PROMPT = """\
You are the attack-path batch agent of a security review harness. You are given **several separate
confirmed candidates in one run**. Each one gets its own attack path, and the rules below are what
keeps several answers from becoming one:

* One entry of `paths` per candidate, with `candidate_id` copied verbatim. A candidate you leave out
  stays without a path, and the report says its reachability was never established.
* `reachable`, `entry_points`, `impact` and `confidence` are **per candidate**. They share source
  files because the harness put them together, not because they share reachability: the same route
  reaching one sink says nothing about the next.
* `entry_points` for each candidate must be the **union** across the instances named for it, not only
  the first one you looked at. If one instance is reachable anonymously and another only by an admin,
  that difference *is* the severity -- put it in `auth_conditions`.
* Output the JSON object described by the schema. No prose around it.

## The single-candidate standard, unchanged

""" + ATTACK_PATH_PROMPT


PLANNER_PROMPT = """\
You are the planning stage of a security review harness. You are given the repository's
architecture, its threat model, and a survey of its directories. Your job is to decide where the
discovery agents should spend their budget -- and to write down why.

The budget is finite and the point of this stage is that it is spent deliberately. For each scope
you open, the rationale must name what is being investigated and what makes it worth the budget:
which asset it touches, which threat it could carry, or which trust boundary it sits on.

Rules:
* Each scope investigates a concrete business operation or asset × security property.
  Controller/service/mapper and SSRF/injection are labels, not reasons to scan the whole tree again.
* Give each scope a stable id, a question, source starting files, rationale, completion_criteria
  and priority (1 highest, 3 lowest). File-review ownership is fixed by the coordinator.
* Proactively explore the threat model, including questions not yet raised by file reviews.
* The survey's scopes come from directory names, which is weak evidence. Confirm, correct or
  replace them -- and where you keep one unchanged, say in the rationale that the evidence is
  directory names.
* You may use your tools to check the architecture before planning against it.
* `excluded` is not optional thinking: name what you are deliberately not planning for, and why.
  An area silently absent from the plan is an area the coverage table cannot report on.
* Output the JSON object described by the schema. No prose around it.
"""


# ─────────────────────────────────────────────────────────── lite skills
#
# One line of extra instruction per scope kind, chosen from the architecture map. Deliberately a
# closed dict: a per-scope instruction is a small hint about *where to start*, and a registration
# API would turn it into a second, invisible agent definition.

LITE_SKILLS: dict[str, str] = {
    "web-route": (
        "LITE SKILL (web-route scope): start at the route annotations in this scope. For each "
        "handler, trace the request parameters (path, query, body, headers) into the service calls "
        "it makes, and follow those calls into the layer below before judging anything."
    ),
    "service-layer": (
        "LITE SKILL (service-layer scope): this code is reached from handlers rather than from the "
        "network. For each method, ask who calls it and with what arguments -- a method that looks "
        "safe is not, if a caller passes raw request data into it."
    ),
    "data-access": (
        "LITE SKILL (data-access scope): look for query construction that concatenates or formats "
        "its arguments, mapper/ORM escape hatches (raw SQL, `${}` in MyBatis, string-built JPQL), "
        "and dynamic table or column names. A parameterised call is not a finding."
    ),
    "batch-task": (
        "LITE SKILL (batch-task scope): this code runs on a schedule or from a queue rather than "
        "from a request. Establish what feeds it -- a file, a message, a remote response -- and "
        "treat that as the untrusted source."
    ),
    "config": (
        "LITE SKILL (config scope): look for credentials, keys and default passwords committed in "
        "configuration, debug or actuator endpoints left enabled, permissive CORS, disabled TLS "
        "verification and deserialization switches."
    ),
    "entrypoint": (
        "LITE SKILL (entrypoint scope): establish what this process exposes and with which "
        "configuration, then use that to decide which of the other scopes are actually reachable."
    ),
}

#: Used when a component's `kind` is missing or unknown. Naming the fallback keeps the scope's
#: prompt honest about not having a specialisation, instead of silently running with none.
DEFAULT_LITE_SKILL = (
    "LITE SKILL (no specialisation for this scope's kind): begin by listing the files in the scope "
    "and reading the ones that carry its responsibility; establish entry points before sinks."
)


def lite_skill(kind: str | None) -> str:
    """The instruction block for a scope kind, or the honest default."""
    key = (kind or "").strip().lower()
    return LITE_SKILLS.get(key, DEFAULT_LITE_SKILL)


def component_kind(component: dict[str, Any]) -> str | None:
    """The scope kind of an architecture component, tolerating the several names producers use."""
    for field in ("kind", "type", "scope_kind", "category"):
        value = component.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    return None


def lite_skill_for_scope(blackboard: Blackboard, scope_id: str) -> str:
    """Look the scope up in the architecture map and pick its lite skill.

    Returns the default block when the scope is not in the map: a scope the planner invented is a
    normal case (a trust boundary is not a directory), and it must still get instructions.
    """
    architecture = blackboard.architecture
    if architecture is not None:
        for component in architecture.components:
            names = {
                str(component.get(field) or "").strip()
                for field in ("id", "name", "scope_id", "title", "path")
            }
            if scope_id in names:
                return lite_skill(component_kind(component))
    return lite_skill(None)


#: What a coverage-group agent is told instead of a scope specialty.
#:
#: Why a group of *files* rather than a directory role: partitioning by directory is a scheduling
#: decision and the planner can get it wrong in a way that hides a whole layer. Measured on the Java
#: benchmark, the planner produced four scopes that were all `web-route`, so the service and
#: data-access layers were never dispatched to anyone, and 21 of 30 known positives sat in files no
#: agent opened. A per-scope skill cannot repair a missing scope; an inventory that is handed out
#: until every file has been read can.
COVERAGE_GROUP_SKILL = (
    "COVERAGE GROUP. You are given a list of files and you own them: read each one end to end "
    "before you conclude anything, because the run measures coverage from your `read` calls and a "
    "file you did not finish is a file nobody looked at. The group is a scheduling boundary, not a "
    "boundary on what can be vulnerable -- follow a lead into any other file you need (callers, "
    "configuration, a mapper or template the code uses), and report candidates anywhere, including "
    "layers no other agent was assigned. Work the class list below against these files: a class this "
    "code cannot support is a legitimate negative, but it has to be stated rather than skipped."
)


def coverage_scope_id(index: int) -> str:
    """The scope id for the `index`-th coverage group. Recognised by prefix, so nothing needs a
    second registry to tell a coverage group from a model-chosen scope."""
    return f"{coverage.COVERAGE_SCOPE_PREFIX}{index}"


def skill_kinds_for_files(files: list[str]) -> list[str]:
    """The lite-skill kinds a group of files calls for, in a stable order.

    Selected by **what the files are**, not by what the scope is called, and that distinction is the
    whole point. The previous implementation looked the scope id up in the architecture map, and the
    planner invents ids -- `scope-route-orders-sql`, `scope-route-products-orderby`, `scope-coverage-3`
    -- which never appear there. Measured on the Java benchmark: **all fourteen scopes fell through to
    the "no specialisation" default**, so the config guidance was never sent to the agent holding
    `application.yml`. That agent found the two hardcoded credentials in that file and missed the
    three one-line switches in it (`include: "*"` on actuator exposure, `h2.console.enabled: true`,
    `include-stacktrace: always`), which is what an instruction-delivery failure looks like: the file
    was read end to end and the model's attention went where its instructions pointed.

    The mapping reuses `survey._role_of` and `survey.CONFIG_SUFFIXES` rather than inventing a second
    one, so a file cannot count as code for the scope plan and as configuration for its instructions.
    """
    kinds: list[str] = []
    for name in files:
        role, _ = survey._role_of(name)
        kind = role if role and role != "config" else None
        if kind is None and Path(name).suffix.lower() in survey.CONFIG_SUFFIXES:
            kind = "config"
        if kind and kind not in kinds:
            kinds.append(kind)
    return kinds


def discovery_extra_system(
    blackboard: Blackboard, scope_id: str, *, index: int, files: list[str] | None = None
) -> str:
    """Everything a discovery agent is told beyond its task.

    The blocks, and what each answers that the others do not:

    * the **scope specialty** (`LITE_SKILLS`) -- what this kind of code is for. Chosen from the files
      the agent owns, one block per kind present, because a group of six files can span layers;
    * the **whole-repository mandate** when this is a coverage group, which is a scheduling boundary
      and not a boundary on what can be vulnerable;
    * the **perspective** -- where to start looking, indexed rather than derived from the scope kind
      because the planner decides that kind and, measured, produced four scopes of the same kind;
    * the **class sweep** -- what an auditor must not leave unexamined, including the obligation to
      say which classes this scope cannot support;
    * the **sibling sweep** and the **finding bar** -- what to enumerate around a hit, and what is
      worth recording at all.

    `index` shifts with the round as well as the position, so a scope re-dispatched for being
    INSUFFICIENT is approached from a *different* perspective the second time. A re-dispatch that
    repeats the same starting point is a re-run, not a second look.
    """
    specialties = [lite_skill(kind) for kind in skill_kinds_for_files(files or [])] or [lite_skill(None)]
    if scope_id.startswith(coverage.COVERAGE_SCOPE_PREFIX):
        # Forward *and* backward: a coverage pass that only follows input from the request side never
        # arrives at a sink whose entry point is not obvious, which is the gap this exists to close.
        opening = "\n\n".join(
            [
                COVERAGE_GROUP_SKILL,
                *specialties,
                skills.PERSPECTIVES["forward"],
                skills.PERSPECTIVES["backward"],
            ]
        )
    else:
        opening = "\n\n".join([*specialties, skills.perspective_for(index)])
    return "\n\n".join(
        (
            opening,
            skills.classes_for_prompt(),
            skills.SIBLING_SWEEP,
            skills.FINDING_BAR,
            skills.COVERAGE_RULE,
        )
    )


def validation_extra_system(blackboard: Blackboard, scope_id: str, *, files: list[str] | None = None) -> str:
    """What the validation agent is told beyond its task.

    Two things, and both are corrections to a measured failure. The **specialty** is chosen from the
    candidate's own file, so a configuration finding is judged against what configuration is for. The
    **sibling rule** matters here as much as it does in discovery, and for the opposite failure: a
    validator that finds an effective control on one member of a family will reject the whole family
    with it, which is how a safe sibling turns into evidence against a vulnerable one.
    """
    specialties = [lite_skill(kind) for kind in skill_kinds_for_files(files or [])]
    return "\n\n".join([*specialties, skills.SIBLING_SWEEP])


# ─────────────────────────────────────────────────────────── the agent spec


@dataclass(frozen=True)
class AgentSpec:
    """What an agent is: its prompt, its allow-list, and the schema its `final` must fit."""

    name: str
    prompt: str
    tools: tuple[ToolName, ...]
    schema: dict[str, Any] | None = None
    #: `maxItems` and friends live in the schema; this is the coordinator's own bound, and both
    #: exist because a model that ignores the schema must still not be able to blow the budget.
    max_output_items: int = 8


AGENTS: dict[str, AgentSpec] = {
    PLAN_UPDATE: AgentSpec(
        name=PLAN_UPDATE,
        prompt="You are the Planner. Process only the supplied known leads. Return decisions; never remove file review tasks. "
        "Use link for the same question on an existing investigation, create only for an independent concrete question, "
        "defer or dismiss with a reason. Do not invent further questions. Each decision needs lead_id, action, reason. "
        "link needs work_id; create needs title, files, completion_criteria, optional priority (1 highest, 3 lowest). "
        "priority needs work_id and priority; merge needs source_work_id and work_id, only identical unstarted "
        "investigations with the same question and files can merge. Never merge a file-review task. "
        "Titles should be operation/asset × security property.",
        tools=(),
        schema={"type": "object", "required": ["decisions"], "properties": {
            "decisions": {"type": "array", "items": {"type": "object", "required": ["lead_id", "action", "reason"],
                "properties": {key: {"type": "string"} for key in
                    ("lead_id", "action", "reason", "work_id", "source_work_id", "title", "completion_criteria")}
                | {"priority": {"type": "integer", "minimum": 1, "maximum": 3},
                   "files": {"type": "array", "items": {"type": "string"}}}}}},
        },
        max_output_items=40,
    ),
    RECON: AgentSpec(
        name=RECON,
        prompt=RECON_PROMPT,
        tools=(
            ToolName.LIST_FILES,
            ToolName.READ,
            ToolName.GREP,
            ToolName.SHELL,
            ToolName.RECORD,
        ),
        schema=RECON_SCHEMA,
    ),
    THREAT_MODEL: AgentSpec(
        name=THREAT_MODEL,
        prompt=THREAT_MODEL_PROMPT,
        tools=(ToolName.READ, ToolName.GREP, ToolName.LIST_FILES, ToolName.RECORD),
        schema=THREAT_MODEL_SCHEMA,
    ),
    SECURITY_INVENTORY: AgentSpec(
        name=SECURITY_INVENTORY,
        prompt=SECURITY_INVENTORY_PROMPT,
        tools=(ToolName.READ, ToolName.GREP, ToolName.LIST_FILES, ToolName.SHELL),
        schema=SECURITY_INVENTORY_SCHEMA,
        max_output_items=200,
    ),
    PLANNER: AgentSpec(
        name=PLANNER,
        prompt=PLANNER_PROMPT,
        tools=(ToolName.READ, ToolName.GREP, ToolName.LIST_FILES, ToolName.SHELL),
        schema=PLANNER_SCHEMA,
        max_output_items=40,
    ),
    DISCOVERY: AgentSpec(
        name=DISCOVERY,
        prompt=DISCOVERY_PROMPT + "\nPublish evidence, candidates and independent leads immediately with record. "
        "Record unfinished checks using kind=gap: unread/basic_check/relationship/tool_failure, "
        "with question,file,line,reason. Before finishing, resolve each known gap with state=resolved "
        "and evidence_refs to recorded source facts, or retain its concrete breakpoint. "
        "Use board before key tracing and before finishing to read task updates. "
        "Evidence uses JSON {file,line,text,category: source_fact|hypothesis}; candidates use the final candidate fields. "
        "Leads use {to_scope,question,file,line,evidence_refs,why}. Follow cross-file relations needed for your "
        "current question yourself; only independent questions become leads. Never spawn agents. "
        "Discovery cannot publish validation conclusions.",
        tools=(ToolName.READ, ToolName.GREP, ToolName.LIST_FILES, ToolName.SHELL, ToolName.RECORD, ToolName.BOARD),
        schema=DISCOVERY_SCHEMA,
    ),
    VALIDATION: AgentSpec(
        name=VALIDATION,
        prompt=VALIDATION_PROMPT,
        tools=(ToolName.READ, ToolName.GREP, ToolName.SHELL, ToolName.DATAFLOW_VERIFY),
        schema=VALIDATION_SCHEMA,
    ),
    VALIDATION_BATCH: AgentSpec(
        name=VALIDATION_BATCH,
        prompt=VALIDATION_BATCH_PROMPT,
        # No `dataflow_verify` on purpose: one run cannot attribute one trace to four claims, and a
        # mis-attributed path is worse than no path. A claim that needs one says `needs_dataflow` and
        # gets its own run, which has the tool.
        tools=(ToolName.READ, ToolName.GREP, ToolName.SHELL),
        schema=VALIDATION_BATCH_SCHEMA,
        max_output_items=6,
    ),
    ATTACK_PATH: AgentSpec(
        name=ATTACK_PATH,
        prompt=ATTACK_PATH_PROMPT,
        tools=(ToolName.READ, ToolName.GREP, ToolName.LIST_FILES, ToolName.SHELL),
        schema=ATTACK_PATH_SCHEMA,
    ),
    ATTACK_PATH_BATCH: AgentSpec(
        name=ATTACK_PATH_BATCH,
        prompt=ATTACK_PATH_BATCH_PROMPT,
        tools=(ToolName.READ, ToolName.GREP, ToolName.LIST_FILES, ToolName.SHELL),
        schema=ATTACK_PATH_BATCH_SCHEMA,
        max_output_items=6,
    ),
}


def spec(name: str) -> AgentSpec:
    try:
        return AGENTS[name]
    except KeyError:  # pragma: no cover - a typo in the coordinator, caught by the test suite
        raise KeyError(f"unknown agent {name!r}; known: {', '.join(sorted(AGENTS))}") from None


# ─────────────────────────────────────────────────────────── task builders
#
# A task is the *user* message: what this run of this agent is about. It re-states the facts the
# agent needs rather than assuming the blackboard's whole content -- an agent given the entire
# blackboard would spend its steps reading state instead of code.


def _json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


#: How many file names of a surveyed scope the opening agents are shown. Enough to orient, bounded so
#: that a 40-scope survey cannot turn the task itself into a file listing the agent then pays to read.
PREP_FILES_PER_SCOPE = 6

#: Handed to the two opening agents. They run *concurrently*, and this is the instruction that makes
#: that safe: the blackboard is the only channel between them, so a fact that stays in a model's head
#: until its final JSON is a fact the other agent cannot use. Written as a task line rather than a
#: system-prompt rule because it is only true of the concurrent stages -- discovery and validation hand
#: their results to the coordinator as they go.
INCREMENTAL_RECORD = (
    "边走边记：每确认一条事实（语言、构建方式、入口、组件、信任边界、资产、攻击者、威胁），"
    "立刻用 record 工具写进共享黑板，不要攒到最后一次性汇报。与你同时运行的 agent 只能看到黑板，"
    "看不到你的推理过程。反过来，你想知道它刚确认了什么，用 board 工具读黑板——"
    "你的 task 在开跑时就定死了，不会自动更新，board 是唯一能看到它后续写入了什么的途径。"
    "只记你已经用工具确认过的东西；最后提交的 JSON 仍是你自己的结论。"
    "**但记录不是这一轮的交付物**：记录工具回“与已有内容重复，已去重”就说明这条已经在黑板上了，"
    "不要再换个说法重记一遍（换个说法的同一条事实也算重复）；你的 turn 预算有限，"
    "把最后几轮留给 final——一个只留下一堆记录、没有 final 的 agent，对本轮等于什么都没产出。"
    "一次回答里**不要塞太多长文本**：一次记一到两条，`text` 写短；"
    "一个超长的回答会被输出上限截断，那样里面一个调用都不会执行。"
)

#: Said to the threat model when a deterministic pre-scan is on the board, so it can tell the
#: orchestrator's counted facts and directory-derived components apart from recon's reading of the code.
SURVEYED_ORIGIN = (
    "黑板上 notes/rationale 以 `survey:` 开头的条目来自编排层的确定性预扫描（只数文件、读目录名、"
    "扫入口标记，没有调用模型），不是 recon 对代码的理解；两者不一致时以你能在代码里验证的为准。"
)


def prep_payload(snapshot: dict[str, Any] | None) -> dict[str, Any] | None:
    """The deterministic pre-scan in the shape a model reads it, or `None` if there was none.

    Read off the snapshot's attribute-bearing objects (`Scope` is a plain dataclass) rather than
    re-walking the tree: the whole point of doing this once in `_prepare` is that the opening agents and
    the planner all consume the *same* reading of the tree.
    """
    if not snapshot:
        return None
    project = snapshot.get("project")
    scopes = snapshot.get("scopes") or []
    return {
        "languages": snapshot.get("languages") or getattr(project, "languages", {}),
        "build_systems": list(getattr(project, "build_systems", []) or []),
        # Named as markers, not as `entry_points`, because that is what they are: a grep for route and
        # bootstrap patterns, one hit per *file*. They are here as leads -- "these files register
        # handlers, open them and enumerate the actual routes" -- and they are deliberately not put on
        # the blackboard, where `entry_points` means "entries an agent read" (`_prepare` explains the
        # 55-vs-42 measurement that decided it).
        "route_markers_in_code": list(getattr(project, "entry_points", []) or []),
        "candidate_scopes": [
            {
                "id": scope.scope_id,
                "title": scope.title,
                "kind": scope.kind,
                "path": scope.path,
                "files": list(scope.files[:PREP_FILES_PER_SCOPE]),
                "file_count": len(scope.files),
            }
            for scope in scopes
        ],
    }


def security_inventory_payload(
    inventory: Any, *, per_section: int | None = 8
) -> dict[str, Any]:
    """The inventory as planner input: counts plus full rows or a bounded preview.

    `None` (the stage did not run -- a dry run, or the opening produced nothing) becomes an empty
    dict, and the planner's prompt says so by being short. The full lists stay on the blackboard;
    The coordinator passes ``per_section=None`` because Planner has no ``board`` tool and therefore
    needs the complete inventory. The bounded default remains useful for reports and callers that only
    need a preview.
    """
    if inventory is None:
        return {}
    sections = (
        "entry_points",
        "authorization_controls",
        "dangerous_capabilities",
        "configurations",
        "dependencies",
        "state_controls",
    )
    out: dict[str, Any] = {}
    for name in sections:
        items = list(getattr(inventory, name, []) or [])
        out[name] = {
            "count": len(items),
            "items": items if per_section is None else items[:per_section],
        }
    out["coverage_gaps"] = list(getattr(inventory, "coverage_gaps", []) or [])
    return out


def recon_task(
    workspace: str,
    *,
    prep: dict[str, Any] | None = None,
    delta: str = "",
    root_hint: str = "",
) -> str:
    lines = [
        f"Workspace root: {workspace}",
        "Establish what this repository is. Start with a listing, then read the build files and "
        "the bootstrap/entry points, then map the components and trust boundaries.",
    ]
    payload = prep_payload(prep)
    if payload is not None:
        lines.append(
            "A pre-scan already walked the tree (deterministic: it counts files, reads directory names "
            "and greps entry-point markers -- no model, no tools) and its result is on the blackboard. "
            "Treat it as a starting point to verify, correct and extend, never as an answer: it cannot "
            "tell you what the code does. `route_markers_in_code` in particular is one hit per *file* "
            "that looks like it registers handlers -- open those files and enumerate the actual routes "
            "yourself, one entry point each; do not copy the markers into `entry_points`."
        )
        lines.append(_json(payload))
    if delta:
        lines.append(delta)
    lines.append(INCREMENTAL_RECORD)
    if root_hint:
        lines.append(root_hint)
    return "\n".join(lines)


def threat_model_task(blackboard: Blackboard, *, delta: str = "") -> str:
    return "\n".join(
        [
            "Deterministic survey context for this repository:",
            _json(
                {
                    "project": _dump(blackboard.project),
                    "architecture": _dump(blackboard.architecture),
                    "workspace": blackboard.workspace,
                }
            ),
            "Reconnaissance runs independently from the same frozen survey. Verify threat-relevant "
            "facts directly in source; you cannot consume Recon's output in this stage.",
            SURVEYED_ORIGIN,
            *([delta] if delta else []),
            INCREMENTAL_RECORD,
            "Produce the threat model, including what is explicitly out of scope.",
        ]
    )


def security_inventory_task(blackboard: Blackboard) -> str:
    return "\n".join([
        f"Workspace root: {blackboard.workspace}",
        "Reconnaissance and threat-model outputs:",
        _json({"project": _dump(blackboard.project),
               "architecture": _dump(blackboard.architecture),
               "threat_model": _dump(blackboard.threats)}),
        "Reconcile these outputs against source and manifests. Enumerate the security surface fully; "
        "record uncertainty in coverage_gaps instead of guessing.",
    ])


def stored_read(blackboard: Blackboard, file: str) -> AgentStep | None:
    """A *complete* read of `file` that this run has already done, if there is one.

    The blackboard already holds the material: every `read` keeps its `lines`, and the audit that
    exposed this problem had 471 of them -- 220 KB of file text, `repo.py` alone stored 88 times. Only
    `coverage.from_runs` ever looked at them, to decide whether a file had been read end to end. So
    the sharing this harness was missing was not missing data; it was missing a reader.

    Complete, not merely present: `returned_lines == total_lines`. Handing over a partial read as if it
    were the file is exactly the false-coverage claim the ledger exists to prevent, and the whole point
    of reusing a stored read is that it is the same bytes an agent already saw.

    The same run only. The workspace is mounted read-only for an audit, so within a run a stored read
    cannot be stale; across runs it could be, and nothing here would notice.
    """
    best: AgentStep | None = None
    for run in blackboard.runs:
        for step in run.steps:
            result = step.result
            call = step.call
            if call is None or result is None or not result.ok:
                continue
            if call.tool is not ToolName.READ:
                continue
            data = result.data or {}
            if str(data.get("path") or "") != file:
                continue
            total = int(data.get("total_lines") or 0)
            returned = int(data.get("returned_lines") or 0)
            if total <= 0 or returned < total:
                continue
            # The longest complete read wins, and later runs win ties: a second read of the same file
            # in the same run is the same bytes, so either answer is correct and picking one keeps the
            # choice deterministic.
            best = AgentStep(index=0, thought=SCOPE_REUSE_THOUGHT, call=call, result=result)
    return best


def replayable_reads(
    blackboard: Blackboard,
    files: list[str],
    *,
    budget: int,
) -> tuple[list[AgentStep], list[str], list[str]]:
    """`(steps, reused, missing)`: complete reads this run has already done, ready to be seeded.

    The sharing this harness was missing was not data, it was a reader: the blackboard already holds
    every `read` result -- 471 of them on the audit that found this, 220 KB of file text with `repo.py`
    alone stored 88 times -- and `coverage.from_runs` was the only thing that ever looked. This is the
    reader, and it is deliberately the *only* one: it never touches the tool layer and never reads the
    disk. A file with no complete read on the board is reported in `missing`, and the caller names it
    in the agent's task text so the agent reads it itself.

    Three properties make this honest rather than a trick:

    * **Real `read` results.** The replayed step carries the original call and result verbatim, so the
      coverage ledger counts it exactly as it counted the model's own read -- no new accounting rule
      and no synthetic "pretend it was read" record.
    * **Complete only.** `returned_lines == total_lines`, or nothing (see `stored_read`). Handing over
      a partial read as if it were the file is exactly the false-coverage claim the ledger exists to
      prevent.
    * **Bounded, and it skips rather than truncates.** A file is seeded only if it fits what is left of
      `budget`; anything larger is named in `missing` and the agent reads it itself. Sending half a
      file while the ledger calls it covered is the worst outcome available here.

    `files` is required, and an empty list is a no-op. It is not optional on purpose: a caller with no
    file list would be asking for "everything this run has read", and an agent handed files that are
    not its business is how one scope's context ends up being the whole repository. A planner-created
    scope can own no files at all (see `_planner_call`); those share nothing rather than everything.

    Cross-agent reuse is the point and is always allowed: the workspace is mounted read-only for an
    audit, so a complete read cannot be stale, and two agents reading one file get the same bytes.
    """
    if budget <= 0 or not files:
        return [], [], []
    steps: list[AgentStep] = []
    reused: list[str] = []
    missing: list[str] = []
    used = 0
    for name in files:
        step = stored_read(blackboard, name)
        if step is None or step.result is None:
            missing.append(name)
            continue
        size = len(step.result.summary or "")
        if used + size > budget:
            missing.append(name)
            continue
        steps.append(step)
        reused.append(name)
        used += size
    return steps, reused, missing


def prefetch_scope_files(
    files: list[str],
    context: Any,
    *,
    budget: int,
    blackboard: Blackboard | None = None,
    from_disk: bool = False,
) -> tuple[list[AgentStep], list[str], list[str], list[str]]:
    """Read a scope's files for a *re-dispatched* discovery run, reusing what the run already read.

    The measurement that led here: 88 agent runs, 471 `read` calls, and the repository has six files.
    Every run read all of them -- `repo.py` was opened by 88 distinct runs. A re-dispatched discovery
    agent is a *fresh* agent with no transcript, so "you already read these" is not something it can
    act on: it has never seen the code, and the only way for it to reason about a file is to read it.
    Rounds 1-3 therefore read *more* per run than round 0 (5.9 vs 4.7), which is where 110 of the 143
    discovery reads went.

    So the harness supplies them, and it takes them **from the blackboard first** -- a complete read
    this run already performed is the same bytes, and re-reading the disk to hand over what is already
    in memory is how a shared state ends up being written by everyone and read by no one. The tool is
    the fallback, for a file this run has not read yet.

    Four properties make this honest rather than a trick:

    * **Real `read` results, from either source.** The reused step carries the original call and result
      verbatim, so the coverage ledger counts it exactly as it counted the model's own read -- no new
      accounting rule, and no synthetic "pretend it was read" record.
    * **It is bounded, and it refuses rather than truncates.** A file is inlined only if it fits the
      remaining budget; anything larger is skipped and named, and the agent reads it itself. Handing
      over half a file while the ledger called it covered would be the worst outcome available here.
    * **Only a re-dispatch, only this scope's files.** Round 0 keeps reading for itself (that is the
      evidence the coverage rule is built on), and no agent is ever handed the whole repository --
      files a scope does not own are not its business.
    * **`budget = 0` switches it off**, so the cost can be measured against a run without it.

    **The default is blackboard-only.** A complete read this run already performed is the same bytes, so
    the agent is *seeded* with it instead of spending a turn fetching it, and no file is read off the
    disk for a scope whose bytes are already in the run's transcript. The disk branch sits behind
    `from_disk=True` and is off by default for two reasons: it puts a full copy of the file in the
    prompt even when the agent would not have chosen to read it, and on a scope larger than `budget` it
    skips whole files *after* having read them. The switch is kept so the measurement above stays
    reproducible and the choice stays reversible.

    Returns `(steps, from_ledger, from_disk, skipped)`.
    """
    if budget <= 0 or not files:
        return [], [], [], []
    if blackboard is None:
        steps: list[AgentStep] = []
        reused: list[str] = []
        missing = list(files)
    else:
        steps, reused, missing = replayable_reads(blackboard, files, budget=budget)
    if not from_disk:
        # Blackboard only. A file with no complete read on the board is named in the last slot so the
        # agent reads it itself -- which is also what the coverage ledger wants for a re-dispatch.
        return steps, reused, [], list(missing)

    from services.harness import react

    try:
        _, _, _, invoke, _ = react.tool_layer()
    except react.ToolLayerUnavailable:
        # The reuse above needed no tool layer, so it survives; only the disk half is lost.
        return steps, reused, [], list(missing)

    used = sum(len(step.result.summary or "") for step in steps if step.result is not None)
    read: list[str] = []
    skipped: list[str] = []
    for name in missing:
        offset = 1
        pending: list[AgentStep] = []
        size = 0
        while True:
            call = ToolCall(
                tool=ToolName.READ,
                arguments={"path": name, "offset": offset},
                reason=SCOPE_PREFETCH_REASON,
            )
            try:
                result = invoke(context, call)
            except Exception as exc:  # noqa: BLE001 - a tool layer that raises is a result
                result = ToolResult(
                    tool=ToolName.READ, ok=False, error=f"read 调用异常：{type(exc).__name__}: {exc}"
                )
            if not result.ok:
                break
            size += len(result.summary or "")
            pending.append(
                AgentStep(index=0, thought=SCOPE_PREFETCH_THOUGHT, call=call, result=result)
            )
            next_offset = (result.data or {}).get("next_offset")
            if not next_offset:
                break
            offset = int(next_offset)
        if pending and used + size <= budget:
            steps.extend(pending)
            read.append(name)
            used += size
        else:
            # Skipped whole, never half: a partially inlined file is one the agent will read anyway,
            # and calling it covered on the strength of the part we sent would be a false coverage
            # claim -- the exact failure mode the ledger exists to prevent.
            skipped.append(name)
    return steps, reused, read, skipped


def discovery_task(
    blackboard: Blackboard,
    item: WorkItem,
    *,
    attempt: int = 1,
    files: list[str] | None = None,
    reused: list[str] | None = None,
    prefetched: list[str] | None = None,
    skipped: list[str] | None = None,
) -> str:
    lines = [
        f"Scope: {item.scope_id} -- {item.title}",
        f"Why this scope was opened: {item.rationale}",
        f"Question: {item.question or item.title}",
        f"Completion criteria: {item.completion_criteria}",
        f"Priority: {item.priority} (1 highest)",
        "Unread source intervals [start,end inclusive; null means EOF]. On continuation use read "
        "offset/limit to finish these intervals; re-read other lines only when needed for the check: "
        + _json(item.unread_ranges),
        "Known gaps (continue these exact checks; preserve unresolved questions): "
        + _json([gap.model_dump(mode="json") for gap in item.gaps if gap.state != "resolved"]),
        f"Workspace root: {blackboard.workspace}",
    ]
    already = [*(reused or []), *(prefetched or [])]
    if already:
        if attempt > 1:
            lines.append(
                "These files are already read for you and their contents are in this transcript as the "
                "first steps -- do not read them again, and do not re-report what they obviously contain. "
                "Your job is the second look: a path you have not followed, a caller you have not checked, "
                "a control whose absence matters here.\n"
                + "\n".join(f"  - {name}（已读入）" for name in already)
            )
        else:
            lines.append(
                "These files are already in this transcript as the first steps -- another scope read "
                "them completely, so do not read them again. Your job is the *first* analysis of this "
                "scope: report what is wrong with the code you can already see, and read anything else "
                "you own yourself.\n"
                + "\n".join(f"  - {name}（已读入，不要重读）" for name in already)
            )
    if skipped:
        lines.append(
            "These files are not in this transcript, so read them yourself:\n"
            + "\n".join(f"  - {name}" for name in skipped)
        )
    owned = [name for name in (files or []) if name not in set(already)]
    if owned:
        lines.append(
            "Files you own -- read each one end to end, and report which of them you finished. "
            "These files are independent of one another, so put several `read` calls in ONE turn "
            "rather than one per turn: a turn is a round trip, and spending one per file is how the "
            "group fails to finish inside its budget.\n"
            + "\n".join(f"  - {name}" for name in owned)
        )
    elif files:
        lines.append(
            "Every file you own is already in this transcript (listed above). Do not read them again; "
            "report which of them you finished, based on what you have."
        )
    if attempt > 1:
        lines.append(
            f"This is discovery round {attempt} over this scope. Earlier rounds left it "
            "INSUFFICIENT: either nothing was found and the scope was not actually covered, or "
            "what was found was not enough. Look somewhere you have not looked yet, or explain in "
            "`notes` what makes the scope genuinely empty."
        )
    if blackboard.threats is not None:
        lines.append("Threat model (what matters here):\n" + _json(_dump(blackboard.threats)))
    seen = [
        {"candidate_id": c.candidate_id, "title": c.title, "file": c.file, "line": c.line}
        for c in blackboard.candidates
        if c.scope_id == item.scope_id
    ]
    if seen:
        # Sending the already-known candidates is what makes a second round *additive* rather than
        # a re-run: without it the model re-proposes what round one found.
        lines.append("Already recorded candidates for this scope (do not repeat them):\n" + _json(seen))
    return "\n".join(lines)


#: What makes a candidate "taint-shaped": the question is whether attacker-controlled data
#: *reaches* the site, which is the one thing reading the code cannot settle on its own. Matched on
#: substrings of the normalised type rather than by equality, because the vocabulary is open -- the
#: deterministic survey names types from its own rules while discovery names them from what the
#: model wrote, so the same finding arrives as `sql_injection`, `SQL Injection` or
#: `template_injection` depending on the run.
TAINT_MARKERS: tuple[str, ...] = (
    "injection",   # sql, command, template, ldap, log, header, expression, jndi
    "ssrf",
    "xxe",
    "xss",
    "traversal",
    "deserial",    # deserialization / deserialisation
    "redirect",
    "forgery",     # CSRF / request forgery
)

#: What the harness writes in the `thought` slot of the step it issues itself. Kept distinct from
#: anything a model would say, so the transcript never leaves the reader guessing who decided to run
#: the trace.
HARNESS_PREFETCH_THOUGHT = (
    "harness（不是模型）：污点类候选在交给验证 agent 之前，由编排层强制先做一次数据流验证"
)

#: The same convention for a re-dispatched scope's files: the harness read them, not the agent.
#: The disk branch of `prefetch_scope_files` is now off by default (`from_disk=False`); this marker
#: survives for the `from_disk=True` reproducibility path.
SCOPE_PREFETCH_THOUGHT = (
    "harness（不是模型）：本 scope 被重派发，编排层先把这些文件读进来，"
    "免得每个新 agent 都把同一批文件重读一遍"
)
SCOPE_PREFETCH_REASON = "编排层在重派发的 discovery 之前预读本 scope 的文件（覆盖率按真实 read 台账计算）"

#: And for a file the run had already read: the material comes out of the blackboard, not off the disk.
SCOPE_REUSE_THOUGHT = (
    "harness（不是模型）：本文件本次运行已经完整读过，直接复用当时的 read 结果（黑板上就有），"
    "没有重复读盘"
)


def _reused_files(initial_steps: list[AgentStep] | None) -> list[str]:
    """The files a run was handed out of the blackboard, read off the seeded steps.

    Derived rather than passed in as a parameter, for the same reason the coverage ledger is derived
    from real `read` calls: a separate argument is a second source of truth that can drift from the
    transcript it describes. The `thought` marker is what separates a reused read from a read the
    harness performed itself (`SCOPE_PREFETCH_THOUGHT`) or a forced dataflow trace
    (`HARNESS_PREFETCH_THOUGHT`).
    """
    found = [
        str((step.result.data or {}).get("path") or "")
        for step in (initial_steps or [])
        if step.thought == SCOPE_REUSE_THOUGHT and step.result is not None and step.result.ok
    ]
    return [name for name in dict.fromkeys(found) if name]


def is_taint_candidate(candidate: Candidate) -> bool:
    """Does deciding this candidate need a traced source-to-sink path?"""
    kind = (candidate.vulnerability_type or "").strip().lower().replace("-", "_").replace(" ", "_")
    return any(marker in kind for marker in TAINT_MARKERS)


def verify_taint_candidate(candidate: Candidate, context: Any) -> AgentStep | None:
    """Run `dataflow_verify` for a taint-shaped candidate, before any model sees it.

    Why the harness calls this instead of asking the model to: with the choice left to the model, a
    measured run over ten candidates produced **zero** `dataflow_verify` calls and ten
    `evidence_kind=semantic` verdicts. Reading the code is cheaper and usually feels sufficient, so
    the taint engine -- the one thing this harness has that reading does not -- went unused on the
    exact candidate class it exists for. Whether a trace was attempted is a fact about the pipeline,
    not a preference to delegate.

    The call sends `{file, line}` and nothing else. No sink is sent and none can be: the engine
    derives it from the hit's position, so text inside the reviewed repository has nothing to
    nominate.

    The result is returned as an `AgentStep` with index 0, to be *prepended* to the validation run.
    That is what makes the rest of the pipeline work unchanged: the transcript shows the call, the
    tool's own `DataflowEvidence` is what reaches the verdict, and a model that also ran its own
    trace still wins, because the search for evidence reads the run backwards.

    Returns None when the tool layer is not installed at all.
    """
    from services.harness import react

    try:
        _, _, _, invoke, _ = react.tool_layer()
    except react.ToolLayerUnavailable:
        return None

    arguments: dict[str, Any] = {"file": candidate.file}
    if candidate.line is not None:
        arguments["line"] = candidate.line
    call = ToolCall(
        tool=ToolName.DATAFLOW_VERIFY,
        arguments=arguments,
        reason=(
            "编排层在验证前强制做数据流验证：污点类候选的“数据是否到达”不由模型自行决定是否追"
        ),
    )
    try:
        result = invoke(context, call)
    except Exception as exc:  # noqa: BLE001 - a tool layer that raises is a result, not a crash
        result = ToolResult(
            tool=ToolName.DATAFLOW_VERIFY,
            ok=False,
            error=f"dataflow_verify 调用异常：{type(exc).__name__}: {exc}",
        )
    return AgentStep(index=0, thought=HARNESS_PREFETCH_THOUGHT, call=call, result=result)


def validation_task(
    blackboard: Blackboard,
    candidate: Candidate,
    *,
    prefetched: AgentStep | None = None,
    dataflow: Any = None,
    material_budget: int = 0,
) -> str:
    lines = [
        f"Scope: {candidate.scope_id} -- candidate {candidate.candidate_id}",
        "Decide whether this candidate is a real finding, and which kind of evidence settles it.",
        _json(_dump(candidate)),
        f"Workspace root: {blackboard.workspace}",
    ]
    packet = _material(blackboard, candidate, dataflow=dataflow, budget=material_budget)
    if packet:
        lines.append(packet)
    if prefetched is not None:
        # The tool's answer is already in the transcript as turn 0, so it is not repeated here:
        # sending the same payload twice spends context on bytes the model has already been given.
        # What it cannot infer from the transcript is the *obligation*, so that is what this adds.
        lines.append(
            "Turn 0 is a `dataflow_verify` the harness ran for you before this task started, so "
            "whether to trace is not a question you get to reopen -- interpreting the trace is. "
            "If it derived a path, that path is the evidence: do not paraphrase it and do not "
            "claim a path it did not return. If it failed or derived nothing, say so in `reasons` "
            "and lower `confidence` -- a failed trace is neither a confirmation nor a rejection, "
            "and it is not the same as the engine proving there is no flow."
        )
    else:
        lines.append(
            "If you choose `dataflow`, you must call `dataflow_verify` with this candidate's file "
            "and line before answering."
        )
    return "\n".join(lines)


def validation_batch_task(
    blackboard: Blackboard,
    items: list[tuple[Candidate, list[Candidate]]],
    *,
    material_budget: int = 0,
) -> str:
    """One task holding several *different* claims, each judged on its own.

    Why this is not "validation with fewer runs": every claim keeps its own verdict, its own
    confidence and its own reasons, and the three rules that make that checkable are stated in the
    task rather than left to the model's judgement --

    * each verdict names the claim it belongs to, verbatim;
    * a claim that needs a traced path says `needs_dataflow` instead of guessing (the coordinator
      re-runs it alone, with `dataflow_verify` available);
    * one claim's evidence may not be used as another's.

    What the run shares is the *reading*: the packets of the claims in the batch overlap on the same
    files, and that overlap is why they were put together (`material.files_for` decides, not the file
    name alone).
    """
    lines = [
        f"You are judging {len(items)} separate candidates in one run. They are separate claims: "
        "each needs its own verdict in `verdicts`, and one claim's evidence must never be used to "
        "settle another.",
        f"Workspace root: {blackboard.workspace}",
        "",
        "## The claims",
    ]
    for index, (candidate, members) in enumerate(items, start=1):
        lines.append("")
        lines.append(f"### Claim {index} -- `{candidate.candidate_id}`")
        lines.append(_json(_dump(candidate)))
        note = group_note(members)
        if note:
            lines.append(note)
    packet = _material_many(blackboard, [candidate for candidate, _ in items], budget=material_budget)
    if packet:
        lines.append("")
        lines.append(packet)
    lines.append("")
    lines.append(
        "Answer with `verdicts`: one entry per claim above, `candidate_id` copied exactly, and "
        "`reasons` that list every entry point the claim itself carries. Use `needs_dataflow` for a "
        "claim you cannot settle by reading -- do not guess at a path."
    )
    return "\n".join(lines)


def attack_path_batch_task(
    blackboard: Blackboard,
    items: list[tuple[Candidate, list[Candidate], CandidateVerdict]],
    *,
    material_budget: int = 0,
) -> str:
    """One task holding several confirmed claims, each getting its own attack path.

    The shared part is the *reading* -- confirmed candidates from one controller share their entry
    points, their callers and their configuration; the per-claim part is reachability, which is not
    shared and is the entire output of this stage.
    """
    lines = [
        f"You are establishing attack paths for {len(items)} separate confirmed candidates in one "
        "run. Each one needs its own path in `paths`, and one candidate's reachability must never be "
        "used as another's.",
        f"Workspace root: {blackboard.workspace}",
        "",
        "## The confirmed candidates",
    ]
    for index, (candidate, members, verdict) in enumerate(items, start=1):
        lines.append("")
        lines.append(f"### Candidate {index} -- `{candidate.candidate_id}`")
        lines.append(_json(_dump(candidate)))
        lines.append("Validation verdict:\n" + _json(_dump(verdict)))
        note = group_note(members)
        if note:
            lines.append(note)
            lines.append(
                "`entry_points` for this candidate must be the **union** across those instances, and "
                "an instance reached anonymously versus one reached by an admin belongs in "
                "`auth_conditions`."
            )
    packet = _material_many(blackboard, [candidate for candidate, _, _ in items], budget=material_budget)
    if packet:
        lines.append("")
        lines.append(packet)
    lines.append("")
    lines.append(
        "Answer with `paths`: one entry per candidate above, `candidate_id` copied exactly. "
        "`confidence` is about reachability, not about the bug."
    )
    return "\n".join(lines)


def attack_path_task(
    blackboard: Blackboard,
    candidate: Candidate,
    verdict: CandidateVerdict,
    *,
    material_budget: int = 0,
    members: list[Candidate] | None = None,
) -> str:
    parts = [
        f"Scope: {candidate.scope_id} -- candidate {candidate.candidate_id}",
        "This candidate was confirmed. Establish the attack path to it.",
        _json(_dump(candidate)),
        "Validation verdict:\n" + _json(_dump(verdict)),
        f"Workspace root: {blackboard.workspace}",
    ]
    note = group_note(members or [candidate])
    if note:
        # The entries of the *other* instances are the whole reason this stage gets the group: it is
        # the stage that produces `entry_points`, and until now it was handed one instance of a claim
        # whose other records named different entries.
        parts.append(
            note
            + "\n\n`entry_points` must be the **union** across those instances, not only the ones "
            "reachable from the representative. If one instance's entry is anonymous and another's is "
            "guarded, that difference is the finding's severity -- put it in `auth_conditions`."
        )
    packet = _material(blackboard, candidate, dataflow=verdict.dataflow, budget=material_budget)
    if packet:
        parts.append(packet)
    return "\n".join(parts)


def _material_many(blackboard: Blackboard, candidates: list[Candidate], *, budget: int) -> str:
    """The packets of several claims, merged so a shared file is inlined once.

    Batching only pays if the *reading* is shared too: four claims from one controller each rendering
    their own copy of that controller would spend four times the context to say the same thing. Blocks
    are therefore deduped by `(file, start, end)` -- the same range is the same bytes -- and the
    merged packet is what the batch run is handed.
    """
    if budget <= 0 or not candidates:
        return ""
    from services.harness.material import candidate_material, lines_from_run

    merged: list[Any] = []
    notes: list[str] = []
    seen: set[tuple[str, int, int]] = set()
    for candidate in candidates:
        try:
            packet = candidate_material(
                Path(str(blackboard.workspace)),
                candidate,
                dataflow=None,
                budget=budget,
                lines_of=lambda name: lines_from_run(blackboard, name),
            )
        except Exception as exc:  # noqa: BLE001 - material is an optimisation, never a blocker
            log.warning("harness: could not build material for %s (%s)", candidate.candidate_id, exc)
            continue
        for block in packet.blocks:
            key = (block.file, block.start, block.end)
            if key in seen:
                continue
            seen.add(key)
            merged.append(block)
        notes.extend(note for note in packet.notes if note not in notes)
    if not merged:
        return ""
    from services.harness.material import Material

    return Material(blocks=merged, notes=notes).render()


def _material(
    blackboard: Blackboard, candidate: Candidate, *, dataflow: Any, budget: int
) -> str:
    """The candidate's source packet, or an empty string when material is switched off.

    `budget = 0` disables it, and that is a real mode rather than a leftover: a run with and a run
    without is the only way to measure what the packet is worth, and the measured cost of reading the
    same files over and over was 471 of 823 round trips on a five-file project. See
    `services.harness.material` for the assembly rules and what the packet refuses to guess.

    The source of the lines is the run's own blackboard first (`material.lines_from_run`): the first
    agent run read every file in full, so 87 runs after it were re-reading bytes that were already on
    the board.
    """
    if budget <= 0:
        return ""
    from services.harness.material import candidate_material, lines_from_run

    evidence: Any = dataflow
    if isinstance(evidence, dict):
        from aegis_contracts.harness import DataflowEvidence

        try:
            evidence = DataflowEvidence.model_validate(evidence)
        except Exception:  # noqa: BLE001 - a malformed path is not a reason to fail the task
            evidence = None
    try:
        return candidate_material(
            Path(str(blackboard.workspace)),
            candidate,
            dataflow=evidence,
            budget=budget,
            lines_of=lambda name: lines_from_run(blackboard, name),
        ).render()
    except Exception as exc:  # noqa: BLE001 - material is an optimisation, never a blocker
        log.warning("harness: could not build material for %s (%s)", candidate.candidate_id, exc)
        return ""


def _dump(model: Any) -> Any:
    if model is None:
        return None
    if hasattr(model, "model_dump"):
        return model.model_dump(mode="json")
    return model


# ─────────────────────────────────────────────────────────── running


@dataclass
class AgentOutcome:
    """One agent run plus whatever it produced, already parsed.

    `parsed` is None when the run produced nothing usable, and that is not the same as an empty
    result: the coordinator records the `AgentRun` either way, and the report has to be able to say
    "this stage did not produce an answer" rather than "this stage found nothing".
    """

    run: AgentRun
    parsed: Any = None
    error: str | None = None


def run(
    *,
    agent: str,
    scope_id: str,
    task: str,
    context: Any,
    client: Any,
    max_steps: int,
    blackboard: Blackboard | None = None,
    run_id: str | None = None,
    extra_system: str = "",
    initial_steps: list[AgentStep] | None = None,
    on_step: Callable[[AgentRun, AgentStep], None] | None = None,
) -> AgentOutcome:
    """Run one agent and parse its `final` into the agent's typed output.

    The step budget is passed straight through to `run_agent`: nothing here may extend it, so the
    coordinator's configured bound is the only one that decides when a run stops.

    `on_step` is the observability hook, passed through untouched -- see `react.run_agent`. The
    coordinator uses it to write each step to the run's trail, which is what makes a 30-minute run
    watchable instead of a black box that only reports at the end.
    """
    chosen = spec(agent)
    run_result = run_agent(
        agent=chosen.name,
        scope_id=scope_id,
        system_prompt=chosen.prompt,
        task=task,
        tools=list(chosen.tools),
        context=context,
        client=client,
        max_steps=max_steps,
        run_id=run_id,
        output_schema=chosen.schema,
        extra_system=extra_system,
        initial_steps=initial_steps,
        on_step=on_step,
    )
    run_result.reused_files = _reused_files(initial_steps)
    parsed, error = parse_output(chosen.name, run_result, blackboard=blackboard, scope_id=scope_id)
    return AgentOutcome(run=run_result, parsed=parsed, error=error)


def parse_output(
    agent: str,
    run_result: AgentRun,
    *,
    blackboard: Blackboard | None = None,
    scope_id: str = "",
) -> tuple[Any, str | None]:
    """`(typed output, error)` for a finished run.

    A run that stopped on `budget` or `error` has no usable `final`, so it parses to nothing and
    the error says which of the two happened -- the coordinator puts that in the coverage reason.
    """
    if run_result.stop_reason != "finished":
        detail = next(
            (
                step.thought.removeprefix("model call failed: ").strip()
                for step in reversed(run_result.steps)
                if step.thought.startswith("model call failed:")
            ),
            "",
        )
        suffix = f"：{detail}" if detail else ""
        return None, (
            f"agent stopped with stop_reason={run_result.stop_reason or 'unknown'}{suffix}"
        )
    payload = run_result.output
    if not payload:
        return None, "agent finished without a final answer"
    try:
        if agent == RECON:
            return _parse_recon(payload), None
        if agent == THREAT_MODEL:
            return ThreatModel(
                assets=_strs(payload.get("assets")),
                actors=_strs(payload.get("actors")),
                threats=[t for t in payload.get("threats") or [] if isinstance(t, dict)],
                out_of_scope=_strs(payload.get("out_of_scope")),
                notes=_strs(payload.get("notes")),
            ), None
        if agent == SECURITY_INVENTORY:
            return SecurityInventory(
                entry_points=_dicts(payload.get("entry_points")),
                authorization_controls=_dicts(payload.get("authorization_controls")),
                dangerous_capabilities=_dicts(payload.get("dangerous_capabilities")),
                configurations=_dicts(payload.get("configurations")),
                dependencies=_dicts(payload.get("dependencies")),
                state_controls=_dicts(payload.get("state_controls")),
                coverage_gaps=_strs(payload.get("coverage_gaps")),
                files_reviewed=_strs(payload.get("files_reviewed")),
                notes=_strs(payload.get("notes")),
            ), None
        if agent == PLAN_UPDATE:
            return (payload, None) if isinstance(payload.get("decisions"), list) else (None, "missing decisions")
        if agent == PLANNER:
            return _parse_plan(payload), None
        if agent == DISCOVERY:
            return _parse_candidates(payload, scope_id=scope_id), None
        if agent == VALIDATION:
            return _parse_verdict(payload, run_result), None
        if agent == VALIDATION_BATCH:
            # The batch's own membership is checked by the coordinator, which is the only place that
            # knows it -- see `_parse_verdict_batch`.
            return _parse_verdict_batch(payload), None
        if agent == ATTACK_PATH_BATCH:
            return _parse_attack_path_batch(payload), None
        if agent == ATTACK_PATH:
            return AttackPath(
                candidate_id=scope_id,  # the candidate id, passed in as the run's scope
                reachable=bool(payload.get("reachable", False)),
                entry_points=_strs(payload.get("entry_points")),
                preconditions=_strs(payload.get("preconditions")),
                auth_conditions=_strs(payload.get("auth_conditions")),
                state_conditions=_strs(payload.get("state_conditions")),
                impact=str(payload.get("impact") or ""),
                alternative_paths=_strs(payload.get("alternative_paths")),
                confidence=_confidence(payload.get("confidence")),
                reasons=_strs(payload.get("reasons")),
            ), None
    except (ValueError, TypeError) as exc:
        # A `final` that fits the schema loosely can still fail pydantic (a confidence of "high",
        # a threats entry that is a string). That is a recorded error, not a crash: the run's
        # transcript is still worth keeping.
        return None, f"agent output did not fit the schema: {exc}"
    return None, f"no parser for agent {agent!r}"  # pragma: no cover - guarded by AGENTS


def _parse_recon(payload: dict[str, Any]) -> ProjectContext:
    """Recon's answer as a `ProjectContext` plus the architecture map it also carries.

    The two are returned together rather than as one model because the contract keeps them apart:
    `ProjectContext` is "what the repository is", `ArchitectureMap` is "where the trust boundaries
    are", and the planner reads the second while the report prints the first.
    """
    languages: dict[str, int] = {}
    raw_languages = payload.get("languages") or {}
    if isinstance(raw_languages, dict):
        for language, count in raw_languages.items():
            try:
                languages[str(language)] = int(count)
            except (TypeError, ValueError):
                languages[str(language)] = 0
    elif isinstance(raw_languages, list):
        for language in raw_languages:
            languages[str(language)] = 0
    components = [
        component
        for component in (payload.get("components") or [])
        if isinstance(component, dict) and (component.get("id") or component.get("name"))
    ]
    project = ProjectContext(
        workspace="",  # filled by the caller: the workspace is the run's identity, not the model's
        languages=languages,
        build_systems=_strs(payload.get("build_systems")),
        entry_points=_strs(payload.get("entry_points")),
        notes=_strs(payload.get("notes")),
    )
    architecture = ArchitectureMap(
        components=components,
        trust_boundaries=_strs(payload.get("trust_boundaries")),
        notes=[],
    )
    return project, architecture


def _parse_candidates(payload: dict[str, Any], *, scope_id: str) -> list[Candidate]:
    """Discovery's list, with ids assigned here rather than by the model.

    The id is the deduplication key for the whole blackboard, so it has to be stable and unique.
    A model-chosen id is neither: it drifts between runs and collides between scopes. The id is
    therefore derived from scope + file + line + weakness, which makes re-proposing the same site
    a no-op instead of a duplicate finding.
    """
    out: list[Candidate] = []
    seen: set[str] = set()
    for raw in payload.get("candidates") or []:
        if not isinstance(raw, dict):
            continue
        file = str(raw.get("file") or "").strip()
        title = str(raw.get("title") or "").strip()
        if not file or not title:
            # A candidate with no file cannot be validated (validation needs a site to look at),
            # so it is dropped here rather than carried forward as an unaddressable row.
            continue
        line = _line(raw.get("line"))
        # Normalised into the closed vocabulary at the point of recording. The type is part of the
        # candidate id and of the dedup key, so drift here is exactly what lets duplicates survive a
        # later dedup pass -- `dos` and `denial_of_service` are one class that a key cannot see are
        # one. `normalize_type` preserves anything it cannot map, so this cannot silently drop a
        # class the vocabulary does not contain.
        vulnerability_type = skills.normalize_type(str(raw.get("vulnerability_type") or ""))
        candidate_id = stable_candidate_id(scope_id, file, line, vulnerability_type)
        if candidate_id in seen:
            continue
        seen.add(candidate_id)
        out.append(
            Candidate(
                candidate_id=candidate_id,
                scope_id=scope_id,
                title=title,
                vulnerability_type=vulnerability_type,
                file=file,
                line=line,
                method=_opt_str(raw.get("method")),
                rationale=str(raw.get("rationale") or ""),
                evidence=_strs(raw.get("evidence")),
                entry_points=_strs(raw.get("entry_points")),
                discovered_by=DISCOVERY,
            )
        )
    return out


def validation_group_key(candidate: Candidate) -> tuple[str, int | None, str]:
    """The key that decides whether two candidates are the *same claim* rather than two claims.

    `(file, line, type)`, and each part earns its place:

    * **line** must stay, or a family collapses -- `BackupService.java` holds four separate
      command-injection call sites (`:33`, `:41`, `:53`, `:61`) which are four truth rows, and a
      `(file, type)` key would answer all four with one verdict;
    * **type** must stay, or two different vulnerabilities on one line conflate --
      `OrderController.java:42` is a SQL injection *and* an IDOR route;
    * **file** is obvious but load-bearing for the same reason.

    Measured on the Java benchmark: 106 candidates collapse to 56 groups under this key while the set
    of ground-truth rows they evidence stays exactly the same (32/35 either way), which is the
    property that makes the saving safe. A normalised-type variant collapses one group further and was
    rejected: that one extra merge is only safe by luck, and the failure mode it introduces -- one
    line, two truth rows -- is a shape this repository actually contains.
    """
    return (candidate.file, candidate.line, candidate.vulnerability_type)


def validation_groups(candidates: list[Candidate]) -> dict[tuple[str, int | None, str], list[Candidate]]:
    """Group candidates by `validation_group_key`, preserving first-seen order."""
    groups: dict[tuple[str, int | None, str], list[Candidate]] = {}
    for candidate in candidates:
        groups.setdefault(validation_group_key(candidate), []).append(candidate)
    return groups


def group_representative(members: list[Candidate]) -> Candidate:
    """The member whose evidence is richest, so a merge never costs the group its best rationale.

    Longest rationale, then most evidence items, then the id as a final tie-break so a re-run picks
    the same one. This is the whole risk of deduplication: if validation is handed a one-line
    "looks like `${}` injection" while another agent filed the same site with the full
    controller-to-mapper chain, the saving was bought with accuracy.
    """
    return max(
        members,
        key=lambda c: (len(c.rationale or ""), len(c.evidence or []), c.candidate_id),
    )


def group_note(members: list[Candidate]) -> str:
    """What the validator is told when one candidate stands for several.

    The other instances are named, not hidden. A verdict that silently covers five candidates is a
    decision whose scope the reader cannot see, and the extra entry points are often the reason the
    verdict should differ between them.

    `entry_points` is why this block carries more than a title: two records of one sink can be
    reached by an anonymous route and by a guarded one, and a validator that is not told which is
    which will either over- or under-call the severity. Merging is a cost decision; losing the
    entries would be a quality decision, and this is the line between them.
    """
    if len(members) <= 1:
        return ""
    lines = [
        f"This candidate stands for {len(members)} separately recorded instances of the same site "
        f"(same file, line and type). The verdict you give covers all of them, so `reasons` must "
        f"account for every entry point listed below -- say explicitly which entries are reachable "
        f"and at what auth level, and if the difference between two entries changes the verdict, say "
        f"that in `reasons`.",
        "",
    ]
    for index, member in enumerate(members):
        marker = "（你正在判的这条）" if index == 0 else ""
        lines.append(
            f"- `{member.candidate_id}`（scope={member.scope_id}）{marker}: "
            f"{' '.join((member.title or '').split())[:160]}"
        )
        if member.entry_points:
            for entry in member.entry_points:
                lines.append(f"    - entry: {entry}")
        if member.rationale:
            lines.append(f"    - why it was recorded: {' '.join(member.rationale.split())[:200]}")
    return "\n".join(lines)


def instance_entry_points(members: list[Candidate]) -> list[str]:
    """Every entry point the instances of one claim named, deduped and in first-seen order.

    Used where a merge would otherwise be lossy in one direction only: findings and attack paths are
    built from the *representative* instance, so without this the entries the other records named
    disappear from the report even though they were paid for.
    """
    out: list[str] = []
    for member in members:
        for entry in member.entry_points:
            text = " ".join(str(entry).split())
            if text and text not in out:
                out.append(text)
    return out


def stable_candidate_id(scope_id: str, file: str, line: int | None, vulnerability_type: str) -> str:
    """A deterministic candidate id.

    Deterministic rather than random because the blackboard deduplicates on it and a second
    discovery round must be able to recognise a site it already proposed. The readable prefix is
    kept because these ids appear in the report and a reviewer has to be able to trace one back to
    a place.
    """
    import hashlib

    digest = hashlib.sha1(  # noqa: S324 - not a security boundary, only a stable short key
        f"{scope_id}|{file}|{line}|{vulnerability_type}".encode()
    ).hexdigest()[:10]
    slug = "".join(ch if ch.isalnum() else "-" for ch in f"{scope_id}-{vulnerability_type}")
    return f"C-{slug[:40].strip('-')}-{digest}"


def pack_claim_batches(
    groups: list[list[Candidate]],
    *,
    files_of: Any,
    max_batch: int = 4,
    max_files: int = 6,
) -> list[list[list[Candidate]]]:
    """Pack claim groups into runs that share their reading, without touching the claims.

    The unit that must not change is the *claim*: a batch carries several whole groups, and each
    group's verdict is still decided once and copied to its instances. What batching adds is that
    four claims whose packets draw on the same files are read once instead of four times.

    Three rules, each of them measured rather than aesthetic:

    * **overlap decides.** A claim joins a batch only when its file set intersects the batch's
      (`material.files_for`). Packing by order instead would produce a batch whose members share
      nothing, which costs the same as four runs and confuses the "shared reading" claim.
    * **a deep claim runs alone.** One that names more than `max_files` files, or whose evidence names
      files outside the workspace, is its own run: it is where the multi-file chains live, and those
      are the findings worth the most (the SSRF chain in the measured audit crossed four files).
    * **a batch is bounded twice** -- by `max_batch` claims and by the size of the union of their file
      sets -- so the packet stays a packet instead of becoming the repository.
    """
    batches: list[list[list[Candidate]]] = []
    sets: list[set[str]] = []
    for group in groups:
        files = {name for member in group for name in files_of(member)}
        if len(files) > max_files:
            batches.append([group])
            sets.append(files)
            continue
        placed = False
        for index, batch in enumerate(batches):
            if len(batch) >= max_batch or not (files & sets[index]):
                continue
            if len(sets[index] | files) > max_files:
                continue
            batch.append(group)
            sets[index] |= files
            placed = True
            break
        if not placed:
            batches.append([group])
            sets.append(set(files))
    return batches


@dataclass
class BatchVerdicts:
    """One batch run's answer: the verdicts it decided, and the claims it sent back out."""

    verdicts: list[CandidateVerdict]
    #: Candidate ids the run answered `needs_dataflow` for. They are re-run as single validations,
    #: which have the trace tool -- the alternative was forcing a semantic guess into a verdict.
    escalate: list[str]


def _parse_verdict_batch(payload: dict[str, Any], known: list[str] | None = None) -> BatchVerdicts:
    """Validation-batch's answer, with unknown or duplicated claim ids dropped rather than guessed.

    A verdict whose `candidate_id` is not one of the claims in *this* batch is not admissable: the run
    was handed a fixed list, and an id from outside it means the model answered about something else.
    Dropping it and saying so is the honest handling -- admitting it would attach a decision to a
    claim nobody looked at. `known = None` skips the membership check, which is what the parser used
    by `parse_output` does: it has the payload but not the batch, and the coordinator that owns the
    batch re-checks the ids against it.
    """
    out: list[CandidateVerdict] = []
    escalate: list[str] = []
    seen: set[str] = set()
    for raw in payload.get("verdicts") or []:
        if not isinstance(raw, dict):
            continue
        candidate_id = str(raw.get("candidate_id") or "").strip()
        if not candidate_id:
            log.warning("harness: batch verdict without a candidate_id; dropped")
            continue
        if known is not None and candidate_id not in known:
            log.warning("harness: batch verdict names unknown claim %r; dropped", candidate_id)
            continue
        if candidate_id in seen:
            log.warning("harness: batch verdict repeats claim %r; the second is dropped", candidate_id)
            continue
        seen.add(candidate_id)
        raw_verdict = str(raw.get("verdict") or "").strip().lower()
        if raw_verdict == "needs_dataflow":
            escalate.append(candidate_id)
            continue
        if raw_verdict not in {kind.value for kind in VerdictKind}:
            log.warning("harness: batch verdict %r has unknown verdict %r", candidate_id, raw_verdict)
            continue
        out.append(
            CandidateVerdict(
                candidate_id=candidate_id,
                verdict=VerdictKind(raw_verdict),
                # A batch has no trace tool, so every verdict it can give rests on reading. Saying so
                # here rather than trusting an `evidence_kind` the schema does not even offer.
                evidence_kind=EvidenceKind.SEMANTIC,
                dataflow=None,
                reasons=_strs(raw.get("reasons")),
                confidence=_confidence(raw.get("confidence")),
            )
        )
    return BatchVerdicts(verdicts=out, escalate=escalate)


def _parse_attack_path_batch(payload: dict[str, Any]) -> list[AttackPath]:
    """A batch attack-path answer, as one `AttackPath` per claim it names.

    Claims the run did not answer are simply absent -- the caller re-runs them alone, exactly as it
    does for a single run that produced nothing. Inventing an "unreachable" path for a candidate
    nobody answered would be the one thing this stage must not do: `reachable=False` is a claim about
    the code, not a placeholder for "no answer".
    """
    out: list[AttackPath] = []
    seen: set[str] = set()
    for raw in payload.get("paths") or []:
        if not isinstance(raw, dict):
            continue
        candidate_id = str(raw.get("candidate_id") or "").strip()
        if not candidate_id or candidate_id in seen:
            log.warning("harness: batch attack path %r is missing or repeated; dropped", candidate_id)
            continue
        seen.add(candidate_id)
        out.append(
            AttackPath(
                candidate_id=candidate_id,
                reachable=bool(raw.get("reachable", False)),
                entry_points=_strs(raw.get("entry_points")),
                preconditions=_strs(raw.get("preconditions")),
                auth_conditions=_strs(raw.get("auth_conditions")),
                state_conditions=_strs(raw.get("state_conditions")),
                impact=str(raw.get("impact") or ""),
                alternative_paths=_strs(raw.get("alternative_paths")),
                confidence=_confidence(raw.get("confidence")),
            )
        )
    return out


def _parse_verdict(payload: dict[str, Any], run_result: AgentRun) -> CandidateVerdict:
    """Validation's answer, with the evidence kind and the tool's own dataflow result attached.

    `dataflow` is taken from the recorded `ToolResult`, never from the model's prose about it, and
    it is attached even when the tool *failed* -- because the tool's failure carries the reason,
    and "the engine could not answer" must not read like "the engine found no path".

    A model that named `dataflow` without getting a usable answer keeps its verdict but is told
    about in `reasons`, so the report can show that the claim rests on reading rather than on a
    derived path.
    """
    raw_verdict = str(payload.get("verdict") or "").strip().lower()
    if raw_verdict not in {kind.value for kind in VerdictKind}:
        raise ValueError(f"unknown verdict {payload.get('verdict')!r}")
    raw_kind = str(payload.get("evidence_kind") or "").strip().lower()

    dataflow = dataflow_evidence(run_result)
    usable = dataflow is not None and dataflow.error is None
    # The evidence kind follows the evidence, not the model's word for it. A model that read the
    # code and called that `semantic` while a derived source-to-sink path is sitting in the run is
    # describing its own method, not the verdict's basis -- and `evidence_kind` exists precisely to
    # tell a reader how much weight the verdict can carry.
    kind = EvidenceKind.DATAFLOW if usable else EvidenceKind.SEMANTIC

    reasons = _strs(payload.get("reasons"))
    if not usable and (dataflow is not None or raw_kind == EvidenceKind.DATAFLOW.value):
        # Reachable two ways, and the report must not paper over either: the harness or the model
        # asked the engine and it could not answer, or the model claimed a dataflow basis without
        # ever asking. Both cases leave the verdict resting on reading, and saying so out loud is
        # the entire reason this note exists.
        failure = dataflow_unavailable_reason(run_result)
        reasons.append(
            "evidence_kind=dataflow，但没有可用的数据流结论"
            + (f"：{failure}" if failure else "（本次运行没有成功调用 dataflow_verify）")
            + "；该结论只能按语义证据看待"
        )
    return CandidateVerdict(
        candidate_id="",  # filled by the caller, which is the only place that knows it
        verdict=VerdictKind(raw_verdict),
        evidence_kind=kind,
        dataflow=dataflow,
        reasons=reasons,
        confidence=_confidence(payload.get("confidence")),
    )


def _parse_plan(payload: dict[str, Any]) -> dict[str, Any]:
    """The planner's answer, normalised to the keys the coordinator reads.

    Reject incomplete investigation contracts. The coordinator separately checks source paths
    against inventory and protects the reserved file-review namespace.
    """
    scopes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in payload.get("scopes") or []:
        if not isinstance(raw, dict):
            continue
        scope_id = str(raw.get("scope_id") or "").strip()
        rationale = str(raw.get("rationale") or "").strip()
        required_text = ("title", "question", "completion_criteria")
        priority = raw.get("priority")
        files = raw.get("files")
        if (not scope_id or not rationale or scope_id in seen
                or any(not isinstance(raw.get(key), str) or not raw[key].strip() for key in required_text)
                or type(priority) is not int or priority not in (1, 2, 3)
                or not isinstance(files, list) or not files
                or any(not isinstance(name, str) or not name.strip() for name in files)):
            continue
        seen.add(scope_id)
        scopes.append(
            {
                "scope_id": scope_id,
                "title": str(raw.get("title") or scope_id),
                "kind": str(raw.get("kind") or "").strip().lower(),
                "path": str(raw.get("path") or ""),
                "rationale": rationale,
                "question": raw["question"].strip(),
                "completion_criteria": raw["completion_criteria"].strip(),
                "priority": priority,
                "files": _strs(raw.get("files")),
            }
        )
    return {
        "scopes": scopes,
        "excluded": _strs(payload.get("excluded")),
        "rationale": str(payload.get("rationale") or ""),
    }


def _strs(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, (int, float, bool)):
                out.append(str(item))
            elif isinstance(item, dict):
                out.append(json.dumps(item, ensure_ascii=False))
        return out
    if isinstance(value, dict):
        return [json.dumps(value, ensure_ascii=False)]
    return []


def _dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _line(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


def _confidence(value: Any) -> float:
    """A number in 0..1, or 0.0. Clamped rather than rejected: severity of a parse is not worth it.

    Unlike `services/ai/parse.py`, this is not the decisive field of the answer -- the verdict is --
    so an unreadable confidence becomes 0.0 (the honest minimum) instead of discarding the verdict.
    """
    if isinstance(value, bool) or value is None:
        return 0.0
    if isinstance(value, str):
        try:
            value = float(value.strip())
        except ValueError:
            return 0.0
    if not isinstance(value, (int, float)):
        return 0.0
    number = float(value)
    if number > 1.0 and number <= 100.0:
        number = number / 100.0
    return min(1.0, max(0.0, number))
