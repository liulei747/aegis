"""Hunting guidance, ported from OpenAI's `codex-security` audit plugin.

WHY THIS FILE EXISTS. The harness's own discovery prompt described *how* to work (read the code,
follow the callers) but never said *what to look for*, and a measured benchmark run showed what that
costs: on a 30-positive Java benchmark the harness surfaced 9 and confirmed 6, while the misses were
not random -- every SQL injection, SSRF, XSS, XXE, SpEL, SSTI, JNDI and hardcoded-secret case was
missed, and the four scopes the planner produced were **all** `web-route` plus `config`. Nothing ever
looked at the service or data-access layers. A prompt that lists the classes an auditor must sweep is
the cheapest known fix for that, and someone has already written a good one.

SOURCE AND LICENCE. Adapted from `openai/codex-security` (Apache License 2.0), specifically
`plugins/codex-security/references/core-scan.md` (the vulnerability-class sweep, the four
investigator perspectives, the severity calibration) and
`plugins/codex-security/skills/finding-discovery/SKILL.md` (the finding bar). The upstream text is
written for a diff-scoped, advisory-seeded, MCP-driven product with a worker fleet; only the parts
that are true of a static repository audit were kept, and the wording is rewritten rather than
copied wholesale. The Apache-2.0 notice is reproduced in `docs/THIRD_PARTY_NOTICES.md`; changes are
described here rather than inline, because a diff against upstream prose is not useful to a reader
of this file.

WHAT WAS DELIBERATELY NOT PORTED: the artifact/scan-contract machinery (canonical
`scan-manifest.json` / `findings.json` / `coverage.json`, sealing, SDK handoff), the advisory- and
CVE-seeded ledger rows, the diff/patch scoping, and the tracking integrations (Linear, Jira, GitHub
advisories). Those are products of a different deployment shape, and porting them would add
machinery without changing what an agent reads.
"""

from __future__ import annotations

#: The vulnerability classes an auditor must sweep. Ported from the baseline-auditor prompt in
#: `core-scan.md`, which lists them as one sentence; split out here so a prompt can render them as a
#: checklist and so a scope can be told which of them its code can even support.
#:
#: The list is deliberately broader than this harness's own survey rules (which cover four classes),
#: because the survey sees *text* while an agent reads *code*. On the benchmark the survey's four
#: rules found 5 signals; the classes below are what the misses were distributed across.
VULNERABILITY_CLASSES: tuple[str, ...] = (
    "SQL and NoSQL injection",
    "cross-site scripting",
    "missing authentication or authorization",
    "broken access control and IDOR",
    "path traversal",
    "command or code injection",
    "open redirect",
    "SSRF",
    "insecure deserialization",
    "sensitive data exposure",
    "hardcoded credentials",
    "XXE",
    "XPath injection",
    "security misconfiguration",
    "denial of service",
    "HTTP header injection",
    "unrestricted upload",
    "memory-safety errors",
    "HTTP request smuggling",
    "prototype pollution",
    "unsafe code generation",
    "resource exhaustion",
)

#: The four investigator perspectives, from `core-scan.md`. They exist because a single "follow the
#: input forward" mandate has a structural blind spot: a sink whose caller is hard to find is never
#: reached. On the benchmark, the SQL sinks lived in a MyBatis mapper XML and a legacy DAO, and
#: nothing ever arrived at them from the request side -- the *backward* perspective is what starts
#: there and walks out.
PERSPECTIVES: dict[str, str] = {
    "forward": (
        "PERSPECTIVE (forward): start at attacker-controlled input -- request parameters, bodies, "
        "headers, path segments, uploaded files, queue messages, configuration an operator can set "
        "-- and follow it toward sensitive operations: queries, command execution, file access, "
        "template or expression evaluation, credential issuance, deserialization. Stop when you "
        "reach a sink or an effective control, and state which it was."
    ),
    "backward": (
        "PERSPECTIVE (backward): start at the sensitive operations themselves -- every query "
        "builder, mapper statement, exec/system call, file read or write, XML or JSON parser, "
        "expression evaluator, JWT or session decode, credential constant -- and trace callers "
        "outward until you either reach something an attacker controls or establish that nothing "
        "does. This is the perspective that finds a sink whose entry point is not obvious; do not "
        "skip a sink because you cannot yet name its caller, and do not stop at the first caller."
    ),
    "authorization": (
        "PERSPECTIVE (authorization and business logic): inspect ownership, tenants, permissions, "
        "sessions, roles, capabilities and lifecycle transitions. For every operation that reads or "
        "mutates a protected object, name the check that decides whether *this* caller may touch "
        "*this* object, and compare sibling operations -- the same resource often has one guarded "
        "route and one unguarded route, and the guard is frequently on the wrong subject "
        "(authenticated is not the same as authorized)."
    ),
    "open": (
        "PERSPECTIVE (open-ended): follow whichever source-backed lead looks most promising, "
        "without restricting yourself to one vulnerability class or one layer. If a mechanism is "
        "unusual -- a custom parser, a hand-rolled escaping routine, a decoder, a reflection or "
        "introspection path, a plugin or extension point -- treat that as the lead."
    ),
}

#: The order perspectives are handed out. Forward first because it is the most productive default,
#: then backward, because pairing the two on the same scope is what closes the reachability gap.
PERSPECTIVE_ORDER: tuple[str, ...] = ("forward", "backward", "authorization", "open")

#: What counts as a candidate worth recording, and what does not. From the finding bar in
#: `finding-discovery/SKILL.md`. The "avoid" half matters as much as the first: on the benchmark the
#: own prompt's rejection discipline produced 24 rejections out of 24 candidates on one project,
#: which is what a prompt looks like when it has no positive definition of a candidate.
FINDING_BAR = (
    "FINDING BAR -- record a candidate when the code supports one of: an authorization bypass; a "
    "confused deputy; SSRF; path traversal; an injection with a real sink; cross-tenant data "
    "exposure; a sensitive state change without correct enforcement; a sandbox or trust-boundary "
    "escape.\n"
    "Do NOT record: 'needs more validation' comments with no exploit path; maintainability or style "
    "complaints; a second variant of the same root cause at the same control. Do record "
    "independently reachable instances separately, even when they share a helper -- a shared sink "
    "with five call sites is five candidates if each call site is reachable on its own."
)

#: How coverage is counted. Ported from the `fully_reviewed_files` rule in `core-scan.md`, which is
#: stricter than this harness's per-scope judgement and is the reason its coverage claim is
#: auditable: a file counts as reviewed only when someone read it end to end, and a search hit
#: never counts. On the benchmark every scope could be marked SUFFICIENT while 21 of 30 known
#: positives sat in files no agent had opened.
COVERAGE_RULE = (
    "COVERAGE -- a file counts as reviewed only if you read it end to end. Opening it, grepping it, "
    "or seeing it in a listing does not count. Report the paths you fully reviewed so the run can "
    "show which files nobody has actually looked at; an honest under-claim is worth more than a "
    "comfortable one."
)

#: Sibling enumeration, condensed from the discovery checklist in `finding-discovery/SKILL.md` -- the
#: clauses about shared helpers, multiple call sites, repeated patterns, concrete implementations and
#: sibling routes. It is the single most portable rule in that document, and the measurement says so:
#: the benchmark's misses cluster into families where one member was found and its siblings were not
#: -- one command-execution method confirmed while two siblings stayed invisible, one authorization
#: check read as if it covered the other operations on the same resource, one escaping call read as
#: if it covered every output path.
#:
#: The upstream text is written for diff-scoped scanning ("when the diff changes a shared helper");
#: the wording here is the repository-wide form, because that is the scan this harness performs.
SIBLING_SWEEP = (
    "SIBLING SWEEP -- a repository repeats itself, and the variant that is *missing* a control is "
    "usually next to the one that has it. When you record a sink, a guard, a route, a template or a "
    "shared helper, do not stop at the one you found:\n"
    "  - every call site of a dangerous sink is its own candidate, with its own source and its own "
    "closest control. One sanitized call does not clear its siblings;\n"
    "  - enumerate the sibling operations in the same family -- create / update / delete / restore / "
    "export, or the read and the write variant of one resource. An authorization check on one "
    "operation is not a check on the others, and the one that lacks it is the finding;\n"
    "  - when a pattern repeats across files (a template, a query builder, a parser or factory "
    "setup, an escaping call), enumerate each affected location and state which ones carry a control "
    "the others lack;\n"
    "  - when a shared helper or wrapper is on the path, keep both the wrapper and the concrete sink "
    "as affected locations rather than collapsing them into one;\n"
    "  - a safe sibling is evidence about that sibling only. It never suppresses the location you are "
    "actually working on, and it is never a reason to close the family."
)


def classes_for_prompt() -> str:
    """The class sweep as a checklist block, in the order an auditor should work through it."""
    listing = "\n".join(f"  - {name}" for name in VULNERABILITY_CLASSES)
    return (
        "SWEEP THESE CLASSES, and say explicitly which ones this scope's code cannot support "
        "(a class with no sink or no boundary here is a legitimate negative, but it has to be "
        "stated rather than skipped):\n" + listing
    )


def perspective_for(index: int) -> str:
    """The perspective for the `index`-th discovery agent, cycling through the order.

    Cycling rather than assigning by scope kind on purpose: the kind is chosen by the planner, and
    on the benchmark the planner produced four scopes that were all the same kind. A perspective
    that depends on the kind would have been the same four times over, which is the failure this is
    meant to fix.
    """
    return PERSPECTIVES[PERSPECTIVE_ORDER[index % len(PERSPECTIVE_ORDER)]]


#: The closed vocabulary a candidate's `vulnerability_type` is recorded in, snake_case.
#:
#: WHY A CLOSED LIST. The field used to be free text, and one class arrived spelled several ways
#: across agents -- measured on the Java benchmark, one site's SQL injection was filed as
#: `sql_injection` by eight different agents, while `OperationsToolService` drew `code_injection`,
#: `expression_injection` and `spel_injection` for a single sink. Deduplication keys on the type, so
#: drift is exactly what lets duplicates survive a dedup pass; constraining the vocabulary where the
#: candidate is *recorded* fixes it at the source instead of papering over it with a synonym table at
#: merge time.
#:
#: PROVENANCE. This is the snake_case form of `VULNERABILITY_CLASSES` above, which is itself ported
#: from the baseline-auditor prompt in `openai/codex-security` (Apache-2.0; see
#: `docs/THIRD_PARTY_NOTICES.md`). The few names that list leaves implicit -- template, expression,
#: JNDI, CSRF, privilege escalation, JWT verification -- are the boundaries that repository's
#: investigator prompt names in prose ("template expansion ... credential issuance, capability
#: grants"). They are general class names, not anything read off a benchmark answer key.
VULNERABILITY_TYPES: tuple[str, ...] = (
    "sql_injection",
    "nosql_injection",
    "command_injection",
    "code_injection",
    "template_injection",
    "expression_injection",
    "jndi_injection",
    "ldap_injection",
    "xpath_injection",
    "log_injection",
    "header_injection",
    "xss",
    "xxe",
    "path_traversal",
    "open_redirect",
    "ssrf",
    "csrf",
    "deserialization",
    "hardcoded_secret",
    "sensitive_data_exposure",
    "unrestricted_upload",
    "broken_access_control",
    "idor",
    "missing_authentication",
    "authz_bypass",
    "privilege_escalation",
    "jwt_verification_bypass",
    "security_misconfiguration",
    "denial_of_service",
    "resource_exhaustion",
    "memory_safety",
    "request_smuggling",
    "prototype_pollution",
    "unsafe_code_generation",
    "other",
)

#: `(needle, type)` applied to the normalised text of whatever the model wrote, first match wins.
#: Ordered so the specific phrase is tested before the general one -- `nosql` before `sql`,
#: `template`/`expression`/`jndi` before the bare `inject` -- because a first-match loop with the
#: general rule first would file every injection family under one name.
_TYPE_RULES: tuple[tuple[str, str], ...] = (
    ("nosql", "nosql_injection"),
    ("sql", "sql_injection"),
    ("command", "command_injection"),
    ("code inject", "code_injection"),
    ("code_inject", "code_injection"),
    ("rce", "code_injection"),
    ("template", "template_injection"),
    ("ssti", "template_injection"),
    ("expression", "expression_injection"),
    ("spel", "expression_injection"),
    ("jndi", "jndi_injection"),
    ("ldap", "ldap_injection"),
    ("xpath", "xpath_injection"),
    ("log inject", "log_injection"),
    ("header inject", "header_injection"),
    ("inject", "code_injection"),
    ("xxe", "xxe"),
    ("xml external", "xxe"),
    ("xss", "xss"),
    ("cross site script", "xss"),
    ("cross-site script", "xss"),
    ("directory traversal", "path_traversal"),
    ("traversal", "path_traversal"),
    ("file write", "path_traversal"),
    ("unrestricted upload", "unrestricted_upload"),
    ("open redirect", "open_redirect"),
    ("redirect", "open_redirect"),
    ("ssrf", "ssrf"),
    ("server side request", "ssrf"),
    ("csrf", "csrf"),
    ("request forgery", "csrf"),
    ("deserial", "deserialization"),
    ("hardcoded", "hardcoded_secret"),
    ("hard coded", "hardcoded_secret"),
    ("credential", "hardcoded_secret"),
    ("secret", "hardcoded_secret"),
    ("disclos", "sensitive_data_exposure"),
    ("exposure", "sensitive_data_exposure"),
    ("idor", "idor"),
    ("access control", "broken_access_control"),
    ("authz", "authz_bypass"),
    ("authoriz", "authz_bypass"),
    ("authentication", "missing_authentication"),
    ("privilege", "privilege_escalation"),
    ("escalation", "privilege_escalation"),
    ("jwt", "jwt_verification_bypass"),
    ("token verif", "jwt_verification_bypass"),
    ("misconfigur", "security_misconfiguration"),
    ("denial of service", "denial_of_service"),
    ("dos", "denial_of_service"),
    ("resource exhaust", "resource_exhaustion"),
    ("memory", "memory_safety"),
    ("smuggl", "request_smuggling"),
    ("prototype", "prototype_pollution"),
    ("code generation", "unsafe_code_generation"),
)


def _slug(text: str) -> str:
    """`SQL Injection` -> `sql_injection`; every non-alphanumeric becomes `_`."""
    slug = "".join(char if char.isalnum() else "_" for char in text.strip().lower())
    while "__" in slug:
        slug = slug.replace("__", "_")
    return slug.strip("_")


def normalize_type(raw: str) -> str:
    """The closed-vocabulary id for whatever the model wrote, or its own text when nothing fits.

    **Unmappable input is preserved verbatim**, deliberately rather than lazily: a list that rewrote
    every unrecognised class to `other` would hide a class the list does not contain, and this
    vocabulary is a reporting aid, not an authority on what a vulnerability is. A value that survives
    unchanged is a visible signal that the list needs another entry.
    """
    text = (raw or "").strip()
    if not text:
        return "other"
    slug = _slug(text)
    if slug in VULNERABILITY_TYPES:
        return slug
    lowered = text.lower().replace("-", " ").replace("_", " ")
    for needle, name in _TYPE_RULES:
        if needle in lowered:
            return name
    return slug or "other"
