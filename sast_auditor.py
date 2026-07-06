"""
Local AI SAST Auditor core.

Runs an agentic scout -> verify loop over a LOCAL directory. Claude drives
list_files / read_file / search_code tools itself (client-side, sandboxed to the
target directory) and records each verified finding through a strict
`report_finding` tool, so every finding is schema-validated by construction.
Secret-bearing files (.env, private keys) are redacted before their contents ever
reach the model — the tool flags "committed secrets" without exfiltrating them.

Focus (in priority order): authentication/authorization bypasses, insecure
deserialization, business-logic flaws, then the full OWASP Top 10. Ignores style
and syntax noise.

Invoked by the VS Code "SAST: Analyze Workspace" button, or standalone:

    export ANTHROPIC_API_KEY=...
    python sast_auditor.py /path/to/project            # human-readable
    python sast_auditor.py /path/to/project --json     # machine JSON on stdout only
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path

try:
    import anthropic
except ModuleNotFoundError:
    sys.stderr.write("The 'anthropic' package is not installed. Run: pip install anthropic\n")
    sys.exit(2)

MODEL = "claude-opus-4-8"
EFFORT = "medium"  # low | medium | high | max. Lower = fewer thinking/exploration
                   # tokens = cheaper. "medium" still catches the high-severity bugs.
MAX_ITERATIONS = 40
MAX_FILE_BYTES = 200_000
MAX_MATCHES = 120
MAX_LISTED = 600

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "dist", "build",
    ".next", ".nuxt", ".idea", ".vscode", "vendor", ".mypy_cache", ".pytest_cache",
    "coverage", ".turbo", "target", "out", ".cache",
}
SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Cargo.lock", "composer.lock", "Gemfile.lock",
}
SKIP_EXT = {
    ".lock", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".pdf",
    ".zip", ".gz", ".tar", ".map", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
    ".mov", ".mp3", ".bin", ".so", ".dll", ".class", ".pyc",
}

# Files whose *values* must never be sent to the model — only the key names are
# useful for a "committed secrets" finding, never the secret material itself.
SECRET_FILE_NAMES = {".env", ".npmrc", ".pypirc", "credentials", ".netrc", ".pgpass"}
SECRET_FILE_GLOBS = (
    ".env", ".env.*", "*.pem", "*.key", "*.pfx", "*.p12", "*.keystore",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "*_rsa", "*.ppk",
)
# High-entropy secret literals stripped from ANY file (hardcoded keys in source).
SECRET_LITERAL_RE = re.compile(
    r"sk-[A-Za-z0-9_-]{16,}"                                   # OpenAI / Anthropic keys
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"  # JWTs
    r"|AKIA[0-9A-Z]{12,}"                                      # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{20,}"                             # GitHub tokens
    r"|[A-Za-z0-9+/]{40,}={0,2}"                               # long base64 blobs
)

# Rough pricing per 1M tokens (Claude Opus 4.8) for an at-a-glance cost estimate.
PRICE_IN, PRICE_OUT = 5.0, 25.0
PRICE_CACHE_WRITE, PRICE_CACHE_READ = 6.25, 0.50

# --- Structured output schema (enriched: CWE + attack vector + PoC + verification) ---

FINDING_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "finding_id": {"type": "string", "description": "e.g. SEC-001"},
        "vulnerability_type": {"type": "string"},
        "cwe_id": {"type": "string", "description": "e.g. CWE-502"},
        "owasp_category": {"type": "string", "description": "e.g. A01:2021-Broken Access Control"},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "file": {"type": "string", "description": "path relative to the project root"},
        "line": {"type": "integer"},
        "attack_vector": {"type": "string", "description": "how an attacker reaches and triggers this"},
        "exploit_proof_of_concept": {"type": "string", "description": "concrete PoC: payload / request / steps"},
        "verification": {
            "type": "string",
            "description": "what you traced to confirm this is real (routing, middleware, schema) and rule out a false positive",
        },
        "remediation": {"type": "string"},
        "remediation_code": {"type": "string"},
    },
    "required": [
        "finding_id", "vulnerability_type", "cwe_id", "owasp_category", "severity",
        "confidence", "file", "line", "attack_vector", "exploit_proof_of_concept",
        "verification", "remediation", "remediation_code",
    ],
}

TOOLS = [
    {
        "name": "list_files",
        "description": "List source files in the project. Optionally filter by a glob (e.g. '**/*.py', 'src/**/routes*').",
        "input_schema": {
            "type": "object",
            "properties": {"glob": {"type": "string", "description": "optional glob filter"}},
        },
    },
    {
        "name": "read_file",
        "description": "Read a file's contents with line numbers. Optionally restrict to a line range.",
        "input_schema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "path relative to the project root"},
                "start_line": {"type": "integer"},
                "end_line": {"type": "integer"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "search_code",
        "description": "Regex-search the codebase and return matching file:line: text. Use to find sinks, auth checks, deserialization calls, route definitions, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {"type": "string", "description": "a Python regular expression"},
                "glob": {"type": "string", "description": "optional glob to limit the search"},
            },
            "required": ["pattern"],
        },
    },
    {
        "name": "report_finding",
        "description": (
            "Record ONE verified security finding. Call this each time you confirm a "
            "real vulnerability, as you go. Never use placeholder values like 'x' — "
            "every field must reference a real file you have read and describe a real issue."
        ),
        "strict": True,
        "input_schema": FINDING_SCHEMA,
    },
    {
        "name": "finish_audit",
        "description": (
            "Call exactly once, at the very end, after you have recorded every finding "
            "via report_finding. Provides the overall summary and coverage notes."
        ),
        "strict": True,
        "input_schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "summary": {"type": "string"},
                "files_reviewed": {"type": "integer"},
                "notes": {"type": "string", "description": "coverage gaps, assumptions, areas needing manual review"},
            },
            "required": ["summary", "files_reviewed", "notes"],
        },
    },
]

SYSTEM_PROMPT = """\
You are an expert Application Security (AppSec) auditor performing a static
application security testing (SAST) review of a local codebase. Ignore syntax,
style, and formatting entirely. Hunt for exploitable security flaws.

STEP 0 — FINGERPRINT THE STACK FIRST.
Read manifests (package.json, requirements.txt, pyproject.toml, pom.xml,
build.gradle, composer.json, Gemfile, go.mod) to identify the language,
framework, and libraries. Then look for the framework-specific flaws that
actually matter for THIS stack — e.g. missing authorization decorators/annotations
on controller or route handlers, ORM calls that bypass tenant scoping, template
engines with autoescape disabled, unsafe deserialization APIs for the language in
use (pickle, yaml.load, Marshal.load, ObjectInputStream, unserialize, etc.).

PRIORITIES, in order:
1. Authentication / authorization bypasses: missing or inconsistent access
   checks, IDOR, broken object/function-level authorization, JWT/session flaws,
   privilege escalation, multi-tenant data leaks (a tenant/org id not enforced in
   the query).
2. Insecure deserialization of untrusted input.
3. Business-logic flaws: race conditions, TOCTOU, workflow/state-machine abuse,
   trust-boundary violations, missing server-side validation.
4. The full OWASP Top 10 (2021).

METHOD — SCOUT, THEN VERIFY. This is mandatory.
- SCOUT: use search_code and list_files to map entry points (routes, handlers,
  request parsing, auth middleware) and flag candidate flaws. Follow untrusted
  input from source to sink across files.
- VERIFY every candidate before reporting it. This is how you avoid false
  positives. For a suspected missing-authorization or tenant-leak bug, trace the
  request path: read the router, the middleware chain, and any base
  controller/decorator to confirm a global guard is NOT already protecting that
  route. For a suspected injection/deserialization, confirm the tainted value
  actually reaches the sink unsanitized. If you cannot confirm exploitability,
  either drop the finding or mark its confidence LOW and say in `verification`
  exactly what you could not rule out.

REPORTING.
- As you VERIFY each finding, immediately record it with the report_finding tool
  — one call per finding. Report every verified finding, including LOW severity
  and LOW confidence ones, each with an honest confidence and its verification
  trace. Never use placeholder values like "x"; every field must reference a real
  file:line you actually read and describe a real issue.
- Provide a concrete attack_vector, an exploit_proof_of_concept (payload/request/
  steps), and remediation_code (the fixed snippet) on every finding.
- Ground every finding in a real file + line you actually read. Never invent paths.
- When you have recorded every finding, call finish_audit exactly once with the
  overall summary, the count of files you reviewed, and any coverage notes.
"""


def _clean_text(s) -> str:
    """Strip any pseudo-XML field dump the model occasionally leaks into a string
    field (e.g. '...cost/DoS abuse.</summary><files_reviewed>28</files_reviewed>')."""
    if not isinstance(s, str):
        return ""
    for marker in ("</summary>", "<files_reviewed>", "<notes>", "<findings>"):
        i = s.find(marker)
        if i != -1:
            s = s[:i]
    return s.strip()


def _is_secret_file(rel: str) -> bool:
    name = Path(rel).name
    return name in SECRET_FILE_NAMES or any(fnmatch.fnmatch(name, g) for g in SECRET_FILE_GLOBS)


def _redact_line(line: str, is_secret_file: bool) -> str:
    # In a secret file (.env etc.), keep the key name but mask every value.
    if is_secret_file and "=" in line and not line.lstrip().startswith("#"):
        return line.partition("=")[0] + "=<REDACTED>"
    # In any file, strip hardcoded secret literals so they never reach the model.
    return SECRET_LITERAL_RE.sub("<REDACTED>", line)


class Workspace:
    """Client-side file tools, sandboxed to the project root."""

    def __init__(self, root: Path):
        self.root = root.resolve()

    def _safe(self, rel: str) -> Path | None:
        p = (self.root / rel).resolve()
        try:
            p.relative_to(self.root)
        except ValueError:
            return None  # path traversal attempt
        return p

    def _iter_files(self):
        for p in self.root.rglob("*"):
            if not p.is_file():
                continue
            if any(part in SKIP_DIRS for part in p.relative_to(self.root).parts):
                continue
            if p.name in SKIP_FILES or p.suffix.lower() in SKIP_EXT:
                continue
            yield p

    def list_files(self, glob: str | None = None) -> str:
        out = []
        for p in self._iter_files():
            rel = str(p.relative_to(self.root))
            if glob and not fnmatch.fnmatch(rel, glob):
                continue
            out.append(rel)
            if len(out) >= MAX_LISTED:
                out.append(f"... (truncated at {MAX_LISTED})")
                break
        return "\n".join(out) or "(no matching files)"

    def read_file(self, path: str, start_line: int | None = None, end_line: int | None = None) -> str:
        p = self._safe(path)
        if p is None or not p.is_file():
            return f"ERROR: file not found or outside project: {path}"
        data = p.read_bytes()[:MAX_FILE_BYTES]
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return f"ERROR: could not decode {path}"
        secret = _is_secret_file(path)
        lines = [_redact_line(l, secret) for l in text.splitlines()]
        s = max(1, start_line or 1)
        e = min(len(lines), end_line or len(lines))
        body = "\n".join(f"{i}\t{lines[i - 1]}" for i in range(s, e + 1)) or "(empty)"
        if secret:
            body = "# NOTE: secret values redacted; key names are real.\n" + body
        return body

    def search_code(self, pattern: str, glob: str | None = None) -> str:
        try:
            rx = re.compile(pattern)
        except re.error as ex:
            return f"ERROR: bad regex: {ex}"
        hits = []
        for p in self._iter_files():
            rel = str(p.relative_to(self.root))
            if glob and not fnmatch.fnmatch(rel, glob):
                continue
            secret = _is_secret_file(rel)
            try:
                for n, line in enumerate(p.read_text("utf-8", errors="replace").splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{rel}:{n}: {_redact_line(line.strip(), secret)[:200]}")
                        if len(hits) >= MAX_MATCHES:
                            hits.append(f"... (truncated at {MAX_MATCHES})")
                            return "\n".join(hits)
            except Exception:
                continue
        return "\n".join(hits) or "(no matches)"


def run(root: Path, json_only: bool):
    log = (lambda *a: None) if json_only else (lambda *a: print(*a, file=sys.stderr, flush=True))
    ws = Workspace(root)
    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY

    messages = [{
        "role": "user",
        "content": (
            f"Audit the project rooted at '{root.name}'. Start by fingerprinting the "
            "stack, then scout and verify. Record each finding with report_finding as "
            "you confirm it, and call finish_audit when done."
        ),
    }]

    findings = []
    meta = None
    usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for _ in range(MAX_ITERATIONS):
        # Stream so a long run can't hit the non-streaming HTTP timeout.
        try:
            with client.messages.stream(
                model=MODEL,
                max_tokens=32000,
                system=SYSTEM_PROMPT,
                tools=TOOLS,
                thinking={"type": "adaptive"},
                output_config={"effort": EFFORT},
                # Cache the growing transcript so each turn re-reads the prior
                # history at ~0.1x instead of full price — the biggest cost lever
                # in a tool loop that resends everything on every iteration.
                cache_control={"type": "ephemeral"},
                messages=messages,
            ) as stream:
                resp = stream.get_final_message()
        except anthropic.APIError as ex:
            log(f"[error] API call failed: {ex}")
            break

        u = getattr(resp, "usage", None)
        if u:
            usage["input"] += getattr(u, "input_tokens", 0) or 0
            usage["output"] += getattr(u, "output_tokens", 0) or 0
            usage["cache_read"] += getattr(u, "cache_read_input_tokens", 0) or 0
            usage["cache_write"] += getattr(u, "cache_creation_input_tokens", 0) or 0

        if resp.stop_reason == "refusal":
            log("[refused] the request was declined by safety classifiers")
            break

        messages.append({"role": "assistant", "content": resp.content})

        tool_results = []
        for block in resp.content:
            if block.type == "text" and block.text.strip():
                log(f"\n{block.text.strip()}")
            elif block.type == "tool_use":
                name, inp, bid = block.name, block.input, block.id
                if name == "finish_audit":
                    meta = inp
                    tool_results.append({"type": "tool_result", "tool_use_id": bid, "content": "Audit complete."})
                elif name == "report_finding":
                    # Reject placeholder / hallucinated findings: the file must exist.
                    p = ws._safe(str(inp.get("file", "")))
                    if p is None or not p.is_file():
                        tool_results.append({
                            "type": "tool_result", "tool_use_id": bid, "is_error": True,
                            "content": (
                                f"File {inp.get('file')!r} does not exist in the project. "
                                "Record a finding only for a real file you have read, with a real "
                                "line number — or omit it. Never use placeholder values."
                            ),
                        })
                    else:
                        finding = dict(inp)
                        finding["finding_id"] = finding.get("finding_id") or f"SEC-{len(findings) + 1:03d}"
                        findings.append(finding)
                        log(f"  [finding] {finding.get('severity')} {finding.get('vulnerability_type')} "
                            f"@ {finding.get('file')}:{finding.get('line')}")
                        tool_results.append({
                            "type": "tool_result", "tool_use_id": bid,
                            "content": f"Recorded {finding['finding_id']}.",
                        })
                else:
                    log(f"  [{name}] {json.dumps(inp)[:160]}")
                    try:
                        if name == "list_files":
                            result = ws.list_files(inp.get("glob"))
                        elif name == "read_file":
                            result = ws.read_file(inp["path"], inp.get("start_line"), inp.get("end_line"))
                        elif name == "search_code":
                            result = ws.search_code(inp["pattern"], inp.get("glob"))
                        else:
                            result = f"ERROR: unknown tool {name}"
                    except Exception as ex:
                        result = f"ERROR: {ex}"
                    tool_results.append({"type": "tool_result", "tool_use_id": bid, "content": result})

        if meta is not None:
            break
        if resp.stop_reason == "end_turn" and not tool_results:
            log("[warn] model ended turn without calling finish_audit")
            break
        messages.append({"role": "user", "content": tool_results})
    else:
        log(f"[warn] hit iteration cap ({MAX_ITERATIONS})")

    cost = (usage["input"] * PRICE_IN + usage["output"] * PRICE_OUT
            + usage["cache_write"] * PRICE_CACHE_WRITE
            + usage["cache_read"] * PRICE_CACHE_READ) / 1_000_000
    return {
        "summary": _clean_text((meta or {}).get("summary", "")) or "Audit ended without a summary.",
        "files_reviewed": (meta or {}).get("files_reviewed", 0),
        "findings": findings,
        "notes": _clean_text((meta or {}).get("notes", "")),
        "usage": {**usage, "estimated_cost_usd": round(cost, 4)},
    }


def print_human(report: dict):
    findings = report.get("findings", [])
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: order.get(f.get("severity"), 9))
    print("\n" + "=" * 70)
    print("AI SAST REPORT")
    print("=" * 70)
    print(report.get("summary", ""))
    print(f"\nFiles reviewed: {report.get('files_reviewed', 0)}   Findings: {len(findings)}")
    u = report.get("usage", {})
    if u:
        print(f"Estimated cost: ${u.get('estimated_cost_usd', 0)}  "
              f"({u.get('input', 0)} in / {u.get('output', 0)} out / {u.get('cache_read', 0)} cached tokens)")
    print()
    for f in findings:
        print(f"[{f.get('severity')}/{f.get('confidence')}] {f.get('finding_id')} "
              f"{f.get('vulnerability_type')} ({f.get('cwe_id')})")
        print(f"    {f.get('file')}:{f.get('line')}  |  {f.get('owasp_category')}")
        print(f"    Attack: {f.get('attack_vector')}")
        print(f"    Fix:    {f.get('remediation')}\n")
    if report.get("notes"):
        print(f"Notes: {report['notes']}")


_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}


def to_sarif(report: dict) -> dict:
    """SARIF 2.1.0 — the standard security-findings format that GitHub code
    scanning, and most SAST dashboards, ingest directly."""
    results = []
    for f in report.get("findings", []):
        results.append({
            "ruleId": f.get("cwe_id") or f.get("finding_id") or "SEC",
            "level": _SARIF_LEVEL.get(f.get("severity"), "warning"),
            "message": {"text": (
                f"[{f.get('severity')}/{f.get('confidence')}] {f.get('vulnerability_type')}\n"
                f"Attack: {f.get('attack_vector')}\nFix: {f.get('remediation')}"
            )},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": f.get("file", "")},
                "region": {"startLine": max(1, int(f.get("line") or 1))},
            }}],
            "properties": {
                "severity": f.get("severity"), "confidence": f.get("confidence"),
                "owasp": f.get("owasp_category"), "poc": f.get("exploit_proof_of_concept"),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AI SAST Auditor",
                "informationUri": "https://github.com/",
                "rules": [],
            }},
            "results": results,
        }],
    }


def to_markdown(report: dict) -> str:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings = sorted(report.get("findings", []), key=lambda x: order.get(x.get("severity"), 9))
    u = report.get("usage", {})
    out = [
        "# AI SAST Report", "",
        report.get("summary", ""), "",
        f"**Files reviewed:** {report.get('files_reviewed', 0)} · "
        f"**Findings:** {len(findings)} · "
        f"**Est. cost:** ${u.get('estimated_cost_usd', '?')}", "",
    ]
    for f in findings:
        out += [
            f"## {f.get('finding_id')} — {f.get('vulnerability_type')} ({f.get('cwe_id')})",
            f"**{f.get('severity')} / {f.get('confidence')} confidence** · {f.get('owasp_category')}",
            f"**Location:** `{f.get('file')}:{f.get('line')}`", "",
            f"**Attack vector:** {f.get('attack_vector')}", "",
            "**Proof of concept:**", "```", str(f.get("exploit_proof_of_concept", "")).strip(), "```",
            f"**Verification:** {f.get('verification')}", "",
            f"**Remediation:** {f.get('remediation')}", "",
            "```", str(f.get("remediation_code", "")).strip(), "```", "",
        ]
    if report.get("notes"):
        out += ["## Notes", report["notes"], ""]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(
        description="Local AI SAST auditor (OWASP Top 10, auth bypasses, insecure deserialization)."
    )
    ap.add_argument("root", help="path to the project to audit")
    ap.add_argument("--json", action="store_true", help="emit only JSON on stdout")
    ap.add_argument("--sarif", metavar="PATH", help="also write a SARIF 2.1.0 report to PATH")
    ap.add_argument("--md", metavar="PATH", help="also write a Markdown report to PATH")
    args = ap.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        sys.stderr.write(f"Not a directory: {root}\n")
        sys.exit(2)

    report = run(root, args.json)

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(report), indent=2))
    if args.md:
        Path(args.md).write_text(to_markdown(report))

    if args.json:
        print(json.dumps(report))  # stdout: machine-readable only
    else:
        print_human(report)


if __name__ == "__main__":
    main()
