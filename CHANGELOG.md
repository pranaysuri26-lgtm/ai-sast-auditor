# Changelog

All notable changes to this project are documented here.

## [0.1.0]

### Added
- Secret redaction: `.env`-style files and hardcoded key literals are masked
  before their contents ever reach the model. Key names and structure survive
  redaction so the agent keeps context; values do not.
- One-finding-at-a-time reporting via a strict-schema `report_finding` tool,
  replacing single-shot report generation — eliminates truncated or
  placeholder-stuffed reports on long runs.
- Cost telemetry: every run reports estimated spend (prompt-cache-aware),
  surfaced in the CLI, the VS Code status bar, and the Output channel.
- SARIF 2.1.0 output (`--sarif`) for GitHub code scanning, plus Markdown
  report output (`--md`).
- GitHub Actions workflow (`.github/workflows/sast.yml`) for CI-driven scans.
- Prompt-caching on the agentic loop to cut repeat-context cost on long scans.

### Changed
- Findings schema enriched with `cwe_id`, `owasp_category`, `attack_vector`,
  `exploit_proof_of_concept`, and a `verification` field describing the trace
  used to rule out a false positive.
- System prompt now mandates a scout-then-verify sequence: candidates are
  traced against routing/middleware/schema before being reported, rather than
  reported on pattern match alone.

### Fixed
- Workspace path resolution now rejects any read that resolves outside the
  declared project root (path-traversal guard).

## [0.0.1] — Initial release

- Local agentic scout loop: `list_files` / `read_file` / `search_code` tools,
  sandboxed to the target workspace.
- VS Code status-bar button (`🛡️ SAST Audit`) with live progress in an Output
  channel and findings rendered as Problems-panel diagnostics.
- CLI entry point (`sast_auditor.py`) for standalone and CI use.
- Framework fingerprinting step (manifests → stack-specific vulnerability
  classes) ahead of the audit.
