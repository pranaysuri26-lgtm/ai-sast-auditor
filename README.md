# AI SAST Auditor — editor bar

A one-click AI security audit, run from a **status-bar button** in VS Code. No
web page. Click **🛡️ SAST Audit**, and Claude (Opus 4.8) audits the open
workspace for authentication bypasses, insecure deserialization, business-logic
flaws, and the full OWASP Top 10 — then drops findings into the **Problems**
panel with CWE, attack vector, proof-of-concept, and a fix on each.

## How it works

- **`sast_auditor.py`** — the core. Runs a local agentic **scout → verify** loop:
  Claude drives `list_files` / `read_file` / `search_code` over your local files
  (sandboxed to the workspace), verifies each candidate (traces routing +
  middleware + schema to kill false positives), then emits every finding through
  a strict `submit_report` tool — so the output is schema-validated by
  construction. Your whole repo is never bulk-uploaded; only the snippets Claude
  chooses to read are sent.
- **`extension.js` / `package.json`** — the VS Code bar: a status-bar button, a
  command, and a `DiagnosticCollection` that renders findings in Problems.

## Setup

```bash
# 1. Install the Python core's dependency
cd vscode-sast
pip install -r requirements.txt

# 2. Export your key in the shell you'll launch VS Code from
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Launch VS Code from that same shell so it inherits the key
code .
```

## Run the extension

**Quickest (debug host):** open the `vscode-sast` folder in VS Code and press
**F5**. A second "Extension Development Host" window opens with the 🛡️ button in
its status bar. Open the project you want to audit in that window and click it.

**Install it for real:**

```bash
npm install -g @vscode/vsce
cd vscode-sast
vsce package                       # produces ai-sast-auditor-0.0.1.vsix
code --install-extension ai-sast-auditor-0.0.1.vsix
```

Then reload VS Code — the 🛡️ **SAST Audit** button appears in the status bar.

## Use the core standalone (or in CI)

```bash
python sast_auditor.py /path/to/project           # human-readable report
python sast_auditor.py /path/to/project --json     # JSON on stdout only
```

The `--json` mode prints nothing but the report object to stdout (progress goes
to stderr), so it pipes cleanly into a CI step or another tool.

## Settings

- `sast.pythonPath` — interpreter used to run the auditor (default `python3`).
  Point this at the venv where you installed `anthropic` if it isn't on PATH.

## Notes & limits

- Model is `claude-opus-4-8` (top reasoning, no cyber-classifier refusal path).
  Change `MODEL` in `sast_auditor.py` to use another.
- This is for auditing code **you own or are authorized to test**.
- The audit is one shot per click; large repos take a few minutes. Watch the
  **Output → AI SAST Auditor** channel for live progress.
