// AI SAST Auditor — VS Code extension.
// Adds a status-bar button ("$(shield) SAST Audit"). Click it to run the local
// Python auditor over the current workspace and render findings in the Problems
// panel (with severity, CWE, attack vector, and fix on each diagnostic).

const vscode = require("vscode");
const cp = require("child_process");
const path = require("path");

let statusItem;
let diagnostics;
let output;

function activate(context) {
  diagnostics = vscode.languages.createDiagnosticCollection("sast");
  output = vscode.window.createOutputChannel("AI SAST Auditor");

  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusItem.command = "sast.analyze";
  setIdle();
  statusItem.show();

  context.subscriptions.push(
    statusItem,
    diagnostics,
    output,
    vscode.commands.registerCommand("sast.analyze", () => analyze(context))
  );
}

function setIdle() {
  statusItem.text = "$(shield) SAST Audit";
  statusItem.tooltip = "Run an AI security audit on this workspace";
}

function analyze(context) {
  const folder = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders[0];
  if (!folder) {
    vscode.window.showErrorMessage("Open a folder to audit first.");
    return;
  }
  if (!process.env.ANTHROPIC_API_KEY) {
    vscode.window.showErrorMessage(
      "ANTHROPIC_API_KEY is not set. Launch VS Code from a shell where it is exported, then retry."
    );
    return;
  }

  const root = folder.uri.fsPath;
  const python = vscode.workspace.getConfiguration("sast").get("pythonPath", "python3");
  const script = path.join(context.extensionPath, "sast_auditor.py");

  diagnostics.clear();
  output.clear();
  output.show(true);
  statusItem.text = "$(sync~spin) SAST: analyzing…";
  statusItem.tooltip = "Auditing… (see Output: AI SAST Auditor)";

  const proc = cp.spawn(python, [script, root, "--json"], { cwd: root, env: process.env });

  let stdout = "";
  proc.stdout.on("data", (d) => (stdout += d.toString()));
  proc.stderr.on("data", (d) => output.append(d.toString())); // live progress log

  proc.on("error", (err) => {
    setIdle();
    vscode.window.showErrorMessage(`Could not start Python (${python}): ${err.message}`);
  });

  proc.on("close", (code) => {
    setIdle();
    if (code !== 0) {
      vscode.window.showErrorMessage(`Auditor exited with code ${code}. See Output: AI SAST Auditor.`);
      return;
    }
    let report;
    try {
      report = JSON.parse(stdout);
    } catch (e) {
      vscode.window.showErrorMessage("Could not parse the auditor's output. See Output panel.");
      output.appendLine("\n[raw stdout]\n" + stdout);
      return;
    }
    render(report, root);
  });
}

function severityToVs(sev) {
  switch ((sev || "").toUpperCase()) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    case "LOW":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function render(report, root) {
  const findings = report.findings || [];
  const byFile = new Map();

  for (const f of findings) {
    const abs = path.join(root, f.file || "");
    const uri = vscode.Uri.file(abs);
    const line = Math.max(0, (f.line || 1) - 1);
    const range = new vscode.Range(line, 0, line, 200);

    const msg =
      `[${f.severity}/${f.confidence}] ${f.vulnerability_type} (${f.cwe_id})\n` +
      `${f.owasp_category}\n` +
      `Attack: ${f.attack_vector}\n` +
      `PoC: ${f.exploit_proof_of_concept}\n` +
      `Verified: ${f.verification}\n` +
      `Fix: ${f.remediation}`;

    const diag = new vscode.Diagnostic(range, msg, severityToVs(f.severity));
    diag.source = `SAST ${f.finding_id || ""}`.trim();
    diag.code = f.cwe_id;

    const arr = byFile.get(uri.fsPath) || [];
    arr.push({ uri, diag });
    byFile.set(uri.fsPath, arr);
  }

  for (const arr of byFile.values()) {
    diagnostics.set(arr[0].uri, arr.map((x) => x.diag));
  }

  const counts = findings.reduce((m, f) => ((m[f.severity] = (m[f.severity] || 0) + 1), m), {});
  const summary =
    `SAST complete — ${findings.length} finding(s): ` +
    ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
      .filter((s) => counts[s])
      .map((s) => `${counts[s]} ${s}`)
      .join(", ");

  output.appendLine("\n" + "=".repeat(60));
  output.appendLine(report.summary || "");
  output.appendLine(`Files reviewed: ${report.files_reviewed || 0}`);
  if (report.notes) output.appendLine("Notes: " + report.notes);

  if (findings.length === 0) {
    vscode.window.showInformationMessage("SAST complete — no findings.");
  } else {
    vscode.window.showWarningMessage(summary + "  (see Problems panel)");
    vscode.commands.executeCommand("workbench.actions.view.problems");
  }
}

function deactivate() {}

module.exports = { activate, deactivate };
