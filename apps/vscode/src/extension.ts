import * as vscode from 'vscode';
import { Orchestrator } from '@guardiant/core';

let diagnosticCollection: vscode.DiagnosticCollection;
const orchestrator = new Orchestrator();

class GuardiantFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    provideCodeActions(document: vscode.TextDocument, range: vscode.Range | vscode.Selection, context: vscode.CodeActionContext, token: vscode.CancellationToken): vscode.CodeAction[] {
        // For each diagnostic entry that has the source 'Guardiant'
        return context.diagnostics
            .filter(diagnostic => diagnostic.source === 'Guardiant')
            .map(diagnostic => this.createFix(document, diagnostic));
    }

    private createFix(document: vscode.TextDocument, diagnostic: vscode.Diagnostic): vscode.CodeAction {
        const fix = new vscode.CodeAction('Run Guardiant AI Fix', vscode.CodeActionKind.QuickFix);
        fix.edit = new vscode.WorkspaceEdit();
        // Since we don't have the full fix logic here immediately, we could hook this up to the orchestrator's fix agent
        // For now, this is a placeholder indicating that a fix can be applied.
        fix.diagnostics = [diagnostic];
        fix.isPreferred = true;
        // In a real implementation, we would register a command to execute the fix agent asynchronously and apply the edit.
        fix.command = {
            command: 'guardiant.applyAiFix',
            title: 'Apply Guardiant AI Fix',
            arguments: [document.uri, diagnostic]
        };
        return fix;
    }
}

export function activate(context: vscode.ExtensionContext) {
    console.log('Guardiant Security extension is now active!');

    diagnosticCollection = vscode.languages.createDiagnosticCollection('guardiant');
    context.subscriptions.push(diagnosticCollection);

    // Register Workspace Scan Command
    const scanWorkspaceCmd = vscode.commands.registerCommand('guardiant.scanWorkspace', async () => {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders) {
            vscode.window.showErrorMessage('No workspace folder open');
            return;
        }

        vscode.window.withProgress({
            location: vscode.ProgressLocation.Notification,
            title: 'Guardiant: Scanning workspace...',
            cancellable: false
        }, async (progress) => {
            try {
                const target = workspaceFolders[0].uri.fsPath;
                const result = await orchestrator.runScan({
                    target,
                    type: 'directory',
                    phases: { exploit: false, fix: false }, // Fast mode for IDE
                });

                updateDiagnosticsForWorkspace(result.findings);
                vscode.window.showInformationMessage(\`Guardiant found \${result.findings.length} issues.\`);
            } catch (err) {
                vscode.window.showErrorMessage('Guardiant scan failed: ' + String(err));
            }
        });
    });

    context.subscriptions.push(scanWorkspaceCmd);

    // Register Quick Fix Provider
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            [{ scheme: 'file' }],
            new GuardiantFixProvider(),
            { providedCodeActionKinds: GuardiantFixProvider.providedCodeActionKinds }
        )
    );

    // Register Apply Fix Command
    const applyFixCmd = vscode.commands.registerCommand('guardiant.applyAiFix', async (uri: vscode.Uri, diagnostic: vscode.Diagnostic) => {
        vscode.window.showInformationMessage('Guardiant AI Fix is analyzing the vulnerability...');
        // Hook into Orchestrator Phase 7: Fix Generation
        // This is a stub for the integration.
    });
    context.subscriptions.push(applyFixCmd);

    // Document Save Trigger
    vscode.workspace.onDidSaveTextDocument(async (document) => {
        const config = vscode.workspace.getConfiguration('guardiant');
        if (config.get('enableRealTimeScanning')) {
            await scanSingleFile(document);
        }
    });
}

async function scanSingleFile(document: vscode.TextDocument) {
    if (['javascript', 'typescript', 'python', 'json'].includes(document.languageId)) {
        try {
            // A real implementation would scan just this file.
            // For now, we clear diagnostics and re-run.
            const result = await orchestrator.runScan({
                target: document.uri.fsPath,
                type: 'directory', // Using directory to reuse existing file discovery for now
                phases: { exploit: false, fix: false },
            });
            
            updateDiagnosticsForDocument(document.uri, result.findings);
        } catch (err) {
            console.error('Scan failed', err);
        }
    }
}

function updateDiagnosticsForWorkspace(findings: any[]) {
    diagnosticCollection.clear();
    const map = new Map<string, vscode.Diagnostic[]>();

    for (const f of findings) {
        if (!f.evidence?.file) continue;
        const uri = vscode.Uri.file(f.evidence.file).toString();
        
        const line = Math.max(0, (f.evidence.line || 1) - 1);
        const range = new vscode.Range(line, 0, line, 100);
        const severity = getVSCodeSeverity(f.severity);
        
        const diagnostic = new vscode.Diagnostic(range, f.title + '\\n' + f.description, severity);
        diagnostic.source = 'Guardiant';
        diagnostic.code = f.id || 'VCVF';
        
        if (!map.has(uri)) map.set(uri, []);
        map.get(uri)!.push(diagnostic);
    }

    for (const [uri, diags] of map.entries()) {
        diagnosticCollection.set(vscode.Uri.parse(uri), diags);
    }
}

function updateDiagnosticsForDocument(uri: vscode.Uri, findings: any[]) {
    // Similar logic for a single document
    updateDiagnosticsForWorkspace(findings);
}

function getVSCodeSeverity(severity: string): vscode.DiagnosticSeverity {
    switch(severity) {
        case 'critical':
        case 'high':
            return vscode.DiagnosticSeverity.Error;
        case 'medium':
            return vscode.DiagnosticSeverity.Warning;
        case 'low':
        case 'info':
        default:
            return vscode.DiagnosticSeverity.Information;
    }
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
        diagnosticCollection.dispose();
    }
}
