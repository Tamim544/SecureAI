import * as vscode from 'vscode';
import axios from 'axios';

const DIAGNOSTIC_COLLECTION_NAME = 'secureai';

export function activate(context: vscode.ExtensionContext) {
    console.log('SecureAI Extension is now active!');

    const diagnosticCollection = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_COLLECTION_NAME);
    context.subscriptions.push(diagnosticCollection);

    // Command to manually trigger a scan
    let scanCommand = vscode.commands.registerCommand('secureai.scanFile', async () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            await scanDocument(editor.document, diagnosticCollection);
        }
    });

    // Automatically scan on save
    vscode.workspace.onDidSaveTextDocument(async (document) => {
        if (document.languageId === 'python' || document.languageId === 'javascript' || document.languageId === 'typescript') {
            await scanDocument(document, diagnosticCollection);
        }
    });

    context.subscriptions.push(scanCommand);
    
    // Register the Code Action Provider for Quick Fixes
    context.subscriptions.push(
        vscode.languages.registerCodeActionsProvider(
            ['python', 'javascript', 'typescript'],
            new SecureAIFixProvider(),
            { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
        )
    );
}

async function scanDocument(document: vscode.TextDocument, diagnosticCollection: vscode.DiagnosticCollection) {
    const config = vscode.workspace.getConfiguration('secureai');
    const apiUrl = config.get<string>('apiUrl', 'http://localhost:8000');
    
    const text = document.getText();
    const language = document.languageId === 'typescript' ? 'javascript' : document.languageId;
    
    try {
        vscode.window.withProgress({
            location: vscode.ProgressLocation.Window,
            title: "SecureAI: Scanning for vulnerabilities...",
        }, async () => {
            const response = await axios.post(`${apiUrl}/api/v1/scan/snippet`, {
                code: text,
                language: language,
                filename: document.fileName
            });
            
            const findings = response.data.findings || [];
            const diagnostics: vscode.Diagnostic[] = [];
            
            for (const finding of findings) {
                // Line numbers from API are 1-indexed, VS Code is 0-indexed
                const line = Math.max(0, finding.line_start - 1);
                const lineText = document.lineAt(line).text;
                
                // Highlight the whole line, stripping leading whitespace
                const startChar = lineText.length - lineText.trimStart().length;
                const endChar = lineText.length;
                
                const range = new vscode.Range(line, startChar, line, endChar);
                
                let severity = vscode.DiagnosticSeverity.Warning;
                if (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') {
                    severity = vscode.DiagnosticSeverity.Error;
                }
                
                const diagnostic = new vscode.Diagnostic(
                    range, 
                    `[${finding.cwe_id}] ${finding.description}\n\nSuggestion: ${finding.fix_suggestion}`, 
                    severity
                );
                diagnostic.source = 'SecureAI';
                diagnostic.code = finding.cwe_id;
                
                // Store finding_id for the Quick Fix provider
                (diagnostic as any).findingId = finding.finding_id;
                (diagnostic as any).severityStr = finding.severity;
                
                diagnostics.push(diagnostic);
            }
            
            diagnosticCollection.set(document.uri, diagnostics);
            
            if (findings.length > 0) {
                vscode.window.showWarningMessage(`SecureAI found ${findings.length} vulnerabilities.`);
            } else {
                vscode.window.showInformationMessage('SecureAI: No vulnerabilities found.');
            }
        });
    } catch (error) {
        console.error('SecureAI scan error:', error);
        vscode.window.showErrorMessage('SecureAI: Failed to connect to the scanning engine. Is the API running?');
    }
}

// Quick Fix Provider
export class SecureAIFixProvider implements vscode.CodeActionProvider {
    public static readonly providedCodeActionKinds = [
        vscode.CodeActionKind.QuickFix
    ];

    public async provideCodeActions(document: vscode.TextDocument, range: vscode.Range, context: vscode.CodeActionContext): Promise<vscode.CodeAction[]> {
        const actions: vscode.CodeAction[] = [];
        
        for (const diagnostic of context.diagnostics) {
            if (diagnostic.source === 'SecureAI') {
                const action = new vscode.CodeAction('Generate AI Fix (SecureAI)', vscode.CodeActionKind.QuickFix);
                action.command = {
                    command: 'secureai.generateFix',
                    title: 'Generate Fix',
                    arguments: [document, diagnostic]
                };
                action.diagnostics = [diagnostic];
                action.isPreferred = true;
                actions.push(action);
            }
        }
        
        return actions;
    }
}

export function deactivate() {}
