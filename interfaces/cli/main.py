"""
SecureAI CLI Tool.

Usage:
  secureai scan ./my_repo
  secureai scan --file auth.py --language python
  secureai fix --file auth.py --line 42
  secureai search "SQL injection via user input" --repo ./my_repo
  secureai serve
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from rich import print as rprint

console = Console()

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "blue",
}


@click.group()
@click.version_option("0.1.0", "--version", "-v")
def cli():
    """🔐 SecureAI — AI-powered security vulnerability detector and fix generator."""
    pass


# ──────────────────────────────────────────────
# scan command
# ──────────────────────────────────────────────

@cli.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--language", "-l", multiple=True, default=["python", "javascript"],
              help="Languages to scan (can specify multiple)")
@click.option("--severity", "-s", default="LOW",
              type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]),
              help="Minimum severity threshold")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Save results to JSON file")
@click.option("--max-files", default=500, help="Max files to scan in repo")
@click.option("--no-fix-suggestions", is_flag=True, help="Skip fix suggestions")
def scan(target: str, language: tuple, severity: str, output: str | None,
         max_files: int, no_fix_suggestions: bool):
    """Scan a file or directory for security vulnerabilities."""
    target_path = Path(target)

    console.print(Panel(
        f"[bold cyan]🔍 SecureAI Scanner[/bold cyan]\n"
        f"Target: {target_path}\n"
        f"Languages: {', '.join(language)}\n"
        f"Severity threshold: {severity}",
        title="SecureAI",
        border_style="cyan",
    ))

    from core.ast_engine.parser import ASTEngine, Language
    from core.taint_engine.analyzer import TaintEngine

    ast_engine = ASTEngine()
    taint_engine = TaintEngine()

    all_findings = []
    files = []

    if target_path.is_file():
        files = [target_path]
    else:
        extensions = {
            "python": [".py"],
            "javascript": [".js", ".mjs", ".jsx", ".ts", ".tsx"],
        }
        target_exts = set()
        for lang in language:
            target_exts.update(extensions.get(lang, []))

        files = [
            f for f in target_path.rglob("*")
            if f.suffix in target_exts
            and "node_modules" not in str(f)
            and "__pycache__" not in str(f)
            and not any(p.startswith(".") for p in f.parts)
        ][:max_files]

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    threshold_level = severity_order.get(severity, 3)

    with console.status(f"[bold green]Scanning {len(files)} files...[/bold green]"):
        for file_path in files:
            try:
                parse_result = ast_engine.parse_file(file_path)
                findings = taint_engine.analyze_file(parse_result)
                filtered = [
                    f for f in findings
                    if severity_order.get(f.severity.value, 5) <= threshold_level
                ]
                all_findings.extend(filtered)
            except Exception as e:
                console.print(f"[yellow]Warning: Failed to scan {file_path}: {e}[/yellow]")

    # Summary
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    console.print(f"\n[bold]Scan Complete[/bold] — {len(files)} files, {len(all_findings)} findings\n")

    if not all_findings:
        console.print("[bold green]✅ No vulnerabilities found![/bold green]")
        return

    # Summary table
    summary = Table(title="Vulnerability Summary", show_header=True, header_style="bold")
    summary.add_column("Severity", style="bold")
    summary.add_column("Count", justify="right")
    for sev, count in severity_counts.items():
        if count > 0:
            summary.add_row(f"[{SEVERITY_COLORS[sev]}]{sev}[/]", str(count))
    console.print(summary)
    console.print()

    # Detailed findings table
    findings_table = Table(title="Vulnerability Findings", show_header=True, header_style="bold cyan")
    findings_table.add_column("Severity", style="bold", min_width=10)
    findings_table.add_column("CWE", min_width=10)
    findings_table.add_column("Function", min_width=20)
    findings_table.add_column("File:Line", min_width=25)
    findings_table.add_column("Description", min_width=40)

    all_findings.sort(key=lambda f: severity_order.get(f.severity.value, 5))
    for f in all_findings:
        sev_color = SEVERITY_COLORS.get(f.severity.value, "white")
        findings_table.add_row(
            f"[{sev_color}]{f.severity.value}[/]",
            f.cwe.value,
            f.function_name[:20],
            f"{Path(f.file_path).name}:{f.line_start}",
            f.description[:60] + ("..." if len(f.description) > 60 else ""),
        )

    console.print(findings_table)

    # Fix suggestions
    if not no_fix_suggestions and all_findings:
        console.print("\n[bold]Fix Suggestions:[/bold]")
        for f in all_findings[:3]:  # Show top 3
            console.print(Panel(
                f"[bold]{f.cwe.value}[/bold] in [cyan]{f.function_name}()[/cyan]\n\n"
                f"[yellow]Suggestion:[/yellow] {f.fix_suggestion}",
                title=f"[{SEVERITY_COLORS.get(f.severity.value, 'white')}]{f.severity.value}[/]",
                border_style="yellow",
            ))

    # JSON output
    if output:
        import json
        results = {
            "summary": severity_counts,
            "findings": [
                {
                    "function": f.function_name,
                    "file": f.file_path,
                    "line_start": f.line_start,
                    "line_end": f.line_end,
                    "cwe": f.cwe.value,
                    "severity": f.severity.value,
                    "description": f.description,
                    "fix_suggestion": f.fix_suggestion,
                }
                for f in all_findings
            ],
        }
        Path(output).write_text(json.dumps(results, indent=2))
        console.print(f"\n[green]Results saved to {output}[/green]")

    # Exit code: 1 if critical/high findings
    if severity_counts.get("CRITICAL", 0) > 0 or severity_counts.get("HIGH", 0) > 0:
        sys.exit(1)


# ──────────────────────────────────────────────
# fix command
# ──────────────────────────────────────────────

@cli.command()
@click.option("--file", "-f", required=True, type=click.Path(exists=True))
@click.option("--line", "-l", type=int, required=True)
@click.option("--cwe", default=None, help="CWE ID if known (e.g., CWE-89)")
@click.option("--output", "-o", type=click.Path(), default=None,
              help="Save patch to file")
def fix(file: str, line: int, cwe: str | None, output: str | None):
    """Generate an AI fix for a vulnerability at a specific file and line."""
    file_path = Path(file)
    language = "python" if file_path.suffix == ".py" else "javascript"

    console.print(Panel(
        f"[bold cyan]🔧 SecureAI Fix Generator[/bold cyan]\n"
        f"File: {file_path}\nLine: {line}",
        border_style="cyan",
    ))

    # Extract the function containing the line
    from core.ast_engine.parser import ASTEngine, Language
    from core.taint_engine.analyzer import TaintEngine

    ast_engine = ASTEngine()
    taint_engine = TaintEngine()
    lang_enum = Language(language)

    parse_result = ast_engine.parse_file(file_path)
    target_func = None
    for func in parse_result.functions:
        if func.location.line_start <= line <= func.location.line_end:
            target_func = func
            break

    if target_func is None:
        console.print(f"[red]No function found at line {line}[/red]")
        sys.exit(1)

    # Show the vulnerable code
    console.print(f"\n[bold]Target function:[/bold] {target_func.qualified_name}()")
    syntax = Syntax(target_func.source_code, language, theme="monokai", line_numbers=True,
                    start_line=target_func.location.line_start)
    console.print(syntax)

    # Detect vulnerabilities in this function
    findings = taint_engine.analyze_function(target_func)

    if not findings:
        console.print("[yellow]No vulnerabilities detected in this function.[/yellow]")

    # Generate fix (rule-based for now without trained model)
    if findings:
        f = findings[0]
        console.print(f"\n[bold red]Detected:[/bold red] {f.cwe.value} — {f.description}")
        console.print(f"\n[bold yellow]Suggested Fix:[/bold yellow]\n{f.fix_suggestion}")


# ──────────────────────────────────────────────
# search command
# ──────────────────────────────────────────────

@cli.command()
@click.argument("query")
@click.option("--repo", "-r", required=True, type=click.Path(exists=True))
@click.option("--top-k", default=10)
@click.option("--language", "-l", default=None)
def search(query: str, repo: str, top_k: int, language: str | None):
    """Semantic code search using natural language."""
    console.print(Panel(
        f"[bold cyan]🔍 Semantic Code Search[/bold cyan]\n"
        f'Query: "{query}"\n'
        f"Repository: {repo}",
        border_style="cyan",
    ))
    console.print("[yellow]Semantic search requires the vector store to be indexed first.[/yellow]")
    console.print("[cyan]Run: secureai index --repo <path>[/cyan]")


# ──────────────────────────────────────────────
# serve command
# ──────────────────────────────────────────────

@cli.command()
@click.option("--host", default="0.0.0.0")
@click.option("--port", default=8000)
@click.option("--reload", is_flag=True, default=False)
def serve(host: str, port: int, reload: bool):
    """Start the SecureAI REST API server."""
    import uvicorn
    console.print(Panel(
        f"[bold cyan]🚀 SecureAI API Server[/bold cyan]\n"
        f"http://{host}:{port}\n"
        f"Docs: http://{host}:{port}/docs",
        border_style="cyan",
    ))
    uvicorn.run(
        "api.rest.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


if __name__ == "__main__":
    cli()
