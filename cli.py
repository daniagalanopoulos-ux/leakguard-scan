"""
LeakGuard CLI - Sensitive Data Discovery Scanner
Entry point for all CLI commands.
"""

import sys
import json
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

from scanner.file_scanner import FileScanner
from scanner.git_scanner import GitScanner 
from scanner.reporter import Reporter, OutputFormat

app = typer.Typer(
    name="leakguard",
    help="LeakGuard — Sensitive data discovery scanner for codebases and git history.",
    add_completion=False,
)
console = Console()


def version_callback(value: bool):
    if value:
        rprint("[bold cyan]LeakGuard[/bold cyan] version [bold]1.0.0[/bold]")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None, "--version", "-v", callback=version_callback, is_eager=True,
        help="Show version and exit."
    )
):
    pass


@app.command("scan")
def scan(
    path: Path = typer.Argument(
        default=".",
        help="Path to file or directory to scan.",
        exists=True,
    ),
    format: OutputFormat = typer.Option(
        OutputFormat.table,
        "--format", "-f",
        help="Output format: table, json, sarif.",
    ),
    output: Path = typer.Option(
        None,
        "--output", "-o",
        help="Write results to a file instead of stdout.",
    ),
    include_git: bool = typer.Option(
        False,
        "--git/--no-git",
        help="Also scan full git commit history.",
    ),
    severity: str = typer.Option(
        "low",
        "--min-severity",
        help="Minimum severity to report: low, medium, high, critical.",
    ),
    ignore_file: Path = typer.Option(
        None,
        "--ignore-file",
        help="Path to a custom .scannerignore file.",
    ),
    baseline: Path = typer.Option(
        None,
        "--baseline",
        help="Path to a baseline JSON file to suppress known findings.",
    ),
):
    """
    Scan a file or directory for sensitive data, secrets, and credentials.
    """
    console.print(
        Panel.fit(
            "[bold cyan]LeakGuard[/bold cyan] — Sensitive Data Scanner",
            border_style="cyan"
        )
    )

    # Resolve ignore file
    if ignore_file is None:
        default_ignore = Path(path) / ".scannerignore"
        ignore_file = default_ignore if default_ignore.exists() else None

    # Load baseline
    baseline_findings = set()
    if baseline and baseline.exists():
        with open(baseline) as f:
            data = json.load(f)
            baseline_findings = {item["fingerprint"] for item in data.get("findings", [])}
        console.print(f"[dim]Loaded {len(baseline_findings)} baseline findings to suppress.[/dim]")

    all_findings = []

    # File scan
    with console.status("[bold green]Scanning files...[/bold green]"):
        file_scanner = FileScanner(ignore_file=ignore_file)
        file_findings = file_scanner.scan(path)
        all_findings.extend(file_findings)

    console.print(f"[green]✔[/green] File scan complete — {len(file_findings)} findings.")

    # Git history scan
    if include_git:
        with console.status("[bold yellow]Scanning git history...[/bold yellow]"):
            git_scanner = GitScanner(ignore_file=ignore_file)
            git_findings = git_scanner.scan(path)
            all_findings.extend(git_findings)
        console.print(f"[green]✔[/green] Git history scan complete — {len(git_findings)} findings.")

    # Filter by severity
    severity_order = ["low", "medium", "high", "critical"]
    min_idx = severity_order.index(severity.lower()) if severity.lower() in severity_order else 0
    all_findings = [
        f for f in all_findings
        if severity_order.index(f.severity.lower()) >= min_idx
    ]

    # Filter baseline
    if baseline_findings:
        all_findings = [f for f in all_findings if f.fingerprint not in baseline_findings]

    # Report
    reporter = Reporter(findings=all_findings)
    output_text = reporter.render(format=format)

    if output:
        output.write_text(output_text)
        console.print(f"\n[bold]Results written to:[/bold] {output}")
    else:
        if format == OutputFormat.table:
            reporter.print_table(console)
        else:
            print(output_text)

    # Summary
    console.print(f"\n[bold]Total findings:[/bold] {len(all_findings)}")

    if all_findings:
        sys.exit(1)  # Non-zero exit for CI pipelines
    else:
        console.print("[bold green]No sensitive data found. ✔[/bold green]")


@app.command("baseline")
def create_baseline(
    path: Path = typer.Argument(default=".", help="Path to scan.", exists=True),
    output: Path = typer.Option(
        Path(".leakguard-baseline.json"),
        "--output", "-o",
        help="Where to write the baseline file.",
    ),
):
    """
    Scan and save current findings as a baseline to suppress in future runs.
    """
    console.print("[bold yellow]Creating baseline...[/bold yellow]")
    file_scanner = FileScanner()
    findings = file_scanner.scan(path)

    data = {"findings": [f.to_dict() for f in findings]}
    output.write_text(json.dumps(data, indent=2))

    console.print(f"[green]✔[/green] Baseline saved to [bold]{output}[/bold] with {len(findings)} findings.")


@app.command("list-rules")
def list_rules():
    """
    Print all built-in detection rules and their severity.
    """
    from scanner.patterns import PATTERNS
    table = Table(title="Built-in Detection Rules", border_style="cyan")
    table.add_column("Rule ID", style="bold cyan")
    table.add_column("Description")
    table.add_column("Severity", style="bold")
    table.add_column("Pattern (truncated)")

    for p in PATTERNS:
        sev_color = {"low": "white", "medium": "yellow", "high": "red", "critical": "bold red"}.get(p.severity, "white")
        table.add_row(
            p.rule_id,
            p.description,
            f"[{sev_color}]{p.severity.upper()}[/{sev_color}]",
            p.regex[:50] + ("…" if len(p.regex) > 50 else ""),
        )

    console.print(table)


if __name__ == "__main__":
    app()