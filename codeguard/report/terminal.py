from collections import defaultdict

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..findings.schema import Severity

console = Console(highlight=False)

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
MAX_ITEMS_PER_FILE = 5

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "bold cyan",
    Severity.INFO: "dim white",
}

TOOL_STYLE = {
    "semgrep": "magenta",
    "trivy": "blue",
    "gitleaks": "green",
}


def _count_by(findings, key_func):
    counts = defaultdict(int)
    for f in findings:
        counts[key_func(f)] += 1
    return counts


def _severity_label(sev):
    style = SEVERITY_STYLE.get(sev, "white")
    return f"[{style}]{sev.value.upper()}[/{style}]"


def _tool_label(tool):
    style = TOOL_STYLE.get(tool, "white")
    return f"[{style}]{tool}[/{style}]"


def print_summary(findings):
    console.print()
    console.rule(f"[bold]Scan complete: {len(findings)} finding(s)[/bold]", style="dim")

    if not findings:
        console.print()
        return

    severity_counts = _count_by(findings, lambda f: f.severity)

    table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2, 0, 0))
    table.add_column("Severity")
    table.add_column("Count", justify="right")
    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count:
            table.add_row(_severity_label(sev), str(count))
    console.print(table)

    tool_counts = _count_by(findings, lambda f: f.tool)
    tool_summary = "   ".join(
        f"{_tool_label(tool)} ({count})" for tool, count in tool_counts.items()
    )
    console.print(f"\n[bold]By tool:[/bold]  {tool_summary}")

    secrets = [f for f in findings if f.finding_type.value == "secret"]
    critical = [f for f in findings if f.severity == Severity.CRITICAL]

    if secrets or critical:
        lines = []
        if secrets:
            lines.append(f"[bold red]•[/bold red] {len(secrets)} secret(s) exposed")
        if critical:
            file_count = len(set(f.file_path for f in critical))
            lines.append(
                f"[bold red]•[/bold red] {len(critical)} CRITICAL finding(s) "
                f"across {file_count} file(s)"
            )
        console.print()
        console.print(Panel("\n".join(lines), title="Top Concerns", border_style="red", expand=False))


def print_grouped_by_file(findings):
    if not findings:
        return

    by_file = defaultdict(list)
    for f in findings:
        by_file[f.file_path].append(f)

    def file_sort_key(file_path):
        return min(SEVERITY_ORDER.index(f.severity) for f in by_file[file_path])

    sorted_files = sorted(by_file.keys(), key=file_sort_key)

    console.print()
    console.rule("[bold]By File[/bold]", style="dim")
    console.print()

    for file_path in sorted_files:
        file_findings = by_file[file_path]
        counts = _count_by(file_findings, lambda f: f.severity)
        count_str = "  ".join(
            f"{counts[sev]} {_severity_label(sev)}" for sev in SEVERITY_ORDER if counts.get(sev)
        )
        console.print(f"[bold underline]{file_path}[/bold underline] — {count_str}")

        titles = [f.title for f in file_findings[:MAX_ITEMS_PER_FILE]]
        remaining = len(file_findings) - MAX_ITEMS_PER_FILE
        title_line = ", ".join(titles)
        if remaining > 0:
            title_line += f"  [dim](+ {remaining} more)[/dim]"
        console.print(f"  {title_line}")
        console.print()


def print_full_detail(findings):
    if not findings:
        console.print("[dim]No findings.[/dim]")
        return

    console.print()
    console.rule("[bold]Full Detail[/bold]", style="dim")
    console.print()

    for f in findings:
        location = f.file_path
        if f.start_line:
            location += f":{f.start_line}"

        header = Text()
        header.append(f"[{f.severity.value.upper()}] ", style=SEVERITY_STYLE.get(f.severity, "white"))
        header.append(f"({f.tool}) ", style=TOOL_STYLE.get(f.tool, "white"))
        header.append(f.title, style="bold")

        console.print(header)
        console.print(f"    [dim]File:[/dim] {location}")
        console.print(f"    {f.description}")
        console.print()


def display_report(findings, ask_for_detail=True):
    print_summary(findings)
    print_grouped_by_file(findings)

    if ask_for_detail and findings:
        choice = console.input("[bold]View full details in terminal? [y/n]: [/bold]").strip().lower()
        if choice == "y":
            print_full_detail(findings)