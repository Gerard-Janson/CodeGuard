from collections import defaultdict
from ..findings.schema import Severity


SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

MAX_ITEMS_PER_FILE = 5


def _count_by(findings, key_func):
    counts = defaultdict(int)
    for f in findings:
        counts[key_func(f)] += 1
    return counts


def print_summary(findings):
    print(f"\nScan complete: {len(findings)} finding(s)\n")

    if not findings:
        return

    severity_counts = _count_by(findings, lambda f: f.severity)
    print("By severity:")
    for sev in SEVERITY_ORDER:
        count = severity_counts.get(sev, 0)
        if count:
            print(f"  {sev.value.upper():<10} {count}")

    tool_counts = _count_by(findings, lambda f: f.tool)
    tool_summary = "  ".join(f"{tool} ({count})" for tool, count in tool_counts.items())
    print(f"\nBy tool:  {tool_summary}")

    secrets = [f for f in findings if f.finding_type.value == "secret"]
    critical = [f for f in findings if f.severity == Severity.CRITICAL]

    if secrets or critical:
        print("\nTop concerns:")
        if secrets:
            print(f"  - {len(secrets)} secret(s) exposed (see gitleaks/semgrep findings)")
        if critical:
            print(f"  - {len(critical)} CRITICAL finding(s) across {len(set(f.file_path for f in critical))} file(s)")


def print_grouped_by_file(findings):
    if not findings:
        return

    by_file = defaultdict(list)
    for f in findings:
        by_file[f.file_path].append(f)

    def file_sort_key(file_path):
        file_findings = by_file[file_path]
        worst = min(SEVERITY_ORDER.index(f.severity) for f in file_findings)
        return worst

    sorted_files = sorted(by_file.keys(), key=file_sort_key)

    print("\nBy file:\n")
    for file_path in sorted_files:
        file_findings = by_file[file_path]
        counts = _count_by(file_findings, lambda f: f.severity)
        count_str = "  ".join(
            f"{counts[sev]} {sev.value.upper()}" for sev in SEVERITY_ORDER if counts.get(sev)
        )
        print(f"{file_path} — {count_str}")

        titles = [f.title for f in file_findings[:MAX_ITEMS_PER_FILE]]
        remaining = len(file_findings) - MAX_ITEMS_PER_FILE
        title_line = ", ".join(titles)
        if remaining > 0:
            title_line += f"  (+ {remaining} more)"
        print(f"  {title_line}\n")


def print_full_detail(findings):
    if not findings:
        print("No findings.")
        return

    for f in findings:
        location = f.file_path
        if f.start_line:
            location += f":{f.start_line}"

        print(f"[{f.severity.value.upper()}] ({f.tool}) {f.title}")
        print(f"    File: {location}")
        print(f"    {f.description}")
        print()


def display_report(findings, ask_for_detail=True):
    print_summary(findings)
    print_grouped_by_file(findings)

    if ask_for_detail and findings:
        choice = input("View full details in terminal? [y/N]: ").strip().lower()
        if choice == "y":
            print_full_detail(findings)