import pyfiglet
import sys
import os

from .scanners.semgrep_runner import semgrep_scan
from .scanners.trivy_runner import trivy_scan
from .scanners.gitleaks_runner import gitleaks_scanner

from .findings.adapters import from_semgrep, from_trivy, from_gitleaks
from .findings.merge import merge_findings

from .repo.clone import clone_repo, cleanup_repo


def print_findings(findings):
    if not findings:
        print("\nNo findings. Clean scan.")
        return

    print(f"\n{len(findings)} finding(s):\n")
    for f in findings:
        print(f"[{f.severity.value.upper()}] ({f.tool}) {f.title}")
        print(f"    File: {f.file_path}" + (f":{f.start_line}" if f.start_line else ""))
        print(f"    {f.description}")
        print()


def run_full_scan(path):
    semgrep_findings = []
    trivy_findings = []
    gitleaks_findings = []

    try:
        semgrep_raw = semgrep_scan(path)
        semgrep_findings = from_semgrep(semgrep_raw)
    except RuntimeError as e:
        print(f"Semgrep failed: {e}")

    try:
        trivy_raw = trivy_scan(path)
        trivy_findings = from_trivy(trivy_raw)
    except RuntimeError as e:
        print(f"Trivy failed: {e}")

    try:
        gitleaks_raw = gitleaks_scanner(path)
        gitleaks_findings = from_gitleaks(gitleaks_raw)
    except RuntimeError as e:
        print(f"Gitleaks failed: {e}")

    return merge_findings(semgrep_findings, trivy_findings, gitleaks_findings)


def local_run():
    path = input("Enter path to scan: ").strip()

    if not os.path.exists(path):
        print(f"Path does not exist: {path}")
        return

    print("Running scans, this may take a few minutes...")
    all_findings = run_full_scan(path)
    print_findings(all_findings)


def repo_run():
    url = input("Enter repo URL to clone and scan: ").strip()

    if not url.startswith(("http://", "https://", "git@")):
        print("That doesn't look like a valid git URL.")
        return

    print("Cloning repository...")
    try:
        temp_dir = clone_repo(url)
    except RuntimeError as e:
        print(f"Clone failed: {e}")
        return

    try:
        print("Running scans, this may take a few minutes...")
        all_findings = run_full_scan(temp_dir)
        print_findings(all_findings)
    finally:
        cleanup_repo(temp_dir)


def password_check():
    print("TODO")


def show_menu():
    result = pyfiglet.figlet_format("CODEGUARD", font="pagga")
    print(result)

    print("1. Run Local Scan")
    print("2. Run Repo")
    print("3. Password Check")
    print("4. Exit")


def main():
 
    while True:
        show_menu()
        choice = input("Please select a number: ")

        try:
            choice = int(choice)
        except ValueError:
            input("Invalid input. Press Enter to try again...")
            continue

        match choice:
            case 1:
                local_run()
            case 2:
                repo_run()
            case 3:
                password_check()
            case 4:
                print("Goodbye!")
                sys.exit()
            case _:
                input("Please enter a number between 1 and 4. Press Enter to try again...")
                continue

        input("\nPress Enter to return to the menu...")


if __name__ == "__main__":
    main()