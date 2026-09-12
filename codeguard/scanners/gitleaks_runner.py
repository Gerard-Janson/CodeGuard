import subprocess
import json
import tempfile
import os


def _parse_json_output(stdout: str, tool_name: str):
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{tool_name} returned invalid JSON: {e}")


def gitleaks_scanner(path, no_git=False, timeout=600):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    command = [
        "gitleaks", "detect",
        "--source", path,
        "--report-format", "json",
        "--report-path", report_path,
    ]
    if no_git:
        command.append("--no-git")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
            encoding="utf-8"

        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Gitleaks scan timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("Gitleaks is not installed or not on PATH")

    if result.returncode not in (0, 1):
        raise RuntimeError(f"Gitleaks failed: {result.stderr}")

    try:
        with open(report_path, "r") as f:
            content = f.read()
        return _parse_json_output(content, "gitleaks")
    finally:
        os.remove(report_path)