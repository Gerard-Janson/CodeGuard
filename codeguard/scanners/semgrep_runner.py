import subprocess
import json


def _parse_json_output(stdout: str, tool_name: str):
    stdout = stdout.strip()
    if not stdout:
        return []
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"{tool_name} returned invalid JSON: {e}")


def semgrep_scan(path, config="auto", timeout=600):
    command = ["semgrep", "scan", "--config", config, "--json", path]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Semgrep scan timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("Semgrep is not installed or not on PATH")

    if result.returncode not in (0, 1):
        raise RuntimeError(f"Semgrep failed: {result.stderr}")

    return _parse_json_output(result.stdout, "semgrep")