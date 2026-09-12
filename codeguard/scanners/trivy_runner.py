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


def trivy_scan(path, config=None, timeout=600):
    command = ["trivy", "fs", "--format", "json"]
    if config:
        command += ["--config", config]
    command.append(path)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Trivy scan timed out after {timeout}s")
    except FileNotFoundError:
        raise RuntimeError("Trivy is not installed or not on PATH")

    if result.returncode != 0:
        raise RuntimeError(f"Trivy failed: {result.stderr}")

    return _parse_json_output(result.stdout, "trivy")