import subprocess
import json

def trivy_scan(path, config=None, timeout=6000):
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

    if result.returncode not in (0, 1):
        raise RuntimeError(f"Trivy failed: {result.stderr}")

    return json.loads(result.stdout)