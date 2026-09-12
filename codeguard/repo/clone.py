import subprocess
import tempfile
import shutil


def clone_repo(git_url, shallow=False, timeout=300):
    temp_dir = tempfile.mkdtemp(prefix="codeguard-clone-")

    command = ["git", "clone", git_url, temp_dir]
    if shallow:
        command += ["--depth", "1"]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        cleanup_repo(temp_dir)
        raise RuntimeError(f"Git clone timed out after {timeout}s")
    except FileNotFoundError:
        cleanup_repo(temp_dir)
        raise RuntimeError("Git is not installed or not on PATH")

    if result.returncode != 0:
        cleanup_repo(temp_dir)
        raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")

    return temp_dir


def cleanup_repo(temp_dir):
    shutil.rmtree(temp_dir, ignore_errors=True)