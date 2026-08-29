from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV_DIR = ROOT / ".venv"


def find_python_in_venv() -> Path:
    if os.name == "nt":
        return VENV_DIR / "Scripts" / "python.exe"
    return VENV_DIR / "bin" / "python"


def ensure_venv() -> Path:
    if not VENV_DIR.exists():
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)

    python_path = find_python_in_venv()
    if not python_path.exists():
        raise FileNotFoundError(f"Virtual environment not ready: {python_path}")

    subprocess.run([str(python_path), "-m", "pip", "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(python_path), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")], check=True)
    return python_path


def main() -> int:
    python_path = ensure_venv()
    cmd = [str(python_path), str(ROOT / "analyser.py")]
    cmd.extend(sys.argv[1:])
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
