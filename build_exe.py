from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parent

cmd = [
    sys.executable,
    "-m",
    "PyInstaller",
    "--onefile",
    "--windowed",
    "--name",
    "NetworkTrafficObserver",
    "analyser.py",
]

print("Building distributable from analyser.py...")
subprocess.run(cmd, cwd=ROOT, check=True)

binary_path = ROOT / "dist" / "NetworkTrafficObserver"
if os.name == "nt":
    binary_path = ROOT / "dist" / "NetworkTrafficObserver.exe"

print(f"Build complete. Output: {binary_path}")
print("Upload that file to GitHub Releases or a download page so users can run it without Python installed.")
