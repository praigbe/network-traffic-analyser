# Network Traffic Observer

This project began as a compact packet monitor and evolved into a practical local network observatory for anyone who wants a clearer view of what is happening on their home or work network. It was designed to make raw traffic easier to understand by highlighting suspicious patterns, risky destination ports, active devices, and basic Wi‑Fi security posture in a readable dashboard.

It is not meant to replace a full enterprise IDS or a professional security appliance. Instead, it serves as a local visibility tool and learning platform: useful for spotting unusual traffic patterns, checking whether a network looks exposed, and understanding how traffic behaviour can reveal more than it first appears.

## Why it was made

Most network traffic looks harmless until it is placed in context. A small burst of connections, repeated access to risky ports, or a weak Wi‑Fi mode can all contribute to a larger picture. This project was created to help a user quickly see those signals without needing to read raw packet data all day.

## What it does now

The app captures traffic from a selected interface and turns it into useful summaries. It currently includes:

- live packet capture from a chosen network interface
- protocol and destination-port visibility
- risky service detection for ports such as SSH, RDP, SMB, MySQL, VNC, and others
- heuristic port-scan detection
- basic host activity analysis, including top talkers and device traffic volume
- alert generation for repeated risky service hits and suspicious scan behaviour
- Wi‑Fi security assessment based on a chosen wireless mode
- exportable report generation for later review
- demo mode and headless mode for testing and quick summaries

## How the code is organised

The main logic lives in [analyser.py](analyser.py), and it is split into a few practical sections:

- packet classification: determines protocol and destination port
- traffic summarisation: counts packets, risky hits, and unique IPs
- host and device analysis: identifies the busiest talkers and active devices
- alert generation: turns patterns into readable threat warnings
- Wi‑Fi assessment: evaluates whether the selected Wi‑Fi mode looks secure or outdated
- report generation: writes a text summary to disk
- GUI layer: the Tkinter dashboard that presents the results to the user

The tests in [tests/test_analyser.py](tests/test_analyser.py) cover the main behaviours: signal detection, Wi‑Fi assessment, scan detection, and the newer host/alert logic.

## How to run it

The easiest way is to use the bundled launcher:

```bash
python start_app.py
```

Manual setup also works:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python analyser.py
```

If you are running on Linux and need live capture access, elevated permissions may be required:

```bash
sudo .venv/bin/python analyser.py
```

## Demo and headless modes

To launch the interface with sample data:

```bash
python analyser.py --demo
```

To print a summary without opening the GUI:

```bash
python analyser.py --headless --demo
```

## Building a release

This project is meant to be built once on a target platform and distributed as a single app file.

### Build with the included helper script

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python build_exe.py
```

### Direct PyInstaller build

```bash
python -m pip install pyinstaller
pyinstaller --onefile --windowed --name NetworkTrafficObserver analyser.py
```

The output is placed in the `dist/` folder. Note that binaries must be built for the target platform and live capture may require administrator or root privileges at runtime.

## Requirements

- Python 3.10+
- Scapy
- Tkinter
- PyInstaller

## Notes

This tool is best treated as a local network visibility and learning tool. It helps users inspect traffic, spot suspicious patterns, and understand how small signals can point to bigger network issues without pretending to be a full security suite.

