# Network Traffic Observer

This project started out as a small packet sniffer and gradually turned into something more useful: a desktop-style network monitor for checking what is happening on a local network, spotting suspicious traffic patterns, and giving a quick sense of whether the Wi‑Fi setup looks safe or not.

It is not a polished enterprise security suite, and it was never meant to pretend to be one. It is more of a practical tool for curious people who want to see traffic in a more readable way and ask better questions about what is moving around them.

## What it does

The app gives you a dark, modern dashboard with a few useful indicators:

- live packet capture from a selected network interface
- protocol and destination-port visibility
- detection of suspicious activity like repeated port probing
- a quick view of risky destinations such as SSH, RDP, SMB, MySQL, VNC, and similar services
- Wi‑Fi security assessment based on the selected mode
- exportable report for later review

It is a simple tool, but the point is not complexity for the sake of it. It is about making network patterns easier to understand without burying the user in raw packets.

## Why it is useful

Most of the time, traffic looks harmless until you look closely. A small burst of packets to different ports can be a scan. Repeated access to a server port can be a clue. An old Wi‑Fi mode can quietly make everything on a network more exposed than it should be.

This app helps with that by pulling those signals into a clearer view. It is not trying to replace a full IDS or a serious security appliance. It is more like a local observatory: something you open to get a better feel for what is happening around your device.

## How to run it

The easiest way is to use the included launcher script, which sets up a local virtual environment and installs the dependencies for you:

```bash
python start_app.py
```

This will automatically:

- create a local virtual environment if needed
- install dependencies from the requirements file
- launch the application

If you want to run it manually instead, this also works:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python analyser.py
```

On Linux, live packet capture may require elevated permissions:

```bash
sudo .venv/bin/python analyser.py
```

## Demo mode

If you want to try the interface without capturing live traffic, use:

```bash
python analyser.py --demo
```

There is also a headless mode for quick summaries in a terminal:

```bash
python analyser.py --headless --demo
```

## Building a desktop executable

If you want something closer to a normal desktop app, package it with PyInstaller:

```bash
python -m pip install pyinstaller
pyinstaller --onefile --windowed --name NetworkTrafficObserver analyser.py
```

The app is also set up to build through:

```bash
python build_exe.py
```

This is the closest step to a real “download and run” workflow, though it still depends on the Python environment used to build it.

## Notes

This project is meant as a practical learning and monitoring tool. It is useful for checking what is on your local network, spotting suspicious patterns, and understanding how simple network visibility can reveal a lot.

It is best treated as a local security helper rather than a guarantee of what is safe or unsafe. Traffic can be unusual without being malicious, and not every flag is a serious incident. The goal is to make those questions easier to ask and easier to understand.

## Requirements

- Python 3.10+
- Scapy
- PyInstaller
- Tkinter

If you are using a Linux setup, make sure your system has the correct permissions to access the network interface you want to inspect.

