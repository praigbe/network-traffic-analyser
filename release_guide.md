# Release guide for the Network Traffic Observer

This project is designed so that the end user does not need to install Python or project dependencies manually. The usual release flow is:

1. Build the executable on a developer machine
2. Upload the generated binary to GitHub Releases
3. Share the download link with users
4. Users download the file and run it directly

## Build the distributable

Create a clean virtual environment if you want a repeatable build, then run the packaging script:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python build_exe.py
```

The output will appear in the `dist` folder.

## PyInstaller command

If you want to build it manually:

```bash
pyinstaller --onefile --windowed --name NetworkTrafficObserver analyser.py
```

This creates one bundled application file.

## GitHub release flow

1. Go to your repository on GitHub
2. Open the Releases tab
3. Click Create a new release
4. Add a version tag, for example `v1.0.0`
5. Upload the built binary from `dist/`
6. Add a short description describing the release
7. Publish the release

Users can then download the .exe or binary and run it directly.

## Notes for users

- Live network capture may require admin or root privileges
- The app generates a report file in the current working directory
- The generated report is called `network_report.txt`

## Important platform note

A single-file executable should be built for the target platform:

- Windows: build on Windows for a `.exe`
- Linux: build on Linux for a Linux binary
- macOS: build on macOS for a macOS app or binary

This is how you avoid requiring users to install Python themselves.
