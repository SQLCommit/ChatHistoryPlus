# Building

[Back to ChatHistoryPlus](README.md)

For normal installation, download the plugin ZIP from the release page. These steps are for building the source.

## Requirements

- Windows with Visual Studio 2022 and its C++ tools.
- CMake 3.22 or newer.
- The Ashita v4 SDK folder containing `Ashita.h`.

## Build

From the project folder in Command Prompt:

```bat
set ASHITA4_SDK_PATH=C:\path\to\ashita-sdk
cmake -S . -B build -G "Visual Studio 17 2022" -A Win32 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

CMake builds for **32-bit x86** and writes `build\Release\chathistoryplus.dll`.

Unload ChatHistoryPlus before replacing `/ashita/plugins/chathistoryplus.dll`. If it reports that cleanup could not finish, fully close FFXI before replacing the DLL. Load before login to enable the larger history.

## Release documentation

Edit the root `README.md` for GitHub. Both release workflows generate a plain Markdown `docs/chathistoryplus/README.md` inside the ZIP: badges become links, image headings become text, and feature dropdowns are expanded. The source README stays unchanged.

To preview the packaged README in PowerShell:

```powershell
./.github/scripts/export-readme.ps1 -Output build/README.release.md
```

The README is read from the revision being packaged. Documentation edits need to be included in that revision before preparing its release files; existing ZIPs do not update automatically.
