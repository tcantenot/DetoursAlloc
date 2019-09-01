# DetoursAlloc

A Detours .dll to track allocations.

## Usage

This project is using [Detours](https://github.com/microsoft/Detours) to patch functions.

Inspired by https://github.com/Lectem/ThreadsTree.detours.

Start by building DetoursAlloc.dll using CMake.

Then use the pre-built `external/Detours/bin.X64/withdll.exe` executable to inject the detours dll (requires administrator privileges):

```
withdll.exe -d:DetoursAlloc.dll YourProgram.exe
```

Note that it will spawn YourProgram.exe as a subprocess, so you might be interested in the following Visual Studio extension [Microsoft Child Process Debugging Power Tool](https://marketplace.visualstudio.com/items?itemName=vsdbgplat.MicrosoftChildProcessDebuggingPowerTool).

## Requirements

- CMake (buildsystem)
- Visual Studio (compiler)
