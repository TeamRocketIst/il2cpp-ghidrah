# il2cpp-ghidrah

`il2cpp-ghidrah` builds a typed Ghidra project from a Unity IL2CPP application and exports selected classes as C++. Everything runs headlessly; the Ghidra GUI is not opened.

## Requirements

- Python 3.10 or newer.
- PyGhidra 3.1 or newer.
- Ghidra 12 or newer.
- TurboHeader installed under Ghidra's `Ghidra/Extensions` directory.
- Either `il2cpp` from il2cppAOTopsy, or both `Il2CppDumper` and `Cpp2IL`.

Generator commands must be available through `PATH`, unless an explicit executable is supplied with the corresponding command option.

Set the Ghidra installation:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

You can also pass it with `--ghidra /path/to/ghidra`.

## Installation

Use a project-local virtual environment:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
il2cpp-ghidrah doctor --probe
```

For an offline installation, activate `.venv` and use the PyGhidra wheels included with Ghidra:

```sh
python -m pip install --no-index \
  -f "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" .
```

For development:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Basic use

The default `auto` mode prefers il2cppAOTopsy and falls back to Il2CppDumper with Cpp2IL. Using extracted files is recommended:

```sh
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  -u 2022.3.0f1 -o output
```

Inspect the resolved input and commands without starting Ghidra:

```sh
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  -u 2022.3.0f1 -o output --dry-run --show-commands
```

## Generators and importers

Choose a generator explicitly when needed:

```sh
il2cpp-ghidrah run game.apk -o out -g aotopsy
il2cpp-ghidrah run game.apk -o out -g dumper
```

Explicit choices do not fall back silently. Custom executables can be supplied with `--il2cpp-command`, `--dumper-command`, and `--cpp2il-command`.

TurboHeader is the default importer. It imports layouts, methods, strings, metadata, and typed relocation slots:

```sh
il2cpp-ghidrah run game.apk -o out --importer turbo
```

The compatibility importer uses the bundled CParserUtils scripts:

```sh
il2cpp-ghidrah run game.apk -o out --importer cparser
```

That flow runs `parse_header_headless.py`, `ghidra_with_struct_headless.py`, and `ghidraUnityMetadata.py`. It imports the header, method signatures, and basic metadata labels, but it does not currently provide TurboHeader's authoritative layouts or complete GOT typing. TurboHeader is still required for the exporter.

TurboHeader layout policies are:

```text
inferred       allow header-inferred offsets
external       require type_offsets.json or dump.cs
authoritative  require authoritative layout evidence
```

The default is `external`. il2cppAOTopsy supplies `type_offsets.json`; Il2CppDumper supplies `dump.cs`.

## Selection

Blacklist known frameworks:

```sh
il2cpp-ghidrah run game.apk -o out -s blacklist \
  --ignore-frameworks framework_ignore.txt
```

Whitelist assemblies:

```sh
il2cpp-ghidrah run game.apk -o out -s whitelist \
  -a Assembly-CSharp -a Assembly-CSharp-firstpass
```

Select individual classes:

```sh
il2cpp-ghidrah run game.apk -o out \
  -c MainMenuController -c PlayerController
```

Export everything:

```sh
il2cpp-ghidrah run game.apk -o out -s all
```

`--classes` accepts a JSON array. `--classes-file` accepts either a JSON array or one class name per line.

## Inputs

Prefer extracted files so each tool receives the exact ARM64 binary and metadata selected by you:

```sh
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  -u 2022.3.0f1 -o out
```

Extracted application directories are also supported:

```sh
il2cpp-ghidrah run extracted-app/ -u 2022.3.0f1 -o out
```

APK, XAPK, APKM, APKS, and ZIP inputs are detected automatically when extracted files are not available:

```sh
il2cpp-ghidrah run game.apk -o out
il2cpp-ghidrah run game.apks -o out
```

The AOTopsy generator can determine the Unity version from package or asset data:

```sh
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  --assets assets/bin/Data -o out
```

Cpp2IL forced-file mode requires a version. For packaged input without `--unity`, the Dumper flow warns and falls back to `2022.3.0f1`. Pass the real version whenever it is known. Extracted and direct inputs never use this fallback.

## Output

```text
output/
├── artifacts/   il2cpp.h, script.json, offsets, dump.cs
├── cpp2il/      DiffableCs class tree
├── project/     Ghidra project
├── decompiled/  assembly/namespace/class.cpp
├── logs/        generation, import, and decompilation logs
└── run.json     configuration and executed commands
```

The first Ghidra process imports and types the binary. The second reopens the project and exports the requested classes. Automatic whole-program analysis remains disabled in both phases.
