# il2cpp-ghidrah

`il2cpp-ghidrah` builds a typed Ghidra project from a Unity IL2CPP application and exports selected classes as C++. Everything runs headlessly; the Ghidra GUI is not opened.

## Requirements

- Python 3.9 or newer.
- PyGhidra 3.1 or newer.
- Ghidra 12 or newer.
- [TurboHeader](https://github.com/TeamRocketIst/turboHeader) installed under Ghidra's `Ghidra/Extensions` directory.
- `Il2CppDumper` and `Cpp2IL`.

Generator commands must be available through `PATH`, unless an explicit executable is supplied with the corresponding command option.

Set the Ghidra installation:

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra
```

For a Homebrew installation, use the Ghidra root inside `libexec`:

```sh
export GHIDRA_INSTALL_DIR="$(brew --prefix ghidra)/libexec"
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

The documented workflow uses Il2CppDumper with Cpp2IL. Using extracted files is recommended:

```sh
export UNITY_VERSION=2022.3.62f3  # replace with the application's exact version
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  -g dumper -u "$UNITY_VERSION" -o output
```

Inspect the resolved input and commands without starting Ghidra:

```sh
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  -g dumper -u "$UNITY_VERSION" -o output --dry-run --show-commands
```

Tool output is shown live and also retained under `output/logs/`.
Decompilation uses eight workers by default. Override it when needed with
`--decompile-jobs N`, where `N` is from `0` through `12`; `0` selects the legacy sequential path.

## Generators and importers

Il2CppDumper creates the header and metadata artifacts, while Cpp2IL creates the DiffableCs class tree. Custom executables can be supplied with `--dumper-command` and `--cpp2il-command`.

[TurboHeader](https://github.com/TeamRocketIst/turboHeader) is the default and recommended importer. It is faster than the CParserUtils compatibility path and imports layouts, methods, strings, metadata, and typed relocation slots:

```sh
il2cpp-ghidrah run game.apk -o out -g dumper --importer turbo -u "$UNITY_VERSION"
```

The compatibility importer uses the bundled CParserUtils scripts:

```sh
il2cpp-ghidrah run game.apk -o out -g dumper --importer cparser -u "$UNITY_VERSION"
```

That flow runs `parse_header_headless.py`, `ghidra_with_struct_headless.py`, and `ghidraUnityMetadata.py`. It imports the header, method signatures, and basic metadata labels, but it does not currently provide TurboHeader's authoritative layouts or complete GOT typing. TurboHeader is still required for the exporter.

TurboHeader layout policies are:

```text
inferred       allow header-inferred offsets
external       require type_offsets.json or dump.cs
authoritative  require authoritative layout evidence
```

The default is `external`. Il2CppDumper supplies `dump.cs`.

## Selection

Blacklist known frameworks:

```sh
il2cpp-ghidrah run game.apk -o out -g dumper -s blacklist -u "$UNITY_VERSION" \
  --ignore-frameworks framework_ignore.txt
```

Whitelist assemblies:

```sh
il2cpp-ghidrah run game.apk -o out -g dumper -s whitelist -u "$UNITY_VERSION" \
  -a Assembly-CSharp -a Assembly-CSharp-firstpass
```

Select individual classes:

```sh
il2cpp-ghidrah run game.apk -o out -g dumper -u "$UNITY_VERSION" \
  -c MainMenuController -c PlayerController
```

Export everything:

```sh
il2cpp-ghidrah run game.apk -o out -g dumper -s all -u "$UNITY_VERSION"
```

`--classes` accepts a JSON array. `--classes-file` accepts either a JSON array or one class name per line.

## Inputs

Prefer extracted files so each tool receives the exact ARM64 binary and metadata selected by you:

```sh
il2cpp-ghidrah run libil2cpp.so -M global-metadata.dat \
  -g dumper -u "$UNITY_VERSION" -o out
```

Extracted application directories are also supported:

```sh
il2cpp-ghidrah run extracted-app/ -g dumper -u "$UNITY_VERSION" -o out
```

APK, XAPK, APKM, APKS, and ZIP inputs are detected automatically when extracted files are not available:

```sh
il2cpp-ghidrah run game.apk -g dumper -u "$UNITY_VERSION" -o out
il2cpp-ghidrah run game.apks -g dumper -u "$UNITY_VERSION" -o out
```

Cpp2IL forced-file mode requires the exact Unity version. The Dumper flow stops with an error when `--unity` is missing; it never guesses a default version.

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
