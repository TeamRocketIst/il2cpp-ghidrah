from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .config import RunConfig
from .installation import doctor
from .pipeline import run


def _class_list(value: str) -> list[str]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise argparse.ArgumentTypeError(f"invalid JSON class list: {error}") from error
    if not isinstance(parsed, list) or not all(isinstance(item, str) and item.strip() for item in parsed):
        raise argparse.ArgumentTypeError("--classes must be a JSON array of non-empty strings")
    return [item.strip() for item in parsed]


def _classes_file(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return _class_list(text)
    return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]


def _common_tools(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ghidra", type=Path, help="Ghidra installation root (or GHIDRA_INSTALL_DIR)")
    parser.add_argument("--il2cpp-command", default="il2cpp")
    parser.add_argument("--dumper-command", default="Il2CppDumper")
    parser.add_argument("--cpp2il-command", default="Cpp2IL")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="il2cpp-ghidrah", description="Headless Ghidra pipeline for Unity IL2CPP")
    root.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = root.add_subparsers(dest="command", required=True)

    run_parser = commands.add_parser("run", help="generate artifacts and run targeted Ghidra headlessly")
    run_parser.add_argument("input", type=Path, help="APK/XAPK/APKS/ZIP, extracted directory, or native binary")
    run_parser.add_argument("-o", "--output", type=Path, required=True)
    run_parser.add_argument("-g", "--generator", choices=("auto", "aotopsy", "dumper"), default="auto")
    run_parser.add_argument("--importer", choices=("turbo", "cparser"), default="turbo")
    run_parser.add_argument("-l", "--layout", choices=("inferred", "external", "authoritative"), default="external")
    run_parser.add_argument("-s", "--scope", choices=("whitelist", "blacklist", "all"), default="blacklist")
    run_parser.add_argument("-M", "--metadata", type=Path)
    run_parser.add_argument("-A", "--assets", type=Path)
    run_parser.add_argument("-U", "--unity-data", type=Path)
    run_parser.add_argument("-u", "--unity", "--force-unity-version", dest="unity")
    run_parser.add_argument("--abi", default="arm64-v8a")
    run_parser.add_argument("-a", "--assembly", action="append", default=[])
    run_parser.add_argument("-c", "--class", dest="selected_classes", action="append", default=[])
    run_parser.add_argument("--classes", type=_class_list, default=[])
    run_parser.add_argument("--classes-file", type=Path)
    run_parser.add_argument("--ignore-frameworks", type=Path)
    run_parser.add_argument("--project-name")
    run_parser.add_argument("--dry-run", action="store_true")
    run_parser.add_argument("--show-commands", action="store_true")
    run_parser.add_argument("--keep-temporary", action="store_true")
    _common_tools(run_parser)

    doctor_parser = commands.add_parser("doctor", help="verify the headless toolchain installation")
    doctor_parser.add_argument("-g", "--generator", choices=("auto", "aotopsy", "dumper"), default="auto")
    doctor_parser.add_argument("--importer", choices=("turbo", "cparser"), default="turbo")
    doctor_parser.add_argument("--probe", action="store_true", help="initialize Ghidra through PyGhidra")
    doctor_parser.add_argument("--json", action="store_true", dest="json_output")
    _common_tools(doctor_parser)
    return root


def _run(args: argparse.Namespace) -> None:
    classes = [*args.selected_classes, *args.classes]
    if args.classes_file:
        classes.extend(_classes_file(args.classes_file))
    config = RunConfig(
        input_path=args.input,
        output=args.output,
        generator=args.generator,
        layout=args.layout,
        scope=args.scope,
        metadata=args.metadata,
        assets=args.assets,
        unity_data=args.unity_data,
        unity=args.unity,
        abi=args.abi,
        assemblies=tuple(dict.fromkeys(args.assembly)),
        classes=tuple(dict.fromkeys(classes)),
        ignore_frameworks=args.ignore_frameworks,
        ghidra_dir=args.ghidra,
        importer=args.importer,
        project_name=args.project_name,
        il2cpp_command=args.il2cpp_command,
        dumper_command=args.dumper_command,
        cpp2il_command=args.cpp2il_command,
        dry_run=args.dry_run,
        show_commands=args.show_commands,
        keep_temporary=args.keep_temporary,
    )
    run(config)


def _doctor(args: argparse.Namespace) -> int:
    checks = doctor(
        args.ghidra,
        importer=args.importer,
        generator=args.generator,
        il2cpp_command=args.il2cpp_command,
        dumper_command=args.dumper_command,
        cpp2il_command=args.cpp2il_command,
        probe=args.probe,
    )
    if args.json_output:
        print(json.dumps([{"name": name, "ok": ok, "detail": detail} for name, ok, detail in checks], indent=2))
    else:
        for name, ok, detail in checks:
            print(f"{'OK' if ok else 'FAIL':4}  {name}: {detail}")
    return 0 if all(ok for _, ok, _ in checks) else 1


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "run":
            _run(args)
            return 0
        return _doctor(args)
    except (FileNotFoundError, FileExistsError, ValueError, RuntimeError) as error:
        print(f"il2cpp-ghidrah: error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
