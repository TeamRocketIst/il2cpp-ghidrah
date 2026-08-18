from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from .config import RunConfig
from .generators import generate
from .ghidra import run_headless
from .inputs import resolve_input
from .installation import discover
from .process import display_command
from .selection import prepare_diffable_selection


def _require_clean_ghidra_log(log: Path) -> None:
    if not log.is_file():
        raise RuntimeError(f"Ghidra did not create its expected log: {log}")
    contents = log.read_text(encoding="utf-8", errors="replace")
    failure_markers = (
        "REPORT SCRIPT ERROR:",
        "Abort due to Headless analyzer error:",
        "Could not find project:",
    )
    marker = next((item for item in failure_markers if item in contents), None)
    if marker:
        raise RuntimeError(f"Ghidra reported {marker.rstrip(':')}; see {log}")


def _require_exported_functions(directory: Path) -> None:
    summary = directory / "_export_summary.txt"
    if not summary.is_file():
        raise RuntimeError(f"Ghidra did not create its export summary: {summary}")
    match = re.search(
        r"^Functions matched/exported:\s*(\d+)\s*$",
        summary.read_text(encoding="utf-8", errors="replace"),
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError(f"Ghidra export summary is incomplete: {summary}")
    if int(match.group(1)) == 0:
        raise RuntimeError(f"Ghidra matched no functions; see {summary}")


def _project_name(config: RunConfig) -> str:
    raw = config.project_name or f"Il2CppAnalysis_{config.input_path.stem}"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", raw)


def run(config: RunConfig) -> None:
    installation = discover(config.ghidra_dir)
    if config.importer == "turbo":
        if not installation.turboheader_installed:
            raise FileNotFoundError(
                "TurboHeader extension or native library is not installed; "
                "install TurboHeader or explicitly use --importer cparser"
            )
        importer = "turbo"
    else:
        importer = "cparser"
    output = config.output.expanduser().resolve()
    output.mkdir(parents=True, exist_ok=True)
    logs = output / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    project_dir = output / "project"
    decompiled = output / "decompiled"
    project_name = _project_name(config)
    if not config.dry_run and any(project_dir.glob(f"{project_name}*")):
        raise FileExistsError(f"Ghidra project already exists: {project_dir / project_name}")
    if not config.dry_run:
        project_dir.mkdir(parents=True, exist_ok=True)

    temporary_context = None if config.keep_temporary else tempfile.TemporaryDirectory(prefix="il2cpp-ghidrah-")
    temporary = Path(tempfile.mkdtemp(prefix="il2cpp-ghidrah-")) if config.keep_temporary else Path(temporary_context.name)
    try:
        resolved = resolve_input(
            config.input_path,
            temporary,
            metadata=config.metadata,
            assets=config.assets,
            unity_data=config.unity_data,
            unity=config.unity,
            abi=config.abi,
        )
        print("Resolved input:")
        print(f"  Binary:   {resolved.binary}")
        print(f"  Metadata: {resolved.metadata}")
        print(f"  Unity data: {resolved.unity_data or '-'}")
        print(f"  Assets:   {resolved.assets or '-'}")
        print(f"  Generator: {config.generator}; layout: {config.layout}; scope: {config.scope}")
        print(f"  Header importer: {importer}")

        artifacts = generate(config, resolved, output / "artifacts", output / "cpp2il", logs)
        selected_diffable = artifacts.diffable
        needs_selection = config.scope == "whitelist" or bool(config.classes)
        if config.dry_run and needs_selection:
            selected_diffable = output / ".selected-diffable"
        elif not config.dry_run:
            selected_diffable = prepare_diffable_selection(
                artifacts.diffable,
                output / ".selected-diffable",
                scope=config.scope,
                assemblies=config.assemblies,
                classes=config.classes,
            )

        offsets = str(artifacts.offsets) if artifacts.offsets != Path("-") else "-"
        import_command = [
            str(project_dir),
            project_name,
            "-import",
            str(resolved.binary),
            "-noanalysis",
        ]
        if importer == "turbo":
            import_command += [
                "-scriptPath", str(installation.scripts_dir),
                "-postScript", "ImportIl2CppTypes.java",
                str(artifacts.header), offsets, str(artifacts.script),
                config.turbo_policy,
            ]
        else:
            fallback_scripts = installation.cparser_scripts_dir
            import_command += [
                "-scriptPath", str(fallback_scripts),
                "-preScript", "parse_header_headless.py", str(artifacts.header),
                "-postScript", "ghidra_with_struct_headless.py", str(artifacts.script),
            ]
            if (fallback_scripts / "ghidraUnityMetadata.py").is_file():
                import_command += [
                    "-postScript", "ghidraUnityMetadata.py", str(artifacts.script),
                ]
        import_logs = run_headless(
            installation.ghidra_dir,
            import_command,
            log=logs / "ghidra-import.log",
            dry_run=config.dry_run,
            show=config.show_commands,
        )
        if not config.dry_run:
            _require_clean_ghidra_log(import_logs.application)
            _require_clean_ghidra_log(import_logs.script)
            if not any(project_dir.glob(f"{project_name}*")):
                raise RuntimeError(
                    f"Ghidra did not create project {project_name}; "
                    f"see {logs / 'ghidra-import.log'}"
                )

        export_scope = "all" if config.scope == "whitelist" else config.scope
        export_command = [
            str(project_dir),
            project_name,
            "-process",
            resolved.binary.name,
            "-noanalysis",
            "-scriptPath",
            str(installation.scripts_dir),
            "-postScript",
            "cpp2il_ghidra_export_editable.py",
            str(selected_diffable),
            str(decompiled),
            export_scope,
        ]
        if config.ignore_frameworks:
            export_command.append(str(config.ignore_frameworks.resolve()))
        if artifacts.noreturn_seeds is not None:
            export_command += ["--noreturn-seeds", str(artifacts.noreturn_seeds)]
        export_logs = run_headless(
            installation.ghidra_dir,
            export_command,
            log=logs / "ghidra-decompile.log",
            dry_run=config.dry_run,
            show=config.show_commands,
        )
        if not config.dry_run:
            _require_clean_ghidra_log(export_logs.application)
            _require_clean_ghidra_log(export_logs.script)
            _require_exported_functions(decompiled)
            if not any(path.stat().st_size for path in decompiled.rglob("*.cpp")):
                raise RuntimeError(
                    f"Ghidra produced no non-empty C++ files; "
                    f"see {logs / 'ghidra-decompile.log'}"
                )

        manifest = {
            "input": str(config.input_path.resolve()),
            "binary": str(resolved.binary),
            "metadata": str(resolved.metadata),
            "generator": artifacts.generator,
            "importer": importer,
            "layout": config.layout,
            "scope": config.scope,
            "assemblies": list(config.assemblies),
            "classes": list(config.classes),
            "project": project_name,
            "commands": [display_command(import_command), display_command(export_command)],
        }
        if not config.dry_run:
            (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    finally:
        if config.keep_temporary:
            print(f"Temporary input retained: {temporary}")
        elif temporary_context is not None:
            temporary_context.cleanup()
