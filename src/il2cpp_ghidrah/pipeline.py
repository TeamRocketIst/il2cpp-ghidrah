from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path

from .config import RunConfig
from .generators import generate
from .ghidra import format_elapsed, run_headless
from .headless_manifest import (
    ExportManifest,
    ImportManifest,
    write_export_manifest,
    write_import_manifest,
)
from .headless_process import GhidraHeadlessRunner, HeadlessOperation, HeadlessRequest
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

        if importer == "turbo":
            runner = GhidraHeadlessRunner(installation.ghidra_dir)
            import_manifest = temporary / "import-request.json"
            if not config.dry_run:
                import_manifest = write_import_manifest(
                    temporary,
                    ImportManifest(
                        artifacts.header,
                        artifacts.offsets if artifacts.offsets != Path("-") else None,
                        artifacts.script,
                        config.turbo_policy,
                    ),
                )
            import_request = HeadlessRequest(
                project_dir,
                project_name,
                HeadlessOperation.IMPORT,
                resolved.binary,
                installation.scripts_dir,
                "ImportIl2CppTypes.java",
                import_manifest,
            )
        else:
            fallback_scripts = installation.cparser_scripts_dir
            import_command = [
                str(project_dir),
                project_name,
                "-import",
                str(resolved.binary),
                "-noanalysis",
                "-scriptPath", str(fallback_scripts),
                "-preScript", "parse_header_headless.py", str(artifacts.header),
                "-postScript", "ghidra_with_struct_headless.py", str(artifacts.script),
            ]
            if (fallback_scripts / "ghidraUnityMetadata.py").is_file():
                import_command += [
                    "-postScript", "ghidraUnityMetadata.py", str(artifacts.script),
                ]
        print("Ghidra import (1/2)", flush=True)
        if importer == "turbo":
            import_logs = runner.run(
                import_request,
                log=logs / "ghidra-import.log",
                dry_run=config.dry_run,
                show=config.show_commands,
            )
            import_record = import_logs.command
        else:
            import_logs = run_headless(
                installation.ghidra_dir,
                import_command,
                log=logs / "ghidra-import.log",
                dry_run=config.dry_run,
                show=config.show_commands,
            )
            import_record = tuple(import_command)
        if not config.dry_run:
            print(f"Ghidra import complete in {format_elapsed(import_logs.elapsed_seconds)}")
        if not config.dry_run:
            _require_clean_ghidra_log(import_logs.application)
            _require_clean_ghidra_log(import_logs.script)
            if not any(project_dir.glob(f"{project_name}*")):
                raise RuntimeError(
                    f"Ghidra did not create project {project_name}; "
                    f"see {logs / 'ghidra-import.log'}"
                )

        export_scope = "all" if config.scope == "whitelist" else config.scope
        if importer == "turbo":
            export_manifest = temporary / "export-request.json"
            if not config.dry_run:
                export_manifest = write_export_manifest(
                    temporary,
                    ExportManifest(
                        selected_diffable,
                        decompiled,
                        export_scope,
                        config.ignore_frameworks,
                        artifacts.noreturn_seeds,
                        config.decompile_jobs,
                    ),
                )
            export_request = HeadlessRequest(
                project_dir,
                project_name,
                HeadlessOperation.PROCESS,
                Path(resolved.binary.name),
                installation.scripts_dir,
                "ExportIl2Cpp.java",
                export_manifest,
            )
        else:
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
            export_command += ["--decompile-jobs", str(config.decompile_jobs)]
        export_mode = "legacy sequential" if config.decompile_jobs == 0 else f"{config.decompile_jobs} workers"
        print(f"Ghidra export (2/2), {export_mode}", flush=True)
        if importer == "turbo":
            export_logs = runner.run(
                export_request,
                log=logs / "ghidra-decompile.log",
                dry_run=config.dry_run,
                show=config.show_commands,
            )
            export_record = export_logs.command
        else:
            export_logs = run_headless(
                installation.ghidra_dir,
                export_command,
                log=logs / "ghidra-decompile.log",
                dry_run=config.dry_run,
                show=config.show_commands,
            )
            export_record = tuple(export_command)
        if not config.dry_run:
            print(f"Ghidra export complete in {format_elapsed(export_logs.elapsed_seconds)}")
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
            "decompile_jobs": config.decompile_jobs,
            "project": project_name,
            "commands": [display_command(import_record), display_command(export_record)],
        }
        if not config.dry_run:
            (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            ghidra_elapsed = import_logs.elapsed_seconds + export_logs.elapsed_seconds
            print(
                "Ghidra elapsed: "
                f"{format_elapsed(ghidra_elapsed)} "
                f"(import {format_elapsed(import_logs.elapsed_seconds)}, "
                f"decompilation {format_elapsed(export_logs.elapsed_seconds)})"
            )
    finally:
        if config.keep_temporary:
            print(f"Temporary input retained: {temporary}")
        elif temporary_context is not None:
            temporary_context.cleanup()
