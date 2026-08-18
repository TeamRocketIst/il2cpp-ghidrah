from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import shutil

from .config import RunConfig
from .inputs import ResolvedInput
from .process import run_command


CPP2IL_PACKAGE_UNITY_FALLBACK = "2022.3.0f1"


@dataclass(frozen=True)
class Artifacts:
    directory: Path
    header: Path
    script: Path
    offsets: Path
    diffable: Path
    generator: str
    noreturn_seeds: Path | None


def resolve_tool(command: str) -> str | None:
    return shutil.which(command)


def select_generator(config: RunConfig) -> tuple[str, str, str | None]:
    aotopsy = resolve_tool(config.il2cpp_command)
    dumper = resolve_tool(config.dumper_command)
    cpp2il = resolve_tool(config.cpp2il_command)
    if config.generator == "aotopsy":
        if not aotopsy:
            raise FileNotFoundError(f"AOTopsy command not found: {config.il2cpp_command}")
        return "aotopsy", aotopsy, None
    if config.generator == "dumper":
        if not dumper:
            raise FileNotFoundError(f"Il2CppDumper command not found: {config.dumper_command}")
        if not cpp2il:
            raise FileNotFoundError(f"Cpp2IL command not found: {config.cpp2il_command}")
        return "dumper", dumper, cpp2il
    if aotopsy:
        return "aotopsy", aotopsy, None
    if dumper and cpp2il:
        return "dumper", dumper, cpp2il
    raise FileNotFoundError(
        "no artifact generator is usable: install AOTopsy, or both Il2CppDumper and Cpp2IL"
    )


def _input_options(config: RunConfig, resolved: ResolvedInput) -> list[str]:
    options: list[str] = []
    if resolved.original == resolved.binary:
        options += ["--metadata", str(resolved.metadata)]
    if config.unity:
        options += ["--unity", config.unity]
    elif config.unity_data:
        options += ["--unity-data", str(config.unity_data.resolve())]
    elif resolved.assets:
        options += ["--assets", str(resolved.assets)]
    return options


def _cpp2il_unity_version(config: RunConfig, resolved: ResolvedInput) -> str:
    if config.unity:
        return config.unity
    if not resolved.is_packaged:
        raise ValueError(
            "Cpp2IL with extracted or direct inputs requires an explicit --unity version"
        )
    print(
        "WARNING: no Unity version was supplied for the packaged input; "
        f"Cpp2IL will use {CPP2IL_PACKAGE_UNITY_FALLBACK}. "
        "Results may be inaccurate for applications built with another Unity version."
    )
    return CPP2IL_PACKAGE_UNITY_FALLBACK


def generate(
    config: RunConfig,
    resolved: ResolvedInput,
    artifacts_dir: Path,
    cpp2il_dir: Path,
    logs_dir: Path,
) -> Artifacts:
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    cpp2il_dir.mkdir(parents=True, exist_ok=True)
    input_options = _input_options(config, resolved)
    generator, generator_command, cpp2il_command = select_generator(config)
    cpp2il_unity_version = None
    if generator == "dumper":
        cpp2il_unity_version = _cpp2il_unity_version(config, resolved)
    print(f"Artifact generator selected: {generator}")
    if generator == "aotopsy":
        command = [
            generator_command,
            "gen",
            str(resolved.original),
            str(artifacts_dir),
            *input_options,
        ]
    else:
        command = [
            generator_command,
            str(resolved.binary),
            str(resolved.metadata),
            str(artifacts_dir),
        ]
    run_command(
        command,
        log=logs_dir / "generation.log",
        dry_run=config.dry_run,
        show=config.show_commands,
    )

    if generator == "aotopsy":
        diffable_command = [
            generator_command,
            "diffable",
            str(resolved.original),
            str(cpp2il_dir),
            *input_options,
        ]
    else:
        if cpp2il_unity_version is None:
            raise RuntimeError("Cpp2IL Unity version was not resolved")
        diffable_command = [
            str(cpp2il_command),
            "--force-binary-path",
            str(resolved.binary),
            "--force-metadata-path",
            str(resolved.metadata),
            "--output-as",
            "diffable-cs",
            "--output-to",
            str(cpp2il_dir),
            "--force-unity-version",
            cpp2il_unity_version,
        ]
    run_command(
        diffable_command,
        log=logs_dir / "diffable.log",
        dry_run=config.dry_run,
        show=config.show_commands,
    )

    header = artifacts_dir / "il2cpp.h"
    script = artifacts_dir / "script.json"
    if config.layout == "inferred":
        offsets = Path("-")
    elif generator == "aotopsy":
        offsets = artifacts_dir / "type_offsets.json"
    else:
        offsets = artifacts_dir / "dump.cs"
    if not config.dry_run:
        required = [header, script, cpp2il_dir / "DiffableCs"]
        if offsets != Path("-"):
            required.append(offsets)
        missing = [str(path) for path in required if not path.exists()]
        if missing:
            raise FileNotFoundError("generator did not produce: " + ", ".join(missing))
    noreturn_seeds = artifacts_dir / "noreturn-seeds.txt" if generator == "aotopsy" else None
    if noreturn_seeds is not None and not config.dry_run:
        if not noreturn_seeds.is_file() or noreturn_seeds.stat().st_size == 0:
            noreturn_seeds = None
    return Artifacts(
        artifacts_dir,
        header,
        script,
        offsets,
        cpp2il_dir / "DiffableCs",
        generator,
        noreturn_seeds,
    )
