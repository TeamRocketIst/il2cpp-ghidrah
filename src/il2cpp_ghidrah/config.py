from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


LAYOUT_POLICIES = {
    "inferred": "allow-inferred",
    "external": "require-external-offsets",
    "authoritative": "require-authoritative",
}


@dataclass(frozen=True)
class RunConfig:
    input_path: Path
    output: Path
    generator: str = "auto"
    layout: str = "external"
    scope: str = "blacklist"
    metadata: Path | None = None
    assets: Path | None = None
    unity_data: Path | None = None
    unity: str | None = None
    abi: str = "arm64-v8a"
    assemblies: tuple[str, ...] = ()
    classes: tuple[str, ...] = ()
    ignore_frameworks: Path | None = None
    ghidra_dir: Path | None = None
    importer: str = "turbo"
    project_name: str | None = None
    il2cpp_command: str = "il2cpp"
    dumper_command: str = "Il2CppDumper"
    cpp2il_command: str = "Cpp2IL"
    decompile_jobs: int = 8
    dry_run: bool = False
    show_commands: bool = False
    keep_temporary: bool = False

    def __post_init__(self) -> None:
        if type(self.decompile_jobs) is not int or not 0 <= self.decompile_jobs <= 12:
            raise ValueError("decompile_jobs must be an integer from 0 through 12")

    @property
    def turbo_policy(self) -> str:
        return LAYOUT_POLICIES[self.layout]
