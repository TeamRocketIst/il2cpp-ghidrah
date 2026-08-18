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
    dry_run: bool = False
    show_commands: bool = False
    keep_temporary: bool = False

    @property
    def turbo_policy(self) -> str:
        return LAYOUT_POLICIES[self.layout]
