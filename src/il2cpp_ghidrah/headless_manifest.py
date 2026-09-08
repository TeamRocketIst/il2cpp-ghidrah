from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


MAX_MANIFEST_BYTES = 1024 * 1024
LAYOUT_POLICIES = frozenset((
    "allow-inferred",
    "require-external-offsets",
    "require-authoritative",
))
EXPORT_SCOPES = frozenset(("whitelist", "blacklist", "all"))
MAX_DECOMPILE_JOBS = 12


def _input_file(path: Path, description: str) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{description} is not a regular file: {resolved}")
    return str(resolved)


def _input_directory(path: Path, description: str) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{description} is not a directory: {resolved}")
    return str(resolved)


def _output_directory(path: Path) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"export directory must not be a symlink: {expanded}")
    if expanded.exists():
        resolved = expanded.resolve(strict=True)
        if not resolved.is_dir():
            raise ValueError(f"export path is not a directory: {resolved}")
        return str(resolved)

    parent = expanded.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError(f"export parent is not a directory: {parent}")
    return str(parent / expanded.name)


@dataclass(frozen=True)
class ImportManifest:
    header: Path
    offsets: Optional[Path]
    methods: Optional[Path]
    layout_policy: str

    def document(self) -> dict:
        if self.layout_policy not in LAYOUT_POLICIES:
            raise ValueError(f"unsupported layout policy: {self.layout_policy}")
        return {
            "schema": 1,
            "operation": "import",
            "header": _input_file(self.header, "IL2CPP header"),
            "offsets": (
                _input_file(self.offsets, "IL2CPP offset data")
                if self.offsets is not None
                else None
            ),
            "methods": (
                _input_file(self.methods, "IL2CPP method data")
                if self.methods is not None
                else None
            ),
            "layoutPolicy": self.layout_policy,
        }


@dataclass(frozen=True)
class ExportManifest:
    class_source: Path
    output: Path
    scope: str
    framework_rules: Optional[Path]
    noreturn_seeds: Optional[Path]
    decompile_jobs: int

    def document(self) -> dict:
        if self.scope not in EXPORT_SCOPES:
            raise ValueError(f"unsupported export scope: {self.scope}")
        if not 0 <= self.decompile_jobs <= MAX_DECOMPILE_JOBS:
            raise ValueError("decompile jobs must be between 0 and 12")
        return {
            "schema": 1,
            "operation": "export",
            "classSource": _input_directory(self.class_source, "class source"),
            "output": _output_directory(self.output),
            "scope": self.scope,
            "frameworkRules": (
                _input_file(self.framework_rules, "framework rules")
                if self.framework_rules is not None
                else None
            ),
            "noreturnSeeds": (
                _input_file(self.noreturn_seeds, "non-return seeds")
                if self.noreturn_seeds is not None
                else None
            ),
            "decompileJobs": self.decompile_jobs,
        }


def _write_manifest(directory: Path, prefix: str, document: dict) -> Path:
    root = directory.expanduser()
    if root.is_symlink():
        raise ValueError(f"manifest directory must not be a symlink: {root}")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"manifest directory is not a directory: {root}")
    if os.name == "posix" and root.stat().st_mode & 0o077:
        raise ValueError(f"manifest directory must be private: {root}")

    contents = json.dumps(
        document, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if len(contents) > MAX_MANIFEST_BYTES:
        raise ValueError("headless request manifest exceeds 1 MiB")

    descriptor, name = tempfile.mkstemp(prefix=prefix, suffix=".json", dir=root)
    path = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        path.unlink(missing_ok=True)
        raise
    return path


def write_import_manifest(directory: Path, request: ImportManifest) -> Path:
    return _write_manifest(directory, "import-", request.document())


def write_export_manifest(directory: Path, request: ExportManifest) -> Path:
    return _write_manifest(directory, "export-", request.document())
