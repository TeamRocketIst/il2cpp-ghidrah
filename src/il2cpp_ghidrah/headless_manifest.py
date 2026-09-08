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


def _input_file(path: Path, description: str) -> str:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{description} is not a regular file: {resolved}")
    return str(resolved)


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


def write_import_manifest(directory: Path, request: ImportManifest) -> Path:
    root = directory.expanduser()
    if root.is_symlink():
        raise ValueError(f"manifest directory must not be a symlink: {root}")
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"manifest directory is not a directory: {root}")
    if os.name == "posix" and root.stat().st_mode & 0o077:
        raise ValueError(f"manifest directory must be private: {root}")

    contents = json.dumps(
        request.document(), ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    if len(contents) > MAX_MANIFEST_BYTES:
        raise ValueError("headless request manifest exceeds 1 MiB")

    descriptor, name = tempfile.mkstemp(prefix="import-", suffix=".json", dir=root)
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
