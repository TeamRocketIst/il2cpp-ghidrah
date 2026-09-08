from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Tuple


SUMMARY_FIELDS = (
    "Assemblies included",
    "Assemblies skipped",
    "Classes selected",
    "Class files written",
    "Functions scanned",
    "Functions matched/exported",
    "Functions failed to decompile",
    "Functions recovered after restart",
    "Ambiguous functions skipped",
    "Assembly ambiguities resolved",
    "Assembly mismatches skipped",
    "Classes with no matches",
)

DIAGNOSTIC_FILES = (
    "_ambiguous_matches.txt",
    "_assembly_filter.txt",
    "_classes_with_no_matches.txt",
)

_SUMMARY_LINE = re.compile(r"^([^:\n]+):\s*(\d+)\s*$", re.MULTILINE)


@dataclass(frozen=True)
class ExportFile:
    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ExportSnapshot:
    summary: Tuple[Tuple[str, int], ...]
    files: Tuple[ExportFile, ...]


@dataclass(frozen=True)
class ExportComparison:
    differences: Tuple[str, ...]

    @property
    def equal(self) -> bool:
        return not self.differences


def _regular_files(root: Path) -> Iterable[Path]:
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            if path.is_symlink():
                raise ValueError(f"export contains a directory symlink: {path}")
        for name in filenames:
            path = directory_path / name
            if path.is_symlink():
                raise ValueError(f"export contains a file symlink: {path}")
            if not path.is_file():
                raise ValueError(f"export contains a non-regular file: {path}")
            yield path


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def _parse_summary(path: Path) -> Tuple[Tuple[str, int], ...]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"export summary is missing or unsafe: {path}")
    values = {
        name.strip(): int(value)
        for name, value in _SUMMARY_LINE.findall(
            path.read_text(encoding="utf-8", errors="strict")
        )
    }
    missing = [name for name in SUMMARY_FIELDS if name not in values]
    if missing:
        raise ValueError("export summary is missing: " + ", ".join(missing))
    return tuple((name, values[name]) for name in SUMMARY_FIELDS)


def capture_export(directory: Path) -> ExportSnapshot:
    root = directory.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError(f"export root is not a directory: {root}")

    summary = _parse_summary(root / "_export_summary.txt")
    included = set(DIAGNOSTIC_FILES)
    files = []
    for path in _regular_files(root):
        relative = path.relative_to(root).as_posix()
        if path.suffix == ".cpp" or relative in included:
            files.append(ExportFile(relative, path.stat().st_size, _sha256(path)))
    files.sort(key=lambda item: item.path)
    return ExportSnapshot(summary, tuple(files))


def compare_exports(reference: Path, candidate: Path) -> ExportComparison:
    expected = capture_export(reference)
    actual = capture_export(candidate)
    differences = []

    expected_summary = dict(expected.summary)
    actual_summary = dict(actual.summary)
    for name in SUMMARY_FIELDS:
        if expected_summary[name] != actual_summary[name]:
            differences.append(
                f"summary {name}: expected {expected_summary[name]}, "
                f"found {actual_summary[name]}"
            )

    expected_files: Dict[str, ExportFile] = {item.path: item for item in expected.files}
    actual_files: Dict[str, ExportFile] = {item.path: item for item in actual.files}
    for path in sorted(expected_files.keys() - actual_files.keys()):
        differences.append(f"missing file: {path}")
    for path in sorted(actual_files.keys() - expected_files.keys()):
        differences.append(f"unexpected file: {path}")
    for path in sorted(expected_files.keys() & actual_files.keys()):
        expected_file = expected_files[path]
        actual_file = actual_files[path]
        if expected_file.sha256 != actual_file.sha256:
            differences.append(
                f"changed file: {path} "
                f"({expected_file.size} bytes -> {actual_file.size} bytes)"
            )
    return ExportComparison(tuple(differences))
