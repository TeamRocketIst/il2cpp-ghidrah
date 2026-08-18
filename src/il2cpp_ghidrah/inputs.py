from __future__ import annotations

import os
import zipfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath


ARCHIVE_SUFFIXES = {".apk", ".apkm", ".apks", ".xapk", ".zip"}
ARM64_BINARY_SUFFIX = ("lib", "arm64-v8a", "libil2cpp.so")
METADATA_SUFFIX = (
    "assets",
    "bin",
    "Data",
    "Managed",
    "Metadata",
    "global-metadata.dat",
)
GLOBAL_MANAGERS_SUFFIX = ("assets", "bin", "Data", "globalgamemanagers")
UNITY_DATA_SUFFIX = ("assets", "bin", "Data", "data.unity3d")
MAX_ARCHIVE_ENTRIES = 250_000
MAX_NESTED_ARCHIVES = 256
MAX_NESTING_DEPTH = 3
MAX_BINARY_SIZE = 2 * 1024**3
MAX_METADATA_SIZE = 1024**3
MAX_UNITY_DATA_SIZE = 4 * 1024**3
MAX_NESTED_ARCHIVE_SIZE = 4 * 1024**3
MAX_TOTAL_EXTRACTED_SIZE = 8 * 1024**3
MAX_COMPRESSION_RATIO = 200
COPY_CHUNK_SIZE = 1024 * 1024


@dataclass(frozen=True)
class ResolvedInput:
    original: Path
    binary: Path
    metadata: Path
    unity_data: Path | None
    assets: Path | None

    @property
    def is_packaged(self) -> bool:
        return self.original.is_file() and self.original.suffix.lower() in ARCHIVE_SUFFIXES


@dataclass
class _ArchiveBudget:
    entries: int = 0
    nested_archives: int = 0
    extracted_bytes: int = 0


@dataclass
class _ArchiveSelection:
    root: Path
    needs_metadata: bool
    needs_unity_data: bool
    binary: Path | None = None
    metadata: Path | None = None
    unity_data: Path | None = None
    unity_priority: int | None = None

    def complete(self) -> bool:
        return (
            self.binary is not None
            and (not self.needs_metadata or self.metadata is not None)
            and (not self.needs_unity_data or self.unity_data is not None)
        )


def _normalized_member_parts(name: str) -> tuple[str, ...]:
    if "\x00" in name:
        raise ValueError("archive member contains a NUL byte")
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or PureWindowsPath(name).drive:
        raise ValueError(f"archive member uses an absolute path: {name}")
    parts = tuple(part for part in normalized.split("/") if part not in {"", "."})
    if ".." in parts:
        raise ValueError(f"archive member escapes its archive root: {name}")
    return parts


def _ends_with(parts: tuple[str, ...], suffix: tuple[str, ...]) -> bool:
    return len(parts) >= len(suffix) and parts[-len(suffix) :] == suffix


def _validate_member_size(member: zipfile.ZipInfo, limit: int) -> None:
    if member.flag_bits & 1:
        raise ValueError(f"encrypted archive member is not supported: {member.filename}")
    if member.file_size > limit:
        raise ValueError(f"archive member is too large: {member.filename}")
    if member.file_size and member.compress_size == 0:
        raise ValueError(f"archive member has an invalid compressed size: {member.filename}")
    if member.file_size > member.compress_size * MAX_COMPRESSION_RATIO:
        raise ValueError(f"archive member exceeds the compression-ratio limit: {member.filename}")


def _copy_member(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    destination: Path,
    limit: int,
    budget: _ArchiveBudget,
) -> Path:
    _validate_member_size(member, limit)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    written = 0
    try:
        with os.fdopen(descriptor, "wb") as output, archive.open(member) as source:
            while True:
                chunk = source.read(COPY_CHUNK_SIZE)
                if not chunk:
                    break
                written += len(chunk)
                if written > limit:
                    raise ValueError(f"archive member exceeded its size limit: {member.filename}")
                if budget.extracted_bytes + len(chunk) > MAX_TOTAL_EXTRACTED_SIZE:
                    raise ValueError("archive extraction exceeded the total size limit")
                output.write(chunk)
                budget.extracted_bytes += len(chunk)
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination


def _accept_core_member(
    archive: zipfile.ZipFile,
    member: zipfile.ZipInfo,
    parts: tuple[str, ...],
    selection: _ArchiveSelection,
    budget: _ArchiveBudget,
) -> bool:
    if _ends_with(parts, ARM64_BINARY_SUFFIX):
        if selection.binary is not None:
            raise ValueError("multiple arm64-v8a libil2cpp.so entries were found")
        selection.binary = _copy_member(
            archive,
            member,
            selection.root / "libil2cpp.so",
            MAX_BINARY_SIZE,
            budget,
        )
        return True

    if selection.needs_metadata and _ends_with(parts, METADATA_SUFFIX):
        if selection.metadata is not None:
            raise ValueError("multiple global-metadata.dat entries were found")
        selection.metadata = _copy_member(
            archive,
            member,
            selection.root / "global-metadata.dat",
            MAX_METADATA_SIZE,
            budget,
        )
        return True

    unity_priority = None
    if _ends_with(parts, GLOBAL_MANAGERS_SUFFIX):
        unity_priority = 0
    elif _ends_with(parts, UNITY_DATA_SUFFIX):
        unity_priority = 1

    if selection.needs_unity_data and unity_priority is not None:
        if selection.unity_priority == unity_priority:
            raise ValueError("multiple equivalent Unity version sources were found")
        if selection.unity_priority is not None and selection.unity_priority < unity_priority:
            return True
        if selection.unity_data is not None:
            selection.unity_data.unlink(missing_ok=True)
            selection.unity_data = None
        selection.unity_data = _copy_member(
            archive,
            member,
            selection.root / "unity-version-data",
            MAX_UNITY_DATA_SIZE,
            budget,
        )
        selection.unity_priority = unity_priority
        return True

    return False


def _scan_archive(
    archive_path: Path,
    selection: _ArchiveSelection,
    budget: _ArchiveBudget,
    depth: int,
) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        budget.entries += len(members)
        if budget.entries > MAX_ARCHIVE_ENTRIES:
            raise ValueError("archive entry count exceeded the configured limit")

        nested_members: list[tuple[zipfile.ZipInfo, tuple[str, ...]]] = []
        for member in members:
            parts = _normalized_member_parts(member.filename)
            if member.is_dir() or not parts:
                continue
            if _accept_core_member(archive, member, parts, selection, budget):
                continue
            if Path(parts[-1]).suffix.lower() in ARCHIVE_SUFFIXES:
                nested_members.append((member, parts))

        if selection.complete():
            return
        if depth >= MAX_NESTING_DEPTH and nested_members:
            raise ValueError("archive nesting exceeded the configured limit")

        for member, _ in sorted(nested_members, key=lambda item: item[0].filename):
            budget.nested_archives += 1
            if budget.nested_archives > MAX_NESTED_ARCHIVES:
                raise ValueError("nested archive count exceeded the configured limit")
            nested_path = selection.root / f"nested-{budget.nested_archives:04d}.zip"
            _copy_member(
                archive,
                member,
                nested_path,
                MAX_NESTED_ARCHIVE_SIZE,
                budget,
            )
            try:
                if zipfile.is_zipfile(nested_path):
                    _scan_archive(nested_path, selection, budget, depth + 1)
            finally:
                nested_path.unlink(missing_ok=True)
            if selection.complete():
                return


def _validate_arm64_elf(path: Path) -> None:
    with path.open("rb") as binary:
        header = binary.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise ValueError(f"not an ELF binary: {path}")
    if header[4] != 2 or header[5] != 1:
        raise ValueError(f"libil2cpp.so must be a little-endian 64-bit ELF: {path}")
    if int.from_bytes(header[18:20], "little") != 183:
        raise ValueError(f"libil2cpp.so is not AArch64: {path}")


def _resolve_file(path: Path, description: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_file():
        raise FileNotFoundError(f"{description} does not exist: {resolved}")
    return resolved


def _resolve_directory(path: Path, description: str) -> Path:
    resolved = path.expanduser().resolve()
    if not resolved.is_dir():
        raise FileNotFoundError(f"{description} does not exist: {resolved}")
    return resolved


def _choose_unique(candidates: list[Path], description: str) -> Path:
    candidates = sorted({candidate.resolve() for candidate in candidates})
    if not candidates:
        raise FileNotFoundError(f"could not find {description}")
    if len(candidates) != 1:
        raise ValueError(f"multiple candidates found for {description}")
    return candidates[0]


def _loose_candidates(root: Path, suffix: tuple[str, ...]) -> list[Path]:
    result = []
    for candidate in root.rglob(suffix[-1]):
        if candidate.is_symlink():
            raise ValueError(f"symbolic-link input candidate is not allowed: {candidate}")
        relative_parts = candidate.relative_to(root).parts
        if candidate.is_file() and _ends_with(relative_parts, suffix):
            result.append(candidate)
    return result


def _resolve_loose_unity_data(root: Path) -> Path | None:
    managers = _loose_candidates(root, GLOBAL_MANAGERS_SUFFIX)
    if managers:
        return _choose_unique(managers, "globalgamemanagers")
    unity_data = _loose_candidates(root, UNITY_DATA_SUFFIX)
    return _choose_unique(unity_data, "data.unity3d") if unity_data else None


def resolve_input(
    input_path: Path,
    temporary: Path,
    *,
    metadata: Path | None,
    assets: Path | None,
    unity_data: Path | None = None,
    unity: str | None = None,
    abi: str = "arm64-v8a",
) -> ResolvedInput:
    if abi != "arm64-v8a":
        raise ValueError("il2cpp-ghidrah currently supports only arm64-v8a")

    original = input_path.expanduser().resolve()
    if not original.exists():
        raise FileNotFoundError(f"input does not exist: {original}")

    resolved_assets = _resolve_directory(assets, "assets directory") if assets else None
    resolved_unity_data = (
        unity_data.expanduser().resolve() if unity_data is not None else None
    )
    if resolved_unity_data is not None and not resolved_unity_data.exists():
        raise FileNotFoundError(f"Unity version source does not exist: {resolved_unity_data}")

    if original.is_file() and original.suffix.lower() == ".so":
        if metadata is None:
            raise ValueError("direct libil2cpp.so input requires --metadata")
        resolved_metadata = _resolve_file(metadata, "global metadata")
        _validate_arm64_elf(original)
        if unity is None and resolved_unity_data is None and resolved_assets is None:
            raise ValueError(
                "direct libil2cpp.so input requires --unity, --unity-data, or --assets"
            )
        return ResolvedInput(
            original,
            original,
            resolved_metadata,
            resolved_unity_data,
            resolved_assets,
        )

    if original.is_dir():
        binary = _choose_unique(
            _loose_candidates(original, ARM64_BINARY_SUFFIX),
            "arm64-v8a libil2cpp.so",
        )
        resolved_metadata = (
            _resolve_file(metadata, "global metadata")
            if metadata is not None
            else _choose_unique(
                _loose_candidates(original, METADATA_SUFFIX),
                "global-metadata.dat",
            )
        )
        if unity is None and resolved_unity_data is None and resolved_assets is None:
            resolved_unity_data = _resolve_loose_unity_data(original)
        _validate_arm64_elf(binary)
        if unity is None and resolved_unity_data is None and resolved_assets is None:
            raise FileNotFoundError(
                "could not find a Unity version source; use --unity, --unity-data, or --assets"
            )
        return ResolvedInput(
            original,
            binary,
            resolved_metadata,
            resolved_unity_data,
            resolved_assets,
        )

    if original.suffix.lower() not in ARCHIVE_SUFFIXES or not zipfile.is_zipfile(original):
        raise ValueError(f"unsupported input file: {original}")

    extraction_root = temporary / "input"
    extraction_root.mkdir(parents=True, mode=0o700)
    resolved_metadata = (
        _resolve_file(metadata, "global metadata") if metadata is not None else None
    )
    selection = _ArchiveSelection(
        extraction_root,
        needs_metadata=resolved_metadata is None,
        needs_unity_data=(
            unity is None and resolved_unity_data is None and resolved_assets is None
        ),
        metadata=resolved_metadata,
        unity_data=resolved_unity_data,
    )
    _scan_archive(original, selection, _ArchiveBudget(), 0)

    if selection.binary is None:
        raise FileNotFoundError("arm64-v8a libil2cpp.so was not found in the package")
    if selection.metadata is None:
        raise FileNotFoundError("global-metadata.dat was not found in the package")
    if selection.needs_unity_data and selection.unity_data is None:
        raise FileNotFoundError(
            "Unity version data was not found; use --unity or --unity-data"
        )

    _validate_arm64_elf(selection.binary)
    return ResolvedInput(
        original,
        selection.binary,
        selection.metadata,
        selection.unity_data,
        resolved_assets,
    )
