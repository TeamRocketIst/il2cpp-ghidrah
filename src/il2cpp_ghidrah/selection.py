from __future__ import annotations

import shutil
from pathlib import Path


DEFAULT_WHITELIST = ("Assembly-CSharp", "Assembly-CSharp-firstpass")


def _normalized(value: str) -> str:
    value = value.strip().replace("\\", "/")
    if value.lower().endswith(".cs"):
        value = value[:-3]
    return value.replace("/", ".").casefold()


def _class_keys(relative: Path) -> set[str]:
    without_suffix = relative.with_suffix("")
    parts = without_suffix.parts
    path = ".".join(parts)
    return {
        _normalized(without_suffix.name),
        _normalized(path),
        _normalized(".".join(parts[1:])) if len(parts) > 1 else _normalized(path),
    }


def prepare_diffable_selection(
    source: Path,
    destination: Path,
    *,
    scope: str,
    assemblies: tuple[str, ...],
    classes: tuple[str, ...],
) -> Path:
    needs_assembly_filter = scope == "whitelist"
    if not needs_assembly_filter and not classes:
        return source
    allowed_assemblies = {item.casefold() for item in (assemblies or DEFAULT_WHITELIST)}
    allowed_classes = {_normalized(item) for item in classes}
    selected = 0
    for path in source.rglob("*.cs"):
        relative = path.relative_to(source)
        if not relative.parts:
            continue
        if needs_assembly_filter and relative.parts[0].casefold() not in allowed_assemblies:
            continue
        if allowed_classes and not (_class_keys(relative) & allowed_classes):
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        selected += 1
    if selected == 0:
        raise ValueError("no DiffableCs classes matched the assembly/class selection")
    return destination
