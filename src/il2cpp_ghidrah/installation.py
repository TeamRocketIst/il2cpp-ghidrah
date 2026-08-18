from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Installation:
    ghidra_dir: Path
    extension_dir: Path
    scripts_dir: Path
    cparser_scripts_dir: Path
    turboheader_installed: bool


def _directory(explicit: Path | None, environment_name: str, description: str) -> Path:
    value = explicit
    if value is None and os.environ.get(environment_name):
        value = Path(os.environ[environment_name])
    if value is None:
        raise FileNotFoundError(
            f"{description} is not configured; use the corresponding option "
            f"or {environment_name}"
        )
    result = value.expanduser().resolve()
    if not result.is_dir():
        raise FileNotFoundError(f"{description} directory does not exist: {result}")
    return result


def _cparser_scripts() -> Path | None:
    scripts = Path(__file__).resolve().parent / "ghidra_scripts"
    required = ("parse_header_headless.py", "ghidra_with_struct_headless.py")
    return scripts if all((scripts / name).is_file() for name in required) else None


def discover(
    ghidra_dir: Path | None,
) -> Installation:
    ghidra = _directory(ghidra_dir, "GHIDRA_INSTALL_DIR", "Ghidra")
    extension = ghidra / "Ghidra" / "Extensions" / "turboheader-ghidra-il2cpp"
    scripts = extension / "ghidra_scripts"
    required = [
        ghidra / "Ghidra" / "application.properties",
        scripts / "ImportIl2CppTypes.java",
        scripts / "cpp2il_ghidra_export_editable.py",
        extension / "lib" / "turboheader-ghidra-il2cpp.jar",
    ]
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise FileNotFoundError(
            "TurboHeader must be installed under the selected Ghidra installation; missing: "
            + ", ".join(missing)
        )
    extension_jar = extension / "lib" / "turboheader-ghidra-il2cpp.jar"
    native_libraries = (
        list(extension.glob("os/*/libturboheader_il2cpp.*"))
        if extension.is_dir()
        else []
    )
    turbo_installed = extension_jar.is_file() and bool(native_libraries)
    if not turbo_installed:
        raise FileNotFoundError(
            f"TurboHeader native library is not installed under {extension / 'os'}"
        )
    bundled = _cparser_scripts()
    if bundled is None:
        raise FileNotFoundError("packaged CParserUtils scripts are missing")
    return Installation(ghidra, extension, scripts, bundled, True)


def doctor(
    ghidra_dir: Path | None,
    *,
    importer: str,
    generator: str,
    il2cpp_command: str,
    dumper_command: str,
    cpp2il_command: str,
    probe: bool,
) -> list[tuple[str, bool, str]]:
    from .generators import resolve_tool

    checks: list[tuple[str, bool, str]] = []

    def command(name: str, executable: str, required: bool = True) -> None:
        path = resolve_tool(executable)
        ok = path is not None or not required
        checks.append((name, ok, path or f"not found: {executable}"))

    command("Python", "python3")
    command("Java", "java")
    pyghidra_available = importlib.util.find_spec("pyghidra") is not None
    checks.append(
        (
            "PyGhidra",
            pyghidra_available,
            "installed" if pyghidra_available else "not installed",
        )
    )
    command("il2cpp", il2cpp_command, required=generator == "aotopsy")
    command("Il2CppDumper", dumper_command, required=generator == "dumper")
    command("Cpp2IL", cpp2il_command, required=generator == "dumper")
    if generator == "auto":
        aotopsy = resolve_tool(il2cpp_command)
        dumper = resolve_tool(dumper_command)
        cpp2il = resolve_tool(cpp2il_command)
        usable = bool(aotopsy or (dumper and cpp2il))
        selected = "AOTopsy" if aotopsy else "Il2CppDumper + Cpp2IL" if dumper and cpp2il else "none"
        checks.append(("Automatic generator", usable, selected))
    try:
        installation = discover(ghidra_dir)
        checks += [
            ("Ghidra", True, str(installation.ghidra_dir)),
            ("TurboHeader installation", True, str(installation.extension_dir)),
            ("TurboHeader scripts", True, str(installation.scripts_dir)),
        ]
        extension = installation.ghidra_dir / "Ghidra" / "Extensions" / "turboheader-ghidra-il2cpp"
        extension_jar = extension / "lib" / "turboheader-ghidra-il2cpp.jar"
        native_libraries = (
            list(extension.glob("os/*/libturboheader_il2cpp.*"))
            if extension.is_dir()
            else []
        )
        fallback = installation.cparser_scripts_dir
        checks.append(
            (
                "TurboHeader extension",
                extension_jar.is_file(),
                str(extension_jar) if extension_jar.is_file() else "not installed",
            )
        )
        checks.append(
            (
                "TurboHeader native library",
                bool(native_libraries),
                str(native_libraries[0]) if native_libraries else "not installed",
            )
        )
        checks.append(
            (
                "Packaged CParserUtils scripts",
                fallback is not None,
                str(fallback) if fallback else "not configured",
            )
        )
        checks.append(("Selected importer", True, importer))
        if probe:
            import pyghidra
            pyghidra.start(install_dir=installation.ghidra_dir)
            checks.append(("PyGhidra probe", True, pyghidra.__version__))
    except FileNotFoundError as error:
        checks.append(("Ghidra/TurboHeader", False, str(error)))
    except (OSError, ImportError, RuntimeError, ValueError) as error:
        checks.append(("PyGhidra probe", False, str(error)))
    return checks
