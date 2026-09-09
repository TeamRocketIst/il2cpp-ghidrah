from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Mapping, Optional, Tuple

from .process import display_command


class HeadlessOperation(Enum):
    IMPORT = "import"
    PROCESS = "process"


SCRIPT_BY_OPERATION = {
    HeadlessOperation.IMPORT: "ImportIl2CppTypes.java",
    HeadlessOperation.PROCESS: "ExportIl2Cpp.java",
}

REMOVED_ENVIRONMENT = frozenset((
    "BASH_ENV",
    "CLASSPATH",
    "ENV",
    "GHIDRA_HEADLESS_JAVA_OPTIONS",
    "GHIDRA_JAVA_OPTIONS",
    "JAVA_TOOL_OPTIONS",
    "JDK_JAVA_OPTIONS",
    "LD_PRELOAD",
    "_JAVA_OPTIONS",
))

_PROJECT_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_PROGRAM_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_WINDOWS_BATCH_META = frozenset("&|<>^%!")


@dataclass(frozen=True)
class HeadlessRequest:
    project_directory: Path
    project_name: str
    operation: HeadlessOperation
    target: Path
    script_directory: Path
    script_name: str
    manifest: Path

    def __post_init__(self) -> None:
        if not isinstance(self.operation, HeadlessOperation):
            raise TypeError("headless operation must be a HeadlessOperation")
        if not _PROJECT_NAME.fullmatch(self.project_name):
            raise ValueError("invalid Ghidra project name")
        if self.script_name not in SCRIPT_BY_OPERATION.values():
            raise ValueError(f"headless script is not allowed: {self.script_name}")
        expected_script = SCRIPT_BY_OPERATION[self.operation]
        if self.script_name != expected_script:
            raise ValueError(f"{self.operation.value} requires {expected_script}")
        program_name = str(self.target)
        if self.operation is HeadlessOperation.PROCESS and not _PROGRAM_NAME.fullmatch(program_name):
            raise ValueError("invalid Ghidra program name")


@dataclass(frozen=True)
class HeadlessResult:
    command: Tuple[str, ...]
    application_log: Path
    script_log: Path
    launcher_log: Path
    elapsed_seconds: float

    @property
    def application(self) -> Path:
        return self.application_log

    @property
    def script(self) -> Path:
        return self.script_log

    @property
    def launcher(self) -> Path:
        return self.launcher_log


def _resolved_file(path: Path, description: str, *, allow_symlink: bool = False) -> Path:
    expanded = path.expanduser()
    if not allow_symlink and expanded.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_file():
        raise ValueError(f"{description} is not a regular file: {resolved}")
    return resolved


def _resolved_directory(
    path: Path, description: str, *, allow_symlink: bool = False
) -> Path:
    expanded = path.expanduser()
    if not allow_symlink and expanded.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {expanded}")
    resolved = expanded.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"{description} is not a directory: {resolved}")
    return resolved


def _check_argument(value: str, *, windows: bool) -> None:
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("headless arguments must not contain control characters")
    if windows and any(character in _WINDOWS_BATCH_META for character in value):
        raise ValueError("headless arguments contain unsafe Windows batch characters")


def _launcher(install_directory: Path, *, platform: str) -> Path:
    root = _resolved_directory(
        install_directory, "Ghidra installation", allow_symlink=True
    )
    name = "analyzeHeadless.bat" if platform == "nt" else "analyzeHeadless"
    launcher = _resolved_file(
        root / "support" / name, "Ghidra headless launcher", allow_symlink=True
    )
    try:
        launcher.relative_to(root)
    except ValueError as error:
        raise ValueError("Ghidra headless launcher escapes its installation") from error
    if platform != "nt" and not os.access(launcher, os.X_OK):
        raise ValueError(f"Ghidra headless launcher is not executable: {launcher}")
    return launcher


def _environment(source: Mapping[str, str], private_root: Path) -> Mapping[str, str]:
    environment = dict(source)
    for name in REMOVED_ENVIRONMENT:
        environment.pop(name, None)
    environment["XDG_CONFIG_HOME"] = str(private_root / "config")
    environment["XDG_CACHE_HOME"] = str(private_root / "cache")
    return environment


def _terminal_text(value: str) -> str:
    output = []
    for character in value:
        if character in ("\n", "\t"):
            output.append(character)
        elif unicodedata.category(character) in ("Cc", "Cf"):
            output.append(f"\\u{ord(character):04x}")
        else:
            output.append(character)
    return "".join(output)


def _log_path(path: Path, description: str) -> Path:
    expanded = path.expanduser()
    if expanded.is_symlink():
        raise ValueError(f"{description} must not be a symlink: {expanded}")
    if expanded.exists() and not expanded.is_file():
        raise ValueError(f"{description} is not a regular file: {expanded}")
    return expanded.resolve()


class GhidraHeadlessRunner:
    def __init__(
        self,
        install_directory: Path,
        *,
        platform: Optional[str] = None,
        environment: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._platform = platform or os.name
        if self._platform not in ("nt", "posix"):
            raise ValueError(f"unsupported operating system: {self._platform}")
        self._launcher = _launcher(install_directory, platform=self._platform)
        self._base_environment = dict(
            environment if environment is not None else os.environ
        )

    def command(
        self,
        request: HeadlessRequest,
        *,
        application_log: Path,
        script_log: Path,
    ) -> Tuple[str, ...]:
        return self._command(request, application_log, script_log, validate_files=True)

    def preview_command(
        self,
        request: HeadlessRequest,
        *,
        application_log: Path,
        script_log: Path,
    ) -> Tuple[str, ...]:
        return self._command(request, application_log, script_log, validate_files=False)

    def _command(
        self,
        request: HeadlessRequest,
        application_log: Path,
        script_log: Path,
        *,
        validate_files: bool,
    ) -> Tuple[str, ...]:
        if validate_files:
            project_directory = _resolved_directory(
                request.project_directory, "Ghidra project directory"
            )
            script_directory = _resolved_directory(
                request.script_directory, "Ghidra script directory"
            )
            _resolved_file(script_directory / request.script_name, "Ghidra script")
            manifest = _resolved_file(request.manifest, "headless request manifest")
            if manifest.stat().st_size > 1024 * 1024:
                raise ValueError("headless request manifest exceeds 1 MiB")
        else:
            project_directory = request.project_directory.expanduser().resolve()
            script_directory = request.script_directory.expanduser().resolve()
            manifest = request.manifest.expanduser().resolve()

        if request.operation is HeadlessOperation.IMPORT:
            operation = "-import"
            target_path = request.target.expanduser().resolve()
            if validate_files:
                target_path = _resolved_file(request.target, "import binary")
            target = str(target_path)
        else:
            operation = "-process"
            target = str(request.target)

        command = (
            str(self._launcher),
            str(project_directory),
            request.project_name,
            operation,
            target,
            "-noanalysis",
            "-log",
            str(application_log.expanduser().resolve()),
            "-scriptlog",
            str(script_log.expanduser().resolve()),
            "-scriptPath",
            str(script_directory),
            "-postScript",
            request.script_name,
            "--request",
            str(manifest),
        )
        for argument in command:
            _check_argument(argument, windows=self._platform == "nt")
        return command

    def run(
        self,
        request: HeadlessRequest,
        *,
        log: Path,
        timeout_seconds: Optional[float] = None,
        dry_run: bool = False,
        show: bool = False,
    ) -> HeadlessResult:
        application_log = _log_path(log, "Ghidra application log")
        script_log = _log_path(application_log.with_name(
            f"{application_log.stem}-script{application_log.suffix}"
        ), "Ghidra script log")
        launcher_log = _log_path(application_log.with_name(
            f"{application_log.stem}-launcher{application_log.suffix}"
        ), "Ghidra launcher log")
        command_builder = self.preview_command if dry_run else self.command
        command = command_builder(request, application_log=application_log, script_log=script_log)
        rendered = display_command(command)
        if show or dry_run:
            print(f"$ {rendered}")
        if dry_run:
            return HeadlessResult(command, application_log, script_log, launcher_log, 0.0)
        if timeout_seconds is not None and timeout_seconds <= 0:
            raise ValueError("headless timeout must be greater than zero")

        application_log.parent.mkdir(parents=True, exist_ok=True)
        launcher_log.write_text(f"$ {rendered}\n", encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="il2cpp-ghidrah-headless-") as directory:
            private_root = Path(directory)
            (private_root / "config").mkdir(mode=0o700)
            (private_root / "cache").mkdir(mode=0o700)
            environment = _environment(self._base_environment, private_root)
            started = time.perf_counter()
            with launcher_log.open("a", encoding="utf-8") as output:
                process = subprocess.Popen(
                    command,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    start_new_session=self._platform != "nt",
                    creationflags=(
                        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                        if self._platform == "nt"
                        else 0
                    ),
                    shell=False,
                )
                expired = threading.Event()
                timer = None
                if timeout_seconds is not None:
                    def stop_after_timeout() -> None:
                        expired.set()
                        self._stop(process)

                    timer = threading.Timer(timeout_seconds, stop_after_timeout)
                    timer.daemon = True
                    timer.start()
                try:
                    if process.stdout is None:
                        raise RuntimeError("Ghidra output pipe was not created")
                    with process.stdout:
                        for line in process.stdout:
                            output.write(line)
                            output.flush()
                            sys.stdout.write(_terminal_text(line))
                            sys.stdout.flush()
                    return_code = process.wait()
                except BaseException:
                    self._stop(process)
                    raise
                finally:
                    if timer is not None:
                        timer.cancel()
                if expired.is_set():
                    raise subprocess.TimeoutExpired(command, timeout_seconds)
            elapsed = time.perf_counter() - started

        if return_code:
            raise RuntimeError(
                f"Ghidra headless process failed with exit code {return_code}; "
                f"see {launcher_log}"
            )
        if not application_log.is_file():
            raise RuntimeError(f"Ghidra did not create its application log: {application_log}")
        if not script_log.is_file():
            raise RuntimeError(f"Ghidra did not create its script log: {script_log}")
        return HeadlessResult(command, application_log, script_log, launcher_log, elapsed)

    def _stop(self, process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        if self._platform == "nt":
            try:
                process.send_signal(signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError):
                process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            if self._platform == "nt":
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
