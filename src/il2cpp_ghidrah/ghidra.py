from __future__ import annotations

import contextlib
import multiprocessing
import os
import queue
import shutil
import sys
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from .process import MirroredTextWriter, display_command


@dataclass(frozen=True)
class HeadlessLogs:
    application: Path
    script: Path
    launcher: Path


def _copy_isolated_log(root: Path, name: str, destination: Path) -> None:
    matches = list(root.rglob(name))
    if len(matches) == 1:
        shutil.copyfile(matches[0], destination)


def _headless_worker(
    install_dir: str,
    arguments: tuple[str, ...],
    log_path: str,
    config_home: str,
    cache_home: str,
    errors: multiprocessing.Queue,
) -> None:
    log = Path(log_path)
    try:
        os.environ["XDG_CONFIG_HOME"] = config_home
        os.environ["XDG_CACHE_HOME"] = cache_home
        import pyghidra

        with log.open("a", encoding="utf-8") as stream:
            mirror = MirroredTextWriter(stream, sys.stdout)
            mirror.write(f"PyGhidra process: {os.getpid()}\n")
            with contextlib.redirect_stdout(mirror), contextlib.redirect_stderr(mirror):
                launcher = pyghidra.start(install_dir=Path(install_dir))

                from ghidra.app.util.headless import AnalyzeHeadless

                AnalyzeHeadless().launch(launcher._layout, list(arguments))
    except BaseException:
        errors.put(traceback.format_exc())
        raise


def run_headless(
    install_dir: Path,
    arguments: Sequence[str],
    *,
    log: Path,
    dry_run: bool = False,
    show: bool = False,
) -> HeadlessLogs:
    if len(arguments) < 2:
        raise ValueError("AnalyzeHeadless requires a project directory and project name")
    script_log = log.with_name(f"{log.stem}-script{log.suffix}")
    launcher_log = log.with_name(f"{log.stem}-launcher{log.suffix}")
    complete_arguments = list(arguments)
    rendered = "pyghidra AnalyzeHeadless " + display_command(complete_arguments)
    if show or dry_run:
        print(f"$ {rendered}")
    if dry_run:
        return HeadlessLogs(log, script_log, launcher_log)

    try:
        import pyghidra  # noqa: F401
    except ImportError as error:
        raise RuntimeError(
            "PyGhidra is required; install this package with its dependencies"
        ) from error

    launcher_log.parent.mkdir(parents=True, exist_ok=True)
    launcher_log.write_text(f"$ {rendered}\n", encoding="utf-8")

    with tempfile.TemporaryDirectory(prefix="il2cpp-ghidrah-ghidra-") as directory:
        isolated = Path(directory)
        config_home = isolated / "config"
        cache_home = isolated / "cache"
        config_home.mkdir()
        cache_home.mkdir()
        context = multiprocessing.get_context("spawn")
        errors = context.Queue()
        process = context.Process(
            target=_headless_worker,
            args=(
                str(install_dir),
                tuple(complete_arguments),
                str(launcher_log),
                str(config_home),
                str(cache_home),
                errors,
            ),
            name="il2cpp-ghidrah-headless",
        )
        process.start()
        process.join()
        _copy_isolated_log(config_home, "application.log", log)
        _copy_isolated_log(config_home, "script.log", script_log)
    if process.exitcode:
        try:
            detail = errors.get_nowait()
        except queue.Empty:
            detail = "no Python traceback was reported"
        raise RuntimeError(
            f"PyGhidra headless process failed with exit code {process.exitcode}; "
            f"see {launcher_log}\n{detail}"
        )
    return HeadlessLogs(log, script_log, launcher_log)
