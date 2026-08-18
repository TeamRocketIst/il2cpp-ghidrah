from __future__ import annotations

import shlex
import subprocess
from pathlib import Path
from typing import Mapping, Sequence


class CommandError(RuntimeError):
    pass


def display_command(command: Sequence[str]) -> str:
    return shlex.join(str(item) for item in command)


def run_command(
    command: Sequence[str],
    *,
    log: Path | None = None,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
    dry_run: bool = False,
    show: bool = False,
) -> None:
    rendered = display_command(command)
    if show or dry_run:
        print(f"$ {rendered}")
    if dry_run:
        return
    if log is None:
        result = subprocess.run(command, cwd=cwd, env=environment, check=False)
    else:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as stream:
            stream.write(f"$ {rendered}\n")
            stream.flush()
            result = subprocess.run(
                command,
                cwd=cwd,
                env=environment,
                stdout=stream,
                stderr=subprocess.STDOUT,
                check=False,
            )
    if result.returncode:
        location = f"; log: {log}" if log else ""
        raise CommandError(f"command failed with exit code {result.returncode}{location}: {rendered}")
