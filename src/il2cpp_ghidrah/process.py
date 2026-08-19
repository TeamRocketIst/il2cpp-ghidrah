from __future__ import annotations

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Mapping, Sequence, TextIO


class CommandError(RuntimeError):
    pass


class MirroredTextWriter:
    def __init__(self, *streams: TextIO) -> None:
        self._streams = streams

    def write(self, value: str) -> int:
        for stream in self._streams:
            stream.write(value)
            stream.flush()
        return len(value)

    def flush(self) -> None:
        for stream in self._streams:
            stream.flush()


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
        returncode = result.returncode
    else:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("w", encoding="utf-8") as stream:
            stream.write(f"$ {rendered}\n")
            stream.flush()
            process = subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            if process.stdout is None:
                raise RuntimeError("command output pipe was not created")
            mirror = MirroredTextWriter(stream, sys.stdout)
            with process.stdout:
                for line in process.stdout:
                    mirror.write(line)
            returncode = process.wait()
    if returncode:
        location = f"; log: {log}" if log else ""
        raise CommandError(f"command failed with exit code {returncode}{location}: {rendered}")
