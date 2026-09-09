from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from il2cpp_ghidrah.headless_process import (
    GhidraHeadlessRunner,
    HeadlessOperation,
    HeadlessRequest,
    _environment,
    _terminal_text,
)


def make_installation(root: Path, *, platform: str = "posix") -> Path:
    installation = root / "ghidra"
    support = installation / "support"
    support.mkdir(parents=True)
    launcher = support / ("analyzeHeadless.bat" if platform == "nt" else "analyzeHeadless")
    launcher.write_text("launcher\n", encoding="utf-8")
    launcher.chmod(0o755)
    return installation


def make_request(
    root: Path, *, operation: HeadlessOperation = HeadlessOperation.IMPORT
) -> HeadlessRequest:
    project = root / "project"
    scripts = root / "scripts"
    project.mkdir()
    scripts.mkdir()
    script_name = (
        "ImportIl2CppTypes.java"
        if operation is HeadlessOperation.IMPORT
        else "ExportIl2Cpp.java"
    )
    (scripts / script_name).write_text(f"class {script_name[:-5]} {{}}\n", encoding="utf-8")
    binary = root / "libil2cpp.so"
    binary.write_bytes(b"ELF")
    manifest = root / "request.json"
    manifest.write_text("{}\n", encoding="utf-8")
    target = binary if operation is HeadlessOperation.IMPORT else Path("libil2cpp.so")
    return HeadlessRequest(
        project,
        "Il2Cpp_Test",
        operation,
        target,
        scripts,
        script_name,
        manifest,
    )


class HeadlessProcessTests(unittest.TestCase):
    def test_command_uses_fixed_java_script_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = GhidraHeadlessRunner(
                make_installation(root), platform="posix", environment={"PATH": "/usr/bin"}
            )
            request = make_request(root)
            command = runner.command(
                request,
                application_log=root / "application.log",
                script_log=root / "script.log",
            )

            self.assertEqual("analyzeHeadless", Path(command[0]).name)
            self.assertIn("-import", command)
            self.assertIn("ImportIl2CppTypes.java", command)
            self.assertEqual("--request", command[-2])
            self.assertEqual(str(request.manifest.resolve()), command[-1])

    def test_dry_run_previews_paths_that_do_not_exist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = GhidraHeadlessRunner(
                make_installation(root), platform="posix", environment={"PATH": "/usr/bin"}
            )
            request = HeadlessRequest(
                root / "future-project",
                "Il2Cpp_Preview",
                HeadlessOperation.IMPORT,
                root / "future-libil2cpp.so",
                root / "future-scripts",
                "ImportIl2CppTypes.java",
                root / "future-request.json",
            )

            with contextlib.redirect_stdout(io.StringIO()):
                result = runner.run(request, log=root / "ghidra.log", dry_run=True)

            self.assertIn(str((root / "future-project").resolve()), result.command)
            self.assertIn(str((root / "future-request.json").resolve()), result.command)
            self.assertFalse(result.launcher_log.exists())

    def test_unapproved_script_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = make_request(root)

            with self.assertRaisesRegex(ValueError, "not allowed"):
                HeadlessRequest(
                    request.project_directory,
                    request.project_name,
                    request.operation,
                    request.target,
                    request.script_directory,
                    "Anything.py",
                    request.manifest,
                )

    def test_script_must_match_operation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = make_request(root)

            with self.assertRaisesRegex(ValueError, "import requires"):
                HeadlessRequest(
                    request.project_directory,
                    request.project_name,
                    request.operation,
                    request.target,
                    request.script_directory,
                    "ExportIl2Cpp.java",
                    request.manifest,
                )

    def test_control_characters_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = GhidraHeadlessRunner(
                make_installation(root), platform="posix", environment={"PATH": "/usr/bin"}
            )
            request = make_request(root)
            hostile = root / "request\n-postScript.json"
            request.manifest.rename(hostile)
            request = HeadlessRequest(
                request.project_directory,
                request.project_name,
                request.operation,
                request.target,
                request.script_directory,
                request.script_name,
                hostile,
            )

            with self.assertRaisesRegex(ValueError, "control characters"):
                runner.command(
                    request,
                    application_log=root / "application.log",
                    script_log=root / "script.log",
                )

    def test_windows_batch_metacharacters_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = GhidraHeadlessRunner(
                make_installation(root, platform="nt"),
                platform="nt",
                environment={"PATH": "C:\\Windows"},
            )
            request = make_request(root)
            hostile = root / "request%PATH%.json"
            request.manifest.rename(hostile)
            request = HeadlessRequest(
                request.project_directory,
                request.project_name,
                request.operation,
                request.target,
                request.script_directory,
                request.script_name,
                hostile,
            )

            with self.assertRaisesRegex(ValueError, "unsafe Windows batch"):
                runner.command(
                    request,
                    application_log=root / "application.log",
                    script_log=root / "script.log",
                )

    def test_symlinked_manifest_is_rejected(self) -> None:
        if os.name == "nt":
            self.skipTest("symlink creation may require Windows privileges")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = GhidraHeadlessRunner(
                make_installation(root), platform="posix", environment={"PATH": "/usr/bin"}
            )
            request = make_request(root)
            target = root / "target.json"
            request.manifest.rename(target)
            request.manifest.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                runner.command(
                    request,
                    application_log=root / "application.log",
                    script_log=root / "script.log",
                )

    def test_environment_removes_java_injection_variables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            private_root = Path(directory)
            environment = _environment({
                "PATH": "/usr/bin",
                "JAVA_TOOL_OPTIONS": "-javaagent:unknown.jar",
                "BASH_ENV": "/tmp/profile",
                "LD_PRELOAD": "/tmp/library.so",
            }, private_root)

            self.assertEqual("/usr/bin", environment["PATH"])
            self.assertNotIn("JAVA_TOOL_OPTIONS", environment)
            self.assertNotIn("BASH_ENV", environment)
            self.assertNotIn("LD_PRELOAD", environment)
            self.assertEqual(str(private_root / "config"), environment["XDG_CONFIG_HOME"])

    def test_terminal_control_sequences_are_escaped(self) -> None:
        self.assertEqual("name\\u001b[31m\n", _terminal_text("name\x1b[31m\n"))

    @unittest.skipUnless(os.name == "posix", "fixture uses a POSIX executable")
    def test_runner_executes_without_a_shell_and_collects_logs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installation = make_installation(root)
            launcher = installation / "support" / "analyzeHeadless"
            launcher.write_text(
                f"#!{sys.executable}\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                "pathlib.Path(args[args.index('-log') + 1]).write_text('application\\n')\n"
                "pathlib.Path(args[args.index('-scriptlog') + 1]).write_text('script\\n')\n"
                "print('progress\\x1b[31m')\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            runner = GhidraHeadlessRunner(
                installation, platform="posix", environment={"PATH": "/usr/bin"}
            )
            visible = io.StringIO()

            with contextlib.redirect_stdout(visible):
                result = runner.run(make_request(root), log=root / "ghidra.log")

            self.assertEqual("application\n", result.application_log.read_text())
            self.assertEqual("script\n", result.script_log.read_text())
            self.assertIn("progress\\u001b[31m", visible.getvalue())
            self.assertIn("progress\x1b[31m", result.launcher_log.read_text())

    @unittest.skipUnless(os.name == "posix", "fixture uses a POSIX executable")
    def test_timeout_stops_an_idle_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installation = make_installation(root)
            launcher = installation / "support" / "analyzeHeadless"
            launcher.write_text(
                f"#!{sys.executable}\nimport time\ntime.sleep(30)\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            runner = GhidraHeadlessRunner(
                installation, platform="posix", environment={"PATH": "/usr/bin"}
            )

            with self.assertRaises(subprocess.TimeoutExpired):
                runner.run(
                    make_request(root),
                    log=root / "ghidra.log",
                    timeout_seconds=0.05,
                )

    @unittest.skipUnless(os.name == "posix", "symlink behavior differs on Windows")
    def test_symlinked_installation_root_is_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installation = make_installation(root)
            link = root / "ghidra-current"
            link.symlink_to(installation, target_is_directory=True)

            runner = GhidraHeadlessRunner(
                link, platform="posix", environment={"PATH": "/usr/bin"}
            )

            command = runner.command(
                make_request(root),
                application_log=root / "application.log",
                script_log=root / "script.log",
            )
            self.assertEqual("analyzeHeadless", Path(command[0]).name)


if __name__ == "__main__":
    unittest.main()
