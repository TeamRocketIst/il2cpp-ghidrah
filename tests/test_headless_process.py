from __future__ import annotations

import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from il2cpp_ghidrah.headless_process import (
    GhidraHeadlessRunner,
    HeadlessOperation,
    HeadlessRequest,
    _environment,
    _terminal_text,
    _warning_color,
    require_clean_ghidra_log,
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

    def test_cparser_import_script_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            request = make_request(root)
            cparser = request.script_directory / "ImportIl2CppCParser.java"
            cparser.write_text("class ImportIl2CppCParser {}\n", encoding="utf-8")

            accepted = HeadlessRequest(
                request.project_directory,
                request.project_name,
                request.operation,
                request.target,
                request.script_directory,
                cparser.name,
                request.manifest,
            )

            self.assertEqual("ImportIl2CppCParser.java", accepted.script_name)

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

    def test_warnings_are_one_plain_line_without_logger_prefixes(self) -> None:
        for message in (
            "skipped ambiguous methods: 2; see _ambiguous_matches.txt.",
            "skipped metadata entries in ELF loader tables: 1.",
            "skipped string entries in ELF loader tables: 1.",
        ):
            with self.subTest(message=message):
                warning = "WARNING: TurboHeader " + message
                line = "INFO  ExportIl2Cpp.java> " + warning + " (GhidraScript)  \n"
                self.assertEqual(warning + "\n", _terminal_text(line))
                self.assertEqual("\x1b[33m" + warning + "\x1b[0m\n", _terminal_text(line, color=True))

    def test_warning_without_newline_does_not_gain_one(self) -> None:
        warning = "WARNING: TurboHeader skipped 2 methods."
        self.assertEqual(warning, _terminal_text(warning))
        self.assertEqual("\x1b[33m" + warning + "\x1b[0m", _terminal_text(warning, color=True))

    def test_warning_controls_are_escaped_before_colouring(self) -> None:
        warning = "WARNING: TurboHeader sample\x1b[2J\r\u202e\n"
        self.assertEqual(
            "\x1b[33mWARNING: TurboHeader sample\\u001b[2J\\u000d\\u202e\x1b[0m\n",
            _terminal_text(warning, color=True),
        )

    def test_normal_output_and_fatal_errors_are_not_reformatted(self) -> None:
        for line in ("progress\n", "ERROR REPORT SCRIPT ERROR: failed\n", "java.lang.IllegalStateException\n"):
            self.assertEqual(line, _terminal_text(line, color=True))

    def test_warning_colour_requires_a_terminal_and_respects_environment(self) -> None:
        for tty, environment, expected in (
            (True, {}, True),
            (False, {}, False),
            (True, {"NO_COLOR": "1"}, False),
            (True, {"NO_COLOR": ""}, False),
            (True, {"TERM": "dumb"}, False),
            (True, {"TERM": "xterm-256color"}, True),
        ):
            with self.subTest(tty=tty, environment=environment):
                with patch("sys.stdout.isatty", return_value=tty):
                    self.assertEqual(expected, _warning_color(environment))

    def test_warnings_do_not_hide_fatal_log_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "ghidra.log"
            log.write_text("WARNING: TurboHeader skipped 1 method.\n", encoding="utf-8")
            require_clean_ghidra_log(log)
            log.write_text(log.read_text() + "ERROR REPORT SCRIPT ERROR: failure\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "REPORT SCRIPT ERROR"):
                require_clean_ghidra_log(log)

    @unittest.skipUnless(os.name == "posix", "fixture uses a POSIX executable")
    def test_runner_colours_only_terminal_output_not_saved_logs(self) -> None:
        class Terminal(io.StringIO):
            def isatty(self) -> bool:
                return True

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            installation = make_installation(root)
            launcher = installation / "support" / "analyzeHeadless"
            line = "INFO  ExportIl2Cpp.java> WARNING: TurboHeader skipped 2 methods. (GhidraScript)"
            launcher.write_text(
                f"#!{sys.executable}\n"
                "import pathlib, sys\n"
                "args = sys.argv[1:]\n"
                f"line = {line!r}\n"
                "pathlib.Path(args[args.index('-log') + 1]).write_text(line + '\\n')\n"
                "pathlib.Path(args[args.index('-scriptlog') + 1]).write_text(line + '\\n')\n"
                "print(line)\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            runner = GhidraHeadlessRunner(installation, platform="posix", environment={"PATH": "/usr/bin"})
            visible = Terminal()
            with contextlib.redirect_stdout(visible):
                result = runner.run(make_request(root), log=root / "ghidra.log")
            self.assertEqual("\x1b[33mWARNING: TurboHeader skipped 2 methods.\x1b[0m\n", visible.getvalue())
            for path in (result.application_log, result.script_log, result.launcher_log):
                self.assertNotIn("\x1b", path.read_text())
                self.assertIn(line, path.read_text())

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
    def test_runner_can_suppress_visible_output(self) -> None:
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
                "print('hidden progress')\n",
                encoding="utf-8",
            )
            launcher.chmod(0o755)
            runner = GhidraHeadlessRunner(
                installation, platform="posix", environment={"PATH": "/usr/bin"}
            )
            visible = io.StringIO()

            with contextlib.redirect_stdout(visible):
                result = runner.run(
                    make_request(root),
                    log=root / "ghidra.log",
                    stream_output=False,
                )

            self.assertEqual("", visible.getvalue())
            self.assertIn("hidden progress", result.launcher_log.read_text())

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
