from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from il2cpp_ghidrah.cli import _class_list, parser
from il2cpp_ghidrah.config import RunConfig
from il2cpp_ghidrah.generators import _cpp2il_unity_version, select_generator
from il2cpp_ghidrah.inputs import resolve_input
from il2cpp_ghidrah.installation import discover
from il2cpp_ghidrah.pipeline import _require_clean_ghidra_log
from il2cpp_ghidrah.process import run_command
from il2cpp_ghidrah.selection import prepare_diffable_selection


class CliTests(unittest.TestCase):
    def test_default_generator_is_auto(self) -> None:
        args = parser().parse_args(["run", "game.apk", "-o", "out"])
        self.assertEqual("auto", args.generator)
        self.assertEqual("turbo", args.importer)

    def test_full_and_short_options(self) -> None:
        args = parser().parse_args([
            "run", "game.apk", "-o", "out", "-g", "dumper", "-l", "inferred",
            "-s", "whitelist", "-a", "Assembly-CSharp", "-c", "A", "--classes", '["B"]',
            "-M", "global-metadata.dat", "-u", "2022.3.0f1",
        ])
        self.assertEqual("dumper", args.generator)
        self.assertEqual(["A"], args.selected_classes)
        self.assertEqual(["B"], args.classes)
        self.assertEqual("2022.3.0f1", args.unity)

    def test_json_class_list_rejects_non_strings(self) -> None:
        with self.assertRaises(Exception):
            _class_list('["A", 2]')

    def test_layout_policy_mapping(self) -> None:
        config = RunConfig(Path("input"), Path("output"), layout="authoritative")
        self.assertEqual("require-authoritative", config.turbo_policy)


class InputTests(unittest.TestCase):
    def test_nested_apk_resolution_prefers_requested_abi(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apk = root / "split.apk"
            elf = bytearray(20)
            elf[:4] = b"\x7fELF"
            elf[4] = 2
            elf[5] = 1
            elf[18:20] = (183).to_bytes(2, "little")
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("lib/arm64-v8a/libil2cpp.so", elf)
                archive.writestr("assets/bin/Data/Managed/Metadata/global-metadata.dat", b"meta")
                archive.writestr("assets/bin/Data/globalgamemanagers", b"unity")
            bundle = root / "game.apks"
            with zipfile.ZipFile(bundle, "w") as archive:
                archive.write(apk, "splits/split.apk")
            resolved = resolve_input(bundle, root / "temporary", metadata=None, assets=None, abi="arm64-v8a")
            self.assertEqual("libil2cpp.so", resolved.binary.name)
            self.assertEqual("global-metadata.dat", resolved.metadata.name)
            self.assertEqual("unity-version-data", resolved.unity_data.name)
            self.assertIsNone(resolved.assets)


class GeneratorTests(unittest.TestCase):
    def test_cpp2il_requires_explicit_unity_version(self) -> None:
        config = RunConfig(Path("game.apk"), Path("output"), generator="dumper")
        with self.assertRaisesRegex(ValueError, "No default version is guessed"):
            _cpp2il_unity_version(config)

    def test_cpp2il_uses_explicit_unity_version(self) -> None:
        config = RunConfig(
            Path("game.apk"), Path("output"), generator="dumper", unity="2021.3.16f1"
        )
        self.assertEqual("2021.3.16f1", _cpp2il_unity_version(config))

    def test_auto_falls_back_to_dumper_and_cpp2il(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dumper = root / "Il2CppDumper"
            cpp2il = root / "Cpp2IL"
            dumper.touch()
            cpp2il.touch()
            dumper.chmod(0o755)
            cpp2il.chmod(0o755)
            config = RunConfig(
                Path("input"),
                Path("output"),
                generator="auto",
                il2cpp_command=str(root / "missing-il2cpp"),
                dumper_command=str(dumper),
                cpp2il_command=str(cpp2il),
            )
            selected, selected_command, diffable_command = select_generator(config)
            self.assertEqual("dumper", selected)
            self.assertEqual(str(dumper), selected_command)
            self.assertEqual(str(cpp2il), diffable_command)


class ProcessTests(unittest.TestCase):
    def test_logged_command_output_is_also_visible(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "tool.log"
            visible = io.StringIO()
            with contextlib.redirect_stdout(visible):
                run_command(
                    [sys.executable, "-c", "print('tool progress')"],
                    log=log,
                )
            self.assertIn("tool progress", visible.getvalue())
            self.assertIn("tool progress", log.read_text(encoding="utf-8"))


class InstallationTests(unittest.TestCase):
    def test_extension_must_be_installed_inside_ghidra(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ghidra = root / "ghidra"
            (ghidra / "Ghidra").mkdir(parents=True)
            (ghidra / "Ghidra/application.properties").touch()
            with self.assertRaisesRegex(FileNotFoundError, "must be installed"):
                discover(ghidra)

    def test_cparser_scripts_are_packaged(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ghidra = Path(directory) / "ghidra"
            extension = ghidra / "Ghidra/Extensions/turboheader-ghidra-il2cpp"
            scripts = extension / "ghidra_scripts"
            native = extension / "os/linux_x86_64"
            scripts.mkdir(parents=True)
            native.mkdir(parents=True)
            (ghidra / "Ghidra/application.properties").touch()
            (scripts / "ImportIl2CppTypes.java").touch()
            (scripts / "cpp2il_ghidra_export_editable.py").touch()
            (extension / "lib").mkdir()
            (extension / "lib/turboheader-ghidra-il2cpp.jar").touch()
            (native / "libturboheader_il2cpp.so").touch()
            installation = discover(ghidra)
            self.assertTrue(
                (installation.cparser_scripts_dir / "parse_header_headless.py").is_file()
            )


class GhidraLogTests(unittest.TestCase):
    def test_script_error_is_not_hidden_by_zero_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "ghidra.log"
            log.write_text("ERROR REPORT SCRIPT ERROR: bad type\n", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "SCRIPT ERROR"):
                _require_clean_ghidra_log(log)

    def test_normal_error_word_does_not_fail_the_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "ghidra.log"
            log.write_text("INFO no ERROR conditions found\n", encoding="utf-8")
            _require_clean_ghidra_log(log)


class SelectionTests(unittest.TestCase):
    def test_whitelist_and_class_filter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "DiffableCs"
            files = [
                source / "Assembly-CSharp" / "Game" / "A.cs",
                source / "Assembly-CSharp" / "Game" / "B.cs",
                source / "Vendor" / "Game" / "A.cs",
            ]
            for path in files:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("class X {}", encoding="utf-8")
            selected = prepare_diffable_selection(
                source,
                root / "selected",
                scope="whitelist",
                assemblies=("Assembly-CSharp",),
                classes=("Game.A",),
            )
            self.assertEqual(
                ["Assembly-CSharp/Game/A.cs"],
                [path.relative_to(selected).as_posix() for path in selected.rglob("*.cs")],
            )


if __name__ == "__main__":
    unittest.main()
