from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from il2cpp_ghidrah.headless_manifest import (
    ExportManifest,
    ImportManifest,
    write_export_manifest,
    write_import_manifest,
)


class HeadlessManifestTests(unittest.TestCase):
    def test_import_manifest_contains_canonical_typed_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "il2cpp.h"
            offsets = root / "type_offsets.json"
            methods = root / "script.json"
            header.write_text("struct Il2CppObject {};\n", encoding="utf-8")
            offsets.write_text("{}\n", encoding="utf-8")
            methods.write_text("{}\n", encoding="utf-8")

            path = write_import_manifest(
                root,
                ImportManifest(header, offsets, methods, "require-external-offsets"),
            )
            document = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(1, document["schema"])
            self.assertEqual("import", document["operation"])
            self.assertEqual(str(header.resolve()), document["header"])
            self.assertEqual(str(offsets.resolve()), document["offsets"])
            self.assertEqual(str(methods.resolve()), document["methods"])
            self.assertEqual("require-external-offsets", document["layoutPolicy"])

    def test_optional_inputs_are_encoded_as_null(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "il2cpp.h"
            header.write_text("struct Il2CppObject {};\n", encoding="utf-8")

            path = write_import_manifest(
                root,
                ImportManifest(header, None, None, "allow-inferred"),
            )
            document = json.loads(path.read_text(encoding="utf-8"))

            self.assertIsNone(document["offsets"])
            self.assertIsNone(document["methods"])

    def test_invalid_layout_policy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "il2cpp.h"
            header.touch()

            with self.assertRaisesRegex(ValueError, "unsupported layout policy"):
                write_import_manifest(
                    root,
                    ImportManifest(header, None, None, "accept-anything"),
                )

    @unittest.skipUnless(os.name == "posix", "permission bits differ on Windows")
    def test_manifest_is_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "il2cpp.h"
            header.touch()

            path = write_import_manifest(
                root,
                ImportManifest(header, None, None, "allow-inferred"),
            )

            self.assertEqual(0o600, path.stat().st_mode & 0o777)

    @unittest.skipUnless(os.name == "posix", "permission bits differ on Windows")
    def test_shared_manifest_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            header = root / "il2cpp.h"
            header.touch()
            shared = root / "shared"
            shared.mkdir(mode=0o755)

            with self.assertRaisesRegex(ValueError, "must be private"):
                write_import_manifest(
                    shared,
                    ImportManifest(header, None, None, "allow-inferred"),
                )

    @unittest.skipUnless(os.name == "posix", "symlink behavior differs on Windows")
    def test_symlinked_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "header-target.h"
            target.touch()
            header = root / "il2cpp.h"
            header.symlink_to(target)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                write_import_manifest(
                    root,
                    ImportManifest(header, None, None, "allow-inferred"),
                )

    def test_export_manifest_contains_typed_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = root / "classes"
            classes.mkdir()
            rules = root / "framework-rules.txt"
            seeds = root / "noreturn.txt"
            rules.write_text("Framework.*\n", encoding="utf-8")
            seeds.write_text("00001000\n", encoding="utf-8")

            path = write_export_manifest(
                root,
                ExportManifest(classes, root / "cpp", "blacklist", rules, seeds, 4),
            )
            document = json.loads(path.read_text(encoding="utf-8"))

            self.assertEqual(1, document["schema"])
            self.assertEqual("export", document["operation"])
            self.assertEqual(str(classes.resolve()), document["classSource"])
            self.assertEqual(str((root / "cpp").resolve()), document["output"])
            self.assertEqual("blacklist", document["scope"])
            self.assertEqual(str(rules.resolve()), document["frameworkRules"])
            self.assertEqual(str(seeds.resolve()), document["noreturnSeeds"])
            self.assertEqual(4, document["decompileJobs"])

    def test_export_optional_files_are_encoded_as_null(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = root / "classes"
            classes.mkdir()

            path = write_export_manifest(
                root,
                ExportManifest(classes, root / "cpp", "all", None, None, 0),
            )
            document = json.loads(path.read_text(encoding="utf-8"))

            self.assertIsNone(document["frameworkRules"])
            self.assertIsNone(document["noreturnSeeds"])

    def test_invalid_export_scope_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = root / "classes"
            classes.mkdir()

            with self.assertRaisesRegex(ValueError, "unsupported export scope"):
                write_export_manifest(
                    root,
                    ExportManifest(classes, root / "cpp", "unknown", None, None, 4),
                )

    def test_invalid_worker_count_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = root / "classes"
            classes.mkdir()

            with self.assertRaisesRegex(ValueError, "decompile jobs"):
                write_export_manifest(
                    root,
                    ExportManifest(classes, root / "cpp", "all", None, None, 13),
                )

    @unittest.skipUnless(os.name == "posix", "symlink behavior differs on Windows")
    def test_symlinked_export_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            classes = root / "classes"
            target = root / "target"
            output = root / "cpp"
            classes.mkdir()
            target.mkdir()
            output.symlink_to(target, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                write_export_manifest(
                    root,
                    ExportManifest(classes, output, "all", None, None, 4),
                )


if __name__ == "__main__":
    unittest.main()
