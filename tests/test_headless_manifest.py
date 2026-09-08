from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from il2cpp_ghidrah.headless_manifest import ImportManifest, write_import_manifest


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


if __name__ == "__main__":
    unittest.main()
