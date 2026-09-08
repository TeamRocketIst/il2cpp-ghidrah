from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from il2cpp_ghidrah.export_contract import SUMMARY_FIELDS, capture_export, compare_exports


def write_export(root: Path, *, matched: int = 2, body: str = "void Player__Run() {}\n") -> None:
    root.mkdir()
    values = {name: 0 for name in SUMMARY_FIELDS}
    values.update({
        "Assemblies included": 1,
        "Classes selected": 1,
        "Class files written": 1,
        "Functions scanned": 3,
        "Functions matched/exported": matched,
    })
    lines = ["Ghidra IL2CPP export summary"]
    lines.extend(f"{name}: {values[name]}" for name in SUMMARY_FIELDS)
    lines.extend(("Decompile topology: staged-java-jobs-8", "Timing total export seconds: 1.25"))
    (root / "_export_summary.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    output = root / "Assembly-CSharp" / "Game"
    output.mkdir(parents=True)
    (output / "Player.cpp").write_text(body, encoding="utf-8")


class ExportContractTests(unittest.TestCase):
    def test_equivalent_exports_ignore_timing_text(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference"
            candidate = root / "candidate"
            write_export(reference)
            write_export(candidate)
            summary = candidate / "_export_summary.txt"
            summary.write_text(
                summary.read_text(encoding="utf-8").replace("1.25", "9.75"),
                encoding="utf-8",
            )

            comparison = compare_exports(reference, candidate)

            self.assertTrue(comparison.equal)
            self.assertEqual((), comparison.differences)

    def test_changed_body_and_summary_are_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference"
            candidate = root / "candidate"
            write_export(reference)
            write_export(candidate, matched=1, body="void Player__Run() { return; }\n")

            differences = compare_exports(reference, candidate).differences

            self.assertTrue(any("Functions matched/exported" in item for item in differences))
            self.assertTrue(any("changed file:" in item for item in differences))

    def test_missing_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            reference = root / "reference"
            candidate = root / "candidate"
            write_export(reference)
            write_export(candidate)
            (candidate / "Assembly-CSharp" / "Game" / "Player.cpp").unlink()

            differences = compare_exports(reference, candidate).differences

            self.assertIn("missing file: Assembly-CSharp/Game/Player.cpp", differences)

    def test_missing_summary_field_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "export"
            write_export(root)
            summary = root / "_export_summary.txt"
            summary.write_text(
                summary.read_text(encoding="utf-8").replace(
                    "Classes selected: 1\n", ""
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "Classes selected"):
                capture_export(root)

    def test_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            export = root / "export"
            write_export(export)
            target = root / "outside.cpp"
            target.write_text("void Outside() {}\n", encoding="utf-8")
            link = export / "Assembly-CSharp" / "Game" / "Linked.cpp"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlinks are not available")

            with self.assertRaisesRegex(ValueError, "file symlink"):
                capture_export(export)


if __name__ == "__main__":
    unittest.main()
