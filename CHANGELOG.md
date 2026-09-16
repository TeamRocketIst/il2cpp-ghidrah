# Changelog

## 0.2.0

- Replaced the embedded PyGhidra launcher with fixed `analyzeHeadless` Java entry points.
- Removed the installation dependency on TurboHeader's obsolete Python exporter.
- Added private typed request manifests for Ghidra import and export operations.
- Routed the TurboHeader and CParser importers through the same metadata, relocation, and export pipeline.
- Added live command output, retained logs, phase timings, and an eight-worker decompiler default.
- Added an optional `doctor --probe` check that starts Ghidra and verifies the selected importer.
- Hardened archive handling, path validation, process environments, and export verification.

This release requires TurboHeader 1.3.9 or newer.

## 0.1.5

- Final release using the PyGhidra-based export pipeline.
- Supports Python 3.9 and newer.
- Compatible with TurboHeader 1.3.8.
- Includes the legacy Python import and export scripts.

New installations should use il2cpp-ghidrah 0.2.0 with TurboHeader 1.3.10.
