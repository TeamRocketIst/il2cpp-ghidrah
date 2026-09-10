// Imports IL2CPP C types with Ghidra's CParser and applies managed metadata.
// @category Data Types

import java.nio.file.Path;

import ghidra.app.script.GhidraScript;
import turboheader.il2cpp.GhidraCParserTypeImportStrategy;
import turboheader.il2cpp.HeadlessRequestReader;
import turboheader.il2cpp.Il2CppLayoutPolicy;
import turboheader.il2cpp.Il2CppMetadataImportService;

public class ImportIl2CppCParser extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("Open a program before importing IL2CPP types");
        }

        String[] args = getScriptArgs();
        if (args.length != 2 || !args[0].equals("--request")) {
            throw new IllegalArgumentException(
                    "Expected: --request <import-request.json>");
        }

        var request = HeadlessRequestReader.readImport(Path.of(args[1]));
        if (request.offsets() != null ||
                request.layoutPolicy() != HeadlessRequestReader.LayoutPolicy.ALLOW_INFERRED) {
            throw new IllegalArgumentException(
                    "Ghidra CParser requires allow-inferred layout without external offsets");
        }

        new GhidraCParserTypeImportStrategy(currentProgram, monitor, this::println)
                .importTypes(request.header(), null, currentProgram.getDefaultPointerSize(),
                        Il2CppLayoutPolicy.ALLOW_INFERRED);
        if (request.methods() != null) {
            new Il2CppMetadataImportService(currentProgram, monitor, this::println, this::printerr)
                    .importScript(request.methods());
        }
    }
}
