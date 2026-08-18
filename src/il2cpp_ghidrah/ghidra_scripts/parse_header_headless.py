# @category C-Parser
# @description Imports a raw Il2CppDumper il2cpp.h into Ghidra without requiring il2cpp_header_to_ghidra

import os
import re
import tempfile

import java.lang.Exception as JavaException
from ghidra.app.util.cparser.C import CParserUtils


# Convert C++ field inheritance into a synthetic C base field for Ghidra's parser.
INHERITANCE_RE = re.compile(r"^(\s*)struct\s+(\S+)\s*:\s*(\S+)\s*\{\s*$")


def get_program_preprocessor_args(program):
    args = []
    pointer_bits = program.getDefaultPointerSize() * 8
    args.append("-D__WORDSIZE={}".format(pointer_bits))

    if pointer_bits == 64:
        args.extend(("-D__LP64__", "-D_LP64"))

    processor = program.getLanguage().getProcessor().toString().lower()
    if "x86" in processor:
        args.extend(
            ("-D__x86_64__", "-D_AMD64_")
            if pointer_bits == 64
            else ("-D__i386__", "-D_X86_")
        )
    elif "aarch64" in processor or "aarch" in processor:
        args.append("-D__aarch64__")
    elif "arm" in processor:
        args.append("-D__arm__")
    elif "mips" in processor:
        args.append("-D__mips__")

    compiler_id = (
        program.getCompilerSpec().getCompilerSpecID().getIdAsString().lower()
    )
    if "gcc" in compiler_id:
        args.extend(("-D__GNUC__=1", "-D__STDC__=1", "-D_GNU_SOURCE=1"))
    elif "windows" in compiler_id or "visualstudio" in compiler_id:
        args.extend(("-D_MSC_VER=1900", "-DWIN32=1", "-D_WIN32=1"))
        if pointer_bits == 64:
            args.extend(("-DWIN64=1", "-D_WIN64=1"))

    return args


def get_compatibility_preamble(pointer_size):
    if pointer_size == 8:
        pointer_signed = "__int64"
        pointer_unsigned = "unsigned __int64"
    elif pointer_size == 4:
        pointer_signed = "__int32"
        pointer_unsigned = "unsigned __int32"
    else:
        raise ValueError(
            "Unsupported program pointer size: {} bytes".format(pointer_size)
        )

    return (
        "typedef unsigned __int8 uint8_t;\n"
        "typedef unsigned __int16 uint16_t;\n"
        "typedef unsigned __int32 uint32_t;\n"
        "typedef unsigned __int64 uint64_t;\n"
        "typedef __int8 int8_t;\n"
        "typedef __int16 int16_t;\n"
        "typedef __int32 int32_t;\n"
        "typedef __int64 int64_t;\n"
        "typedef {pointer_signed} intptr_t;\n"
        "typedef {pointer_signed} uintptr_t;\n"
        "typedef {pointer_unsigned} size_t;\n"
    ).format(
        pointer_signed=pointer_signed,
        pointer_unsigned=pointer_unsigned,
    )


def split_line_ending(line):
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1], line[-1:]
    return line, ""


def create_ghidra_compatible_header(source_path, pointer_size):
    source_path = os.path.abspath(source_path)
    source_directory = os.path.dirname(source_path)
    descriptor, temporary_path = tempfile.mkstemp(
        prefix="il2cpp_ghidra_",
        suffix=".h",
        dir=source_directory,
    )
    converted_count = 0

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            output.write(get_compatibility_preamble(pointer_size))
            with open(source_path, "r", encoding="utf-8", newline="") as source:
                for line_number, line in enumerate(source, 1):
                    if line_number % 100000 == 0:
                        monitor.checkCancelled()

                    body, line_ending = split_line_ending(line)
                    match = INHERITANCE_RE.match(body)
                    if match is None:
                        output.write(line)
                        continue

                    indentation, child_type, parent_type = match.groups()
                    output.write(
                        "{}struct {} {{{}".format(
                            indentation,
                            child_type,
                            line_ending,
                        )
                    )
                    output.write(
                        "{} {} super;{}".format(
                            indentation,
                            parent_type,
                            line_ending,
                        )
                    )
                    converted_count += 1
        return temporary_path, converted_count
    except Exception:
        try:
            os.remove(temporary_path)
        except OSError:
            pass
        raise


def parse_header(target_header, include_paths):
    temporary_header = None
    try:
        temporary_header, converted_count = create_ghidra_compatible_header(
            target_header,
            currentProgram.getDefaultPointerSize(),
        )
        preprocessor_args = get_program_preprocessor_args(currentProgram)
        print("[*] Target raw header: {}".format(target_header))
        print("[*] Temporary parser header: {}".format(temporary_header))
        print("[*] Program: {}".format(currentProgram.getName()))
        print("[*] Include paths: {}".format(include_paths))
        print("[*] Preprocessor flags: {}".format(preprocessor_args))
        print(
            "[*] Converted C++ inheritance declarations: {}".format(
                converted_count
            )
        )

        CParserUtils.parseHeaderFiles(
            [],
            [temporary_header],
            include_paths,
            preprocessor_args,
            currentProgram.getDataTypeManager(),
            monitor,
        )
        print("[+] Parsing successfully completed; data types were added to the program.")
    except JavaException as error:
        print(
            "[-] Java exception during header parsing: {}".format(
                error.getMessage() or str(error)
            )
        )
        raise
    except Exception as error:
        print("[-] Python exception during header parsing: {}".format(error))
        raise
    finally:
        if temporary_header is not None and os.path.exists(temporary_header):
            try:
                os.remove(temporary_header)
                print("[*] Removed temporary parser header.")
            except OSError as error:
                print(
                    "[!] Unable to remove temporary parser header {}: {}".format(
                        temporary_header,
                        error,
                    )
                )


def run():
    script_args = list(getScriptArgs())
    if not script_args:
        raise ValueError(
            "No header supplied. Usage: -preScript parse_header_headless.py "
            "/path/to/il2cpp.h [/optional/include/path ...]"
        )

    target_header = os.path.abspath(script_args[0])
    if not os.path.isfile(target_header):
        raise IOError("Header file does not exist: {}".format(target_header))

    include_paths = [os.path.dirname(target_header)]
    for include_path in script_args[1:]:
        absolute_path = os.path.abspath(include_path)
        if not os.path.isdir(absolute_path):
            raise IOError("Include directory does not exist: {}".format(absolute_path))
        if absolute_path not in include_paths:
            include_paths.append(absolute_path)

    parse_header(target_header, include_paths)


if __name__ == "__main__":
    run()
