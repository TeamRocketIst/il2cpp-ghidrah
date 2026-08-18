# @author
# @category Il2Cpp
# @keybinding
# @menupath
# @toolbar
# @runtime PyGhidra

import json
import re
from collections import Counter, defaultdict

from java.lang import Long
from java.util import ArrayList
from ghidra.app.util.cparser.C import CParserUtils, ParseException
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.util import CodeUnitInsertionException
from ghidra.program.model.data import (
    AbstractIntegerDataType,
    CategoryPath,
    DataTypeConflictHandler,
    TypedefDataType,
)
from turboheader.il2cpp import Il2CppProgramFacts

processFields = [
    "ScriptMethod",
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
    "Addresses",
]

functionManager = currentProgram.getFunctionManager()
baseAddress = currentProgram.getImageBase()
dtm = currentProgram.getDataTypeManager()
USER_DEFINED = SourceType.USER_DEFINED

MAX_SIGNATURE_FAILURE_SAMPLES = 25
signature_stats = Counter()
signature_failure_causes = Counter()
signature_failure_samples = defaultdict(list)

METHODINFO_PARAM_RE = re.compile(
    r"^(?:const\s+)?(?:struct\s+)?MethodInfo(?:_[A-Fa-f0-9]+)?\s*\*\s*method$"
)

C_KEYWORD_PARAMETER_BASES = frozenset((
    "alignas",
    "alignof",
    "asm",
    "atomic",
    "auto",
    "bool",
    "break",
    "case",
    "char",
    "class",
    "complex",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "generic",
    "goto",
    "if",
    "imaginary",
    "inline",
    "int",
    "long",
    "noreturn",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "static_assert",
    "struct",
    "switch",
    "thread_local",
    "typedef",
    "typeof",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
))

FUNCTION_POINTER_PARAMETER_NAME_RE = re.compile(
    r"(\(\s*[*&]\s*)([A-Za-z_][A-Za-z0-9_]*)(\s*\))"
)

TRAILING_PARAMETER_NAME_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)(\s*(?:\[[^\]]*\]\s*)*)$"
)


def sanitize_symbol(symbol_name):
    replacements = {
        "<": "_",
        ">": "",
        ", ": "_",
        ",": "_",
        " ": "_",
    }

    for old_char, new_char in replacements.items():
        symbol_name = symbol_name.replace(old_char, new_char)

    return symbol_name


def set_name(addr, name):
    try:
        name = name.replace(" ", "-")
        name = sanitize_symbol(name) + "___" + str(addr)
        createLabel(addr, name, True, USER_DEFINED)
    except Exception as e:
        print("set_name() Failed at {}: {}".format(addr, e))


def get_addr(addr):
    return baseAddress.add(addr)


def set_type(addr, type_str):
    newType = type_str.replace("*", " *").replace("  ", " ").strip()
    dataTypes = getDataTypes(newType)
    addrType = None

    if len(dataTypes) == 0:
        if newType.endswith(" *"):
            baseType = newType[:-2]
            dataTypes = getDataTypes(baseType)
            if len(dataTypes) == 1:
                pointerType = dtm.getPointer(dataTypes[0])
                addrType = dtm.addDataType(pointerType, None)
    elif len(dataTypes) > 1:
        print("Conflicting data types found for type {} (parsed as '{}')".format(type_str, newType))
        return
    else:
        addrType = dataTypes[0]

    if addrType is None:
        print("Could not identify type {} (parsed as '{}')".format(type_str, newType))
    else:
        try:
            createData(addr, addrType)
        except CodeUnitInsertionException:
            print("Warning: unable to set type at {} (CodeUnitInsertionException)".format(addr))
        except Exception as e:
            print("Warning: unable to set type at {}: {}".format(addr, e))


def make_function(start):
    func = getFunctionAt(start)
    if func is None:
        try:
            createFunction(start, None)
        except Exception as e:
            print("Warning: Unable to create function at {}: {}".format(start, e))


def _integer_type(is_signed, size):
    if is_signed:
        return AbstractIntegerDataType.getSignedDataType(size, dtm)
    return AbstractIntegerDataType.getUnsignedDataType(size, dtm)


def _has_named_datatype(name):
    try:
        for data_type in getDataTypes(name):
            if data_type.getName() == name:
                return True
    except Exception:
        pass
    return False


def register_c_integer_aliases():
    pointer_size = currentProgram.getDefaultPointerSize()
    aliases = (
        ("int8_t", True, 1),
        ("uint8_t", False, 1),
        ("int16_t", True, 2),
        ("uint16_t", False, 2),
        ("int32_t", True, 4),
        ("uint32_t", False, 4),
        ("int64_t", True, 8),
        ("uint64_t", False, 8),
        ("intptr_t", True, pointer_size),
        ("uintptr_t", False, pointer_size),
        ("size_t", False, pointer_size),
        ("ssize_t", True, pointer_size),
        ("ptrdiff_t", True, pointer_size),
        ("il2cpp_array_size_t", False, pointer_size),
        ("il2cpp_array_lower_bound_t", True, 4),
    )

    added = 0
    existing = 0
    for name, is_signed, size in aliases:
        if _has_named_datatype(name):
            existing += 1
            continue

        base_type = _integer_type(is_signed, size)
        typedef = TypedefDataType(CategoryPath("/"), name, base_type, dtm)
        dtm.addDataType(typedef, DataTypeConflictHandler.KEEP_HANDLER)
        added += 1

    print("[*] C aliases ready: {} added, {} already present".format(added, existing))


def split_top_level_arguments(text):
    if not text.strip():
        return []

    result = []
    start = 0
    parentheses = 0
    brackets = 0

    for index, char in enumerate(text):
        if char == "(":
            parentheses += 1
        elif char == ")":
            parentheses -= 1
        elif char == "[":
            brackets += 1
        elif char == "]":
            brackets -= 1
        elif char == "," and parentheses == 0 and brackets == 0:
            result.append(text[start:index].strip())
            start = index + 1

    result.append(text[start:].strip())
    return result


def remove_hidden_methodinfo(signature):
    signature = signature.strip()
    if signature.endswith(";"):
        signature = signature[:-1].rstrip()

    close_index = signature.rfind(")")
    if close_index < 0:
        return signature

    depth = 0
    open_index = None
    for index in range(close_index, -1, -1):
        char = signature[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                open_index = index
                break

    if open_index is None:
        return signature

    arguments = split_top_level_arguments(signature[open_index + 1:close_index])
    if not arguments or not METHODINFO_PARAM_RE.fullmatch(arguments[-1].strip()):
        return signature

    arguments = arguments[:-1]
    replacement = ", ".join(arguments) if arguments else "void"
    return signature[:open_index + 1] + replacement + signature[close_index:]


def is_keyword_shaped_parameter_name(name):
    if not name or not name.startswith("_"):
        return False

    base_name = name.lstrip("_").lower()
    return base_name in C_KEYWORD_PARAMETER_BASES


def repaired_parameter_name(name):
    return "{}_arg".format(name)


def sanitize_one_parameter_declaration(argument):
    stripped = argument.strip()
    if not stripped or stripped == "void" or stripped == "...":
        return argument, 0

    function_pointer_match = FUNCTION_POINTER_PARAMETER_NAME_RE.search(argument)
    if function_pointer_match is not None:
        name = function_pointer_match.group(2)
        if is_keyword_shaped_parameter_name(name):
            replacement = (
                function_pointer_match.group(1)
                + repaired_parameter_name(name)
                + function_pointer_match.group(3)
            )
            return (
                argument[:function_pointer_match.start()]
                + replacement
                + argument[function_pointer_match.end():],
                1,
            )

    trailing_match = TRAILING_PARAMETER_NAME_RE.search(argument)
    if trailing_match is None:
        return argument, 0

    name = trailing_match.group(1)
    if not is_keyword_shaped_parameter_name(name):
        return argument, 0

    if not argument[:trailing_match.start(1)].strip():
        return argument, 0

    replacement = repaired_parameter_name(name) + trailing_match.group(2)
    return (
        argument[:trailing_match.start(1)]
        + replacement
        + argument[trailing_match.end():],
        1,
    )


def sanitize_signature_parameter_names(signature):
    close_index = signature.rfind(")")
    if close_index < 0:
        return signature

    depth = 0
    open_index = None
    for index in range(close_index, -1, -1):
        char = signature[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                open_index = index
                break

    if open_index is None:
        return signature

    arguments = split_top_level_arguments(
        signature[open_index + 1:close_index]
    )

    if not arguments:
        return signature

    repaired_arguments = []
    repaired_count = 0

    for argument in arguments:
        repaired_argument, count = sanitize_one_parameter_declaration(argument)
        repaired_arguments.append(repaired_argument)
        repaired_count += count

    if repaired_count == 0:
        return signature

    signature_stats["reserved_parameter_names_repaired"] += repaired_count

    return (
        signature[:open_index + 1]
        + ", ".join(repaired_arguments)
        + signature[close_index:]
    )


def make_unique_parameter_names(type_sig):
    args = type_sig.getArguments()
    used_names = set()
    next_suffix = Counter()
    modified = False

    for index, arg in enumerate(args):
        name = arg.getName()
        if not name:
            name = "param_{}".format(index + 1)

        if name not in used_names:
            used_names.add(name)
            next_suffix[name] = 1
            if arg.getName() != name:
                arg.setName(name)
                modified = True
            continue

        suffix = next_suffix[name]
        candidate = "{}_{}".format(name, suffix)
        while candidate in used_names:
            suffix += 1
            candidate = "{}_{}".format(name, suffix)

        next_suffix[name] = suffix + 1
        used_names.add(candidate)
        arg.setName(candidate)
        modified = True
        signature_stats["duplicate_names_repaired"] += 1

    if modified:
        type_sig.setArguments(args)


def record_signature_failure(name, addr, signature, error):
    message = str(error).strip() or error.__class__.__name__
    first_line = message.splitlines()[0]
    signature_failure_causes[first_line] += 1

    if sum(len(samples) for samples in signature_failure_samples.values()) < MAX_SIGNATURE_FAILURE_SAMPLES:
        signature_failure_samples[first_line].append(
            (name, str(addr), signature, message)
        )


def set_sig(addr, name, signature):
    signature_stats["total"] += 1
    signature = remove_hidden_methodinfo(signature)
    signature = sanitize_signature_parameter_names(signature)

    try:
        type_sig = CParserUtils.parseSignature(None, currentProgram, signature, False)
    except ParseException as error:
        signature_stats["parse_failed"] += 1
        record_signature_failure(name, addr, signature, error)
        return False
    except Exception as error:
        signature_stats["unexpected_parse_failed"] += 1
        record_signature_failure(name, addr, signature, error)
        return False

    try:
        make_unique_parameter_names(type_sig)
        type_sig.setName(sanitize_symbol(name))

        default_cc = (
            currentProgram
            .getCompilerSpec()
            .getDefaultCallingConvention()
        )

        if default_cc is not None:
            type_sig.setCallingConvention(default_cc.getName())

        command = ApplyFunctionSignatureCmd(
            addr,
            type_sig,
            USER_DEFINED,
            False,
            True,
        )
        applied = command.applyTo(currentProgram, monitor)
        if not applied:
            signature_stats["apply_failed"] += 1
            status = command.getStatusMsg()
            record_signature_failure(
                name,
                addr,
                signature,
                RuntimeError(status or "ApplyFunctionSignatureCmd returned false"),
            )
            return False

        signature_stats["applied"] += 1
        return True
    except Exception as error:
        signature_stats["apply_failed"] += 1
        record_signature_failure(name, addr, signature, error)
        return False


def print_signature_summary():
    print("\n[*] Signature import summary")
    print("    total                    : {}".format(signature_stats["total"]))
    print("    applied                  : {}".format(signature_stats["applied"]))
    print("    duplicate names repaired: {}".format(signature_stats["duplicate_names_repaired"]))
    print("    reserved names repaired : {}".format(signature_stats["reserved_parameter_names_repaired"]))
    print("    parse failed             : {}".format(signature_stats["parse_failed"]))
    print("    unexpected parse failed  : {}".format(signature_stats["unexpected_parse_failed"]))
    print("    apply failed             : {}".format(signature_stats["apply_failed"]))

    if not signature_failure_causes:
        return

    print("\n[!] Top signature failure causes")
    for cause, count in signature_failure_causes.most_common(10):
        print("    {:>7}  {}".format(count, cause))

    print("\n[!] Bounded signature failure samples ({})".format(
        sum(len(samples) for samples in signature_failure_samples.values())
    ))
    shown = 0
    for cause, samples in signature_failure_samples.items():
        for name, addr, signature, message in samples:
            shown += 1
            print("\n    Sample {}".format(shown))
            print("      function : {}".format(name))
            print("      address  : {}".format(addr))
            print("      signature: {}".format(signature))
            print("      parser   : {}".format(message))


def register_managed_method_facts(script_methods):
    method_offsets = ArrayList(len(script_methods))
    runtime_metadata_probe_offsets = ArrayList()

    for index, method in enumerate(script_methods):
        address = method.get("Address")
        name = method.get("Name")
        if isinstance(address, bool) or not isinstance(address, int) or address < 0:
            raise ValueError("invalid ScriptMethod address at index {}".format(index))
        if not isinstance(name, str):
            raise ValueError("invalid ScriptMethod name at index {}".format(index))

        boxed_address = Long.valueOf(address)
        method_offsets.add(boxed_address)
        if name == "System.Exception$$get_Message":
            runtime_metadata_probe_offsets.add(boxed_address)

    stats = Il2CppProgramFacts.replaceManagedMethodOffsets(
        currentProgram,
        method_offsets,
        runtime_metadata_probe_offsets,
    )
    print(
        "[*] IL2CPP program facts: {} method entries, {} unique executable methods, "
        "{} runtime metadata probes".format(
            stats.methodEntries(),
            stats.managedMethods(),
            stats.runtimeMetadataProbes(),
        )
    )


args = getScriptArgs()

if len(args) < 1:
    print("[-] Missing script.json path")
    exit(-1)

path = args[0]
print("[*] Loading: {}".format(path))

with open(path, "r", encoding="utf-8") as json_file:
    data = json.load(json_file)

register_c_integer_aliases()

if "ScriptMethod" in data and "ScriptMethod" in processFields:
    scriptMethods = data["ScriptMethod"]
    register_managed_method_facts(scriptMethods)
    monitor.initialize(len(scriptMethods))
    monitor.setMessage("Methods")
    for scriptMethod in scriptMethods:
        addr = get_addr(scriptMethod["Address"])
        name = scriptMethod["Name"]
        set_name(addr, name)
        monitor.incrementProgress(1)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in processFields:
    scriptMetadataMethods = data["ScriptMetadataMethod"]
    monitor.initialize(len(scriptMetadataMethods))
    monitor.setMessage("Metadata Methods")
    for scriptMetadataMethod in scriptMetadataMethods:
        addr = get_addr(scriptMetadataMethod["Address"])
        name = scriptMetadataMethod["Name"]
        set_name(addr, name)
        setEOLComment(addr, name)
        monitor.incrementProgress(1)

if "Addresses" in data and "Addresses" in processFields:
    addresses = data["Addresses"]
    monitor.initialize(len(addresses))
    monitor.setMessage("Addresses")
    for index in range(len(addresses) - 1):
        start = get_addr(addresses[index])
        make_function(start)
        monitor.incrementProgress(1)

if "ScriptMethod" in data and "ScriptMethod" in processFields:
    scriptMethods = data["ScriptMethod"]
    monitor.initialize(len(scriptMethods))
    monitor.setMessage("Applying IL2CPP method signatures")
    for scriptMethod in scriptMethods:
        addr = get_addr(scriptMethod["Address"])
        signature = scriptMethod.get("Signature", "")
        name = scriptMethod["Name"]
        if signature:
            set_sig(addr, name, signature)
        else:
            signature_stats["total"] += 1
            signature_stats["parse_failed"] += 1
            record_signature_failure(name, addr, "", ValueError("empty signature"))
        monitor.incrementProgress(1)

print_signature_summary()
print("Script finished!")
