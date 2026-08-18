import json
import string

import ghidra
from ghidra.program.model.symbol import SourceType


PROCESS_FIELDS = {
    "ScriptString",
    "ScriptMetadata",
    "ScriptMetadataMethod",
}

base_address = currentProgram.getImageBase()
user_defined = SourceType.USER_DEFINED


def get_address(offset):
    return base_address.add(offset)


def set_name(address, name):
    createLabel(address, name.replace(" ", "-"), True, user_defined)


def escape_label_text(value):
    escaped = []
    for character in value:
        if character == "\n":
            escaped.append("\\n")
        elif character == "\t":
            escaped.append("\\t")
        elif character == "\r":
            escaped.append("\\r")
        elif character in string.printable and character not in string.whitespace:
            escaped.append(character)
        else:
            escaped.append("\\x{:02x}".format(ord(character)))
    return "".join(escaped).replace(" ", "\\x20")


def rename_string_pointer(address, value):
    name = "s_{}_{}".format(value[:1950] + "..." if len(value) >= 2000 else value, address)
    symbol_table = currentProgram.getSymbolTable()
    symbol = symbol_table.getPrimarySymbol(address)
    try:
        if symbol is None:
            symbol_table.createLabel(address, name, user_defined)
        else:
            symbol.setName(name, user_defined)
    except ghidra.util.exception.DuplicateNameException:
        print("Duplicate string label at {}: {}".format(address, name))


script_args = getScriptArgs()
if not script_args:
    raise ValueError("Missing script.json path")

with open(script_args[0], "r", encoding="utf-8") as input_file:
    data = json.load(input_file)

if "ScriptString" in data and "ScriptString" in PROCESS_FIELDS:
    script_strings = data["ScriptString"]
    monitor.initialize(len(script_strings))
    monitor.setMessage("Strings")
    for index, script_string in enumerate(script_strings, 1):
        address = get_address(script_string["Address"])
        value = script_string["Value"]
        createLabel(address, "StringLiteral_{}".format(index), True, user_defined)
        setEOLComment(address, value)
        rename_string_pointer(address, escape_label_text(value))
        monitor.incrementProgress(1)

if "ScriptMetadata" in data and "ScriptMetadata" in PROCESS_FIELDS:
    script_metadata = data["ScriptMetadata"]
    monitor.initialize(len(script_metadata))
    monitor.setMessage("Metadata")
    for item in script_metadata:
        address = get_address(item["Address"])
        name = item["Name"]
        set_name(address, name)
        setEOLComment(address, name)
        monitor.incrementProgress(1)

if "ScriptMetadataMethod" in data and "ScriptMetadataMethod" in PROCESS_FIELDS:
    metadata_methods = data["ScriptMetadataMethod"]
    monitor.initialize(len(metadata_methods))
    monitor.setMessage("Metadata Methods")
    for method in metadata_methods:
        address = get_address(method["Address"])
        name = method["Name"]
        set_name(address, name)
        setEOLComment(address, name)
        monitor.incrementProgress(1)

print("Script finished!")
