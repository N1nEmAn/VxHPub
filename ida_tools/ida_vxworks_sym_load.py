import ida_kernwin
import ida_name
import ida_funcs
import ida_idaapi
import struct
import collections


def read_symbols(file: str):
    with open(file, 'rb') as fp:
        total_size = struct.unpack(">I", fp.read(4))[0]
        entry_count = struct.unpack(">I", fp.read(4))[0]
        entry_data = fp.read(entry_count * 8)
        string_data = fp.read(total_size - entry_count * 8)
        if len(string_data) != total_size - entry_count * 8 - 8:
            raise Exception("The file is not symbol table")

        symbol_name_dict = {}
        idx = 0
        for symbol_name in string_data.split(b"\0"):
            symbol_name_dict[idx] = symbol_name.decode()
            idx += len(symbol_name) + 1  # the terminal null

        SymbolEntry = collections.namedtuple("SymbolEntry", "type address name")
        symbol_entries = []
        for i in range(entry_count):
            t, high_bit_idx, low_bit_idx, address = struct.unpack(">BBHI", entry_data[i * 8:i * 8 + 8])
            idx = (high_bit_idx << 16) + low_bit_idx
            name = symbol_name_dict[idx]
            symbol_entries.append(SymbolEntry(t, address, name))
        return symbol_entries


def process_symbols():
    sym_file = ida_kernwin.ask_file(0, "*", "symbol table file")
    if sym_file is None:
        return

    print(f"read symbol file from {sym_file}")

    entries = read_symbols(sym_file)

    for entry in entries:
        ida_name.set_name(entry.address, entry.name, ida_name.SN_CHECK)
        if entry.type == 84 or entry.type == 116:  # "t" and "T"
            ida_funcs.add_func(entry.address)


class SymbolImporterPlugin(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL
    comment = "vxworks Symbol Importer"
    help = "Imports symbols from a custom symbol table file"
    wanted_name = "Symbol Importer"
    wanted_hotkey = "Ctrl-Shift-S"

    def init(self):
        print("Symbol Importer Plugin initialized")
        return ida_idaapi.PLUGIN_OK

    def run(self, arg):
        process_symbols()

    def term(self):
        print("Symbol Importer Plugin terminated")


def PLUGIN_ENTRY():
    return SymbolImporterPlugin()

