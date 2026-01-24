import subprocess
import os
import lief
import json
import sys



if len(sys.argv) != 2:
    print("Usage: python ./refind_symbols.py ./prog")
    exit()

bin_name = sys.argv[1]


ghidra = "./ghidra_11.4.2_PUBLIC/support/analyzeHeadless"
script_path = os.path.expanduser("~/GHIDRA_SCRIPT")

cmd = [
    ghidra,
    ".", "MyProj",
    "-import", bin_name,
    "-scriptPath", script_path,
    "-postScript", "rename.py",
    "prefix=my_fn_",
    "output=./symbols.json",
    "-deleteProject",
]

# subprocess.run(cmd, check=True)


with open("/tmp/symbols.json") as f:
    data = json.load(f)

elf = lief.parse(bin_name)

text_section = elf.get_section(".text")
text_index = elf.get_section_idx(".text")

is_pie = elf.header.file_type == lief.ELF.Header.FILE_TYPE.DYN
for fn in data["functions"]:
    sym = lief.ELF.Symbol()
    sym.name = fn["name"]
    sym.value = fn["va"]
    if is_pie:
        # image_base d'un pie dans ghidra
        sym.value -= 0x00100000
    sym.size = 0
    sym.type = lief.ELF.Symbol.TYPE.FUNC
    sym.binding = lief.ELF.Symbol.BINDING.GLOBAL
    sym.shndx = text_index  # <-- pas SHNDEX, juste l'index
    elf.add_symtab_symbol(sym)

elf.write(bin_name + "_with_symbols")
