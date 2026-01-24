#@author sk4r
#@category Symbol
#@keybinding
#@menupath Tools.RenameFunctions
#@toolbar

# Renomme toutes les fonctions "non nommees" (ex: FUN_401000) en leur donnant un nom lisible
# Utilisation:
# ./ghidra_11.4.2_PUBLIC/support/analyzeHeadless \
# . MyProj -import ./ch18.bin -scriptPath ~/GHIDRA_SCRIPT \
# -postScript rename.py prefix=my_fn_ output=./out 

import json
from ghidra.program.model.symbol import SourceType

args = dict(
    a.split("=", 1) for a in getScriptArgs() if "=" in a
)


prefix = args.get("prefix", "sub_")
output = args.get("output", "/tmp/symbols.json")

fm = currentProgram.getFunctionManager()
base = currentProgram.getImageBase().getOffset()

symbols = []

for f in fm.getFunctions(True):
    name = f.getName()
    if name.startswith("FUN_"):
        newname = prefix + f.getEntryPoint().toString()
        f.setName(newname, SourceType.USER_DEFINED)
        name = newname

    symbols.append({
        "name": name,
        "va": f.getEntryPoint().getOffset(),
        "offset": f.getEntryPoint().getOffset() - base,
    })

with open(output, "w") as fd:
    json.dump({
        "image_base": base,
        "functions": symbols
    }, fd, indent=2)

print("[+] Exported %d symbols to %s" % (len(symbols), output))
