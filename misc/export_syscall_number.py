import sys

from lief import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

pe = PE.parse(sys.argv[1])
cs = Cs(CS_ARCH_X86, CS_MODE_32)

def detail(obj):
    ret = {}
    for key in dir(obj):
        if key[0] == '_':
            continue
        try:
            ret[key] = getattr(obj, key)
        except:
            pass

    return ret

for f in pe.exported_functions:
    if f.name[:2] != 'Zw':
        continue

    print(f.name)

    body = bytes(pe.get_content_from_virtual_address(f.address, 32))
    for op in cs.disasm(body, 0):
        print('%4x: %-12s%s' % (op.address, op.mnemonic, op.op_str))
print(dir(op))
