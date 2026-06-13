#!/usr/bin/env python3
"""Disassemble span-setup function 0x564080 and the caller of the table [0x80085c]."""
import pefile, capstone, struct

EXE = r"C:\Games\MechWarrior3\Mech3.exe"
pe = pefile.PE(EXE)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
out = open(r"C:\tmp\mw3_setup_out.txt", "w", encoding="utf-8")
def p(*a): print(*a, file=out)

iat = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.address:
            nm = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
            iat[imp.address] = f"{dll}!{nm}"

def read_cstr(va, maxlen=160):
    rva = va - base
    if rva < 0 or rva >= len(data): return None
    o = bytearray()
    for i in range(maxlen):
        b = data[rva+i]
        if b == 0: break
        o.append(b)
    if len(o) >= 3 and all(32 <= c < 127 or c in (9,10,13) for c in o):
        return o.decode()
    return None

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

def fmt(ins):
    line = f"0x{ins.address:08x}  {ins.bytes.hex():<22s} {ins.mnemonic} {ins.op_str}"
    notes = []
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
            t = op.mem.disp
            if t in iat: notes.append(f"-> {iat[t]}")
        if op.type == capstone.x86.X86_OP_IMM:
            imm = op.value.imm
            s = read_cstr(imm)
            if s: notes.append(f'imm -> "{s}"')
    if notes: line += "   ; " + " | ".join(notes)
    return line

def disasm(start, end, title):
    p("=" * 90)
    p(title)
    p("=" * 90)
    code = data[start-base:end-base]
    for ins in md.disasm(code, start):
        p(fmt(ins))
    p()

# setup function at 0x564080 (stored in [0x800828])
disasm(0x564080, 0x5642c0, "Function 0x564080 (slot [0x800828]) - writes 0x72c278")

# find callers of indirect table slots: search for ff 15/ff d? with [0x80085c] etc.
p("=" * 90)
p("Indirect calls/jumps through table slots 0x800828-0x800890")
p("=" * 90)
text = pe.sections[0]
tstart = text.VirtualAddress
tdata = data[tstart:tstart+text.Misc_VirtualSize]
for slot in range(0x800828, 0x800894, 4):
    needle = struct.pack("<I", slot)
    i = 0
    while True:
        i = tdata.find(needle, i)
        if i < 0: break
        va = base + tstart + i
        pre = tdata[max(0,i-2):i]
        p(f"  slot 0x{slot:08x} referenced at VA 0x{va:08x} (instr bytes before: {pre.hex()})")
        i += 1
out.close()
print("done")
