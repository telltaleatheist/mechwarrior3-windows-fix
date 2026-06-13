#!/usr/bin/env python3
"""Disassemble caller regions that set [0x72c278] and call the span table; find strings."""
import pefile, capstone, struct, re

EXE = r"C:\Games\MechWarrior3\Mech3.exe"
pe = pefile.PE(EXE)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
out = open(r"C:\tmp\mw3_caller_out.txt", "w", encoding="utf-8")
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

def find_func_start(va, maxback=0x1000):
    off = va - base
    i = off
    while i > 0 and off - i < maxback:
        if data[i] == 0x55 and data[i+1] == 0x8B and data[i+2] == 0xEC:
            if data[i-1] in (0xC3, 0xCC, 0x90) or data[i-3] == 0xC2:
                return base + i
        # also detect nop-padding boundary followed by non-ebp prologue
        i -= 1
    return None

def disasm(start, end, title):
    p("=" * 90)
    p(title)
    p("=" * 90)
    code = data[start-base:end-base]
    for ins in md.disasm(code, start):
        p(fmt(ins))
    p()

# ca