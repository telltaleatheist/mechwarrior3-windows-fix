#!/usr/bin/env python3
"""Analyze MechWarrior 3 crash at module offset 0x16d4a5 (read-only)."""
import sys
import pefile
import capstone

EXE = r"C:\Games\MechWarrior3\Mech3.exe"
FAULT_RVA = 0x16D4A5

sys.stdout = open(r"C:\tmp\mw3_out.txt", "w", encoding="utf-8")

pe = pefile.PE(EXE, fast_load=False)
image_base = pe.OPTIONAL_HEADER.ImageBase
fault_va = image_base + FAULT_RVA
print(f"ImageBase      : 0x{image_base:08x}")
print(f"Fault RVA      : 0x{FAULT_RVA:08x}")
print(f"Fault VA       : 0x{fault_va:08x}")

# Map RVA to section
sec = None
for s in pe.sections:
    start = s.VirtualAddress
    end = start + max(s.Misc_VirtualSize, s.SizeOfRawData)
    if start <= FAULT_RVA < end:
        sec = s
        break
if sec is None:
    print("Fault RVA not in any section!")
    sys.exit(1)

name = sec.Name.rstrip(b"\x00").decode()
file_off = sec.PointerToRawData + (FAULT_RVA - sec.VirtualAddress)
print(f"Section        : {name}  VA 0x{sec.VirtualAddress:08x}-0x{sec.VirtualAddress+sec.Misc_VirtualSize:08x}  raw 0x{sec.PointerToRawData:08x} size 0x{sec.SizeOfRawData:08x}")
print(f"File offset    : 0x{file_off:08x}")
print()
print("All sections:")
NUL_BYTE = b"\x00"
for s in pe.sections:
    sname = s.Name.rstrip(NUL_BYTE).decode()
    print(f"  {sname:8s} VA 0x{s.VirtualAddress:08x} vsize 0x{s.Misc_VirtualSize:08x} raw 0x{s.PointerToRawData:08x} rsize 0x{s.SizeOfRawData:08x} chars 0x{s.Characteristics:08x}")
print()

# Build IAT map: VA of IAT slot -> dll!name
iat = {}
if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        for imp in entry.imports:
            if imp.address:
                nm = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
                iat[imp.address] = f"{dll}!{nm}"
print(f"IAT entries: {len(iat)}")

# Get full image data so we can read strings by VA
data = pe.get_memory_mapped_image()


def read_cstr(va, maxlen=128):
    rva = va - image_base
    if rva < 0 or rva >= len(data):
        return None
    out = bytearray()
    for i in range(maxlen):
        if rva + i >= len(data):
            break
        b = data[rva + i]
        if b == 0:
            break
        out.append(b)
    if len(out) >= 3 and all(32 <= c < 127 or c in (9, 10, 13) for c in out):
        return out.decode("ascii", "replace")
    return None


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True

text_start_rva = sec.VirtualAddress
text_data = data[text_start_rva: text_start_rva + sec.Misc_VirtualSize]

# Find function start: scan backwards from fault for prologue 55 8B EC preceded
# by ret/int3/nop padding, then disassemble forward to confirm alignment.
fault_in_text = FAULT_RVA - text_start_rva


def find_func_start(pos):
    """Scan back for push ebp/mov ebp,esp or padding boundary."""
    i = pos
    candidates = []
    while i > 0 and pos - i < 0x4000:
        # 55 8B EC : push ebp / mov ebp, esp
        if text_data[i] == 0x55 and text_data[i+1] == 0x8B and text_data[i+2] == 0xEC:
            prev = text_data[i-1]
            # preceded by ret(C3/C2 xx xx), int3(CC), nop(90)
            if prev in (0xC3, 0xCC, 0x90) or (i >= 3 and text_data[i-3] == 0xC2):
                candidates.append(i)
                break
            candidates.append(i)  # weaker candidate, keep going a bit
            if len(candidates) > 4:
                break
        i -= 1
    return candidates


cands = find_func_start(fault_in_text)
print(f"Function-start candidates (RVA): {[hex(text_start_rva + c + 0) for c in cands]}")
print()

# Choose strongest candidate (first found = closest with good boundary)
func_start_rva = text_start_rva + cands[0] if cands else FAULT_RVA - 0x200


def fmt_ins(ins):
    line = f"0x{ins.address:08x}  {ins.bytes.hex():<20s} {ins.mnemonic} {ins.op_str}"
    notes = []
    # resolve indirect calls/jumps through IAT
    for op in ins.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
            target = op.mem.disp
            if target in iat:
                notes.append(f"-> {iat[target]}")
        if op.type == capstone.x86.X86_OP_IMM:
            imm = op.value.imm
            if image_base <= imm < image_base + len(data):
                s = read_cstr(imm)
                if s:
                    notes.append(f'imm -> "{s}"')
                elif imm in iat:
                    notes.append(f"imm -> IAT {iat[imm]}")
    if ins.mnemonic == "call" and ins.operands and ins.operands[0].type == capstone.x86.X86_OP_IMM:
        notes.append(f"call 0x{ins.operands[0].value.imm:08x}")
    if notes:
        line += "   ; " + " ".join(notes)
    return line


def disasm_range(start_rva, end_rva, mark_va=None):
    code = data[start_rva:end_rva]
    va = image_base + start_rva
    lines = []
    for ins in md.disasm(code, va):
        marker = " >>> " if mark_va is not None and ins.address <= mark_va < ins.address + ins.size else "     "
        lines.append(marker + fmt_ins(ins))
    return lines


print("=" * 100)
print(f"Disassembly from function start 0x{image_base+func_start_rva:08x} through fault+0x200")
print("=" * 100)
end_rva = FAULT_RVA + 0x200
for line in disasm_range(func_start_rva, end_rva, mark_va=fault_va):
    print(line)
