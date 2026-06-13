#!/usr/bin/env python3
"""Find writers of the blitter pointer globals and the format selector."""
import pefile, capstone, struct

EXE = r"C:\Games\MechWarrior3\Mech3.exe"
pe = pefile.PE(EXE)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
out = open(r"C:\tmp\mw3_writers_out.txt", "w", encoding="utf-8")
def p(*a): print(*a, file=out)

iat = {}
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode()
    for imp in entry.imports:
        if imp.address:
            nm = imp.name.decode() if imp.name else f"ord{imp.ordinal}"
            iat[imp.address] = f"{dll}!{nm}"

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True
text = pe.sections[0]
tstart = text.VirtualAddress
tdata = data[tstart:tstart+text.Misc_VirtualSize]

# globals: dest ptr, src base, palette/lut base, src stride adders
targets = {0x72c278:"DEST_PTR(esp)", 0x72c268:"SRC_BASE(ebp)", 0x72c26c:"LUT_BASE(ebx)",
           0x72c270:"ADD_X", 0x72c274:"ADD_Y", 0x5efb98:"SRC_INDEX", 0x8007d8:"PIXEL_FORMAT_SEL", 0x8007d4:"DEST_STRIDE"}

# find mov [global], reg  => opcodes a3(eax), 89 1d/0d/15/05/25/2d/35/3d ...
for g, label in targets.items():
    needle = struct.pack("<I", g)
    i = 0
    writes = []
    while True:
        i = tdata.find(needle, i)
        if i < 0: break
        va = base + tstart + i
        pre3 = tdata[max(0,i-3):i]
        # writer opcodes: a3 (mov [imm32],eax), 89 with modrm 05/0d/15/1d/25/2d/35/3d, c7 05 (mov [imm32],imm32)
        is_write = False
        if pre3[-1:] == b'\xa3':
            is_write = True; kind="mov [g],eax"
        elif len(pre3)>=2 and pre3[-2]==0x89 and (pre3[-1] & 0xC7)==0x05:
            is_write=True; kind=f"mov [g],reg(89 {pre3[-1]:02x})"
        elif len(pre3)>=2 and pre3[-2]==0xc7 and pre3[-1]==0x05:
            is_write=True; kind="mov [g],imm32"
        else:
            kind="read/other"
        if is_write:
            writes.append((va, kind))
        i += 1
    p(f"=== {label} 0x{g:08x} : {len(writes)} writes ===")
    for va, kind in writes:
        p(f"   write at 0x{va:08x}  ({kind})")
p()

# Disassemble around the first writer of 0x72c278 to see the span setup
needle = struct.pack("<I", 0x72c278)
i = 0
first_writers = []
while True:
    i = tdata.find(needle, i)
    if i < 0: break
    pre = tdata[max(0,i-2):i]
    if pre[-1:]==b'\xa3' or (len(pre)>=2 and pre[-2]==0x89 and (pre[-1]&0xc7)==0x05):
        first_writers.append(base + tstart + i - (1 if pre[-1:]==b'\xa3' else 2))
    i += 1
p(f"Writer instruction addresses for DEST_PTR: {[hex(x) for x in first_writers]}")
out.close()
print("done")
