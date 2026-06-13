#!/usr/bin/env python3
"""Find xrefs to the faulting span function family and the globals it uses."""
import sys
import struct
import pefile
import capstone

EXE = r"C:\Games\MechWarrior3\Mech3.exe"
pe = pefile.PE(EXE)
base = pe.OPTIONAL_HEADER.ImageBase
data = pe.get_memory_mapped_image()
out = open(r"C:\tmp\mw3_xrefs_out.txt", "w", encoding="utf-8")

def p(*a):
    print(*a, file=out)

# Addresses of interest: family of span funcs and the globals
funcs = [0x56d440, 0x56d4c0, 0x56d540, 0x56d5c0, 0x56d640]
globals_ = [0x72c268, 0x72c26c, 0x72c270, 0x72c274, 0x72c278, 0x74a338, 0x5efb98]

# 1) raw dword scan for function pointers in the whole image (tables)
p("=== dword references to span functions (pointer tables / immediates) ===")
for f in funcs:
    needle = struct.pack("<I", f)
    i = 0
    while True:
        i = data.find(needle, i)
        if i < 0:
            break
        p(f"  0x{f:08x} referenced at VA 0x{base+i:08x}")
        i += 1

# 2) raw dword scan for the globals (besides inside the span funcs themselves)
p()
p("=== dword references to globals ===")
span_range = (0x56d440 - base, 0x56e000 - base)
for g in globals_:
    needle = struct.pack("<I", g)
    i = 0
    hits = []
    while True:
        i = data.find(needle, i)
        if i < 0:
            break
        if not (span_range[0] <= i < span_range[1]):
            hits.append(base + i)
        i += 1
    p(f"  0x{g:08x}: {len(hits)} refs outside span family: " + " ".join(f"0x{h:08x}" for h in hits[:40]))

# 3) find call rel32 to func starts in .text
text = None
for s in pe.sections:
    if s.Name.startswith(b".text"):
        text = s
        break
tstart = text.VirtualAddress
tdata = data[tstart:tstart + text.Misc_VirtualSize]
p()
p("=== E8 call rel32 to span funcs ===")
for f in funcs:
    for i in range(len(tdata) - 5):
        if tdata[i] == 0xE8:
            rel = struct.unpack("<i", tdata[i+1:i+5])[0]
            tgt = base + tstart + i + 5 + rel
            if tgt == f:
                p(f"  call 0x{f:08x} from VA 0x{base+tstart+i:08x}")
out.close()
print("done")
