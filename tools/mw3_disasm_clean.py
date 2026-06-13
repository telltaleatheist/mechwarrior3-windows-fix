import pefile, capstone
pe = pefile.PE(r"C:\Games\MechWarrior3\Mech3.exe", fast_load=True)
base = pe.OPTIONAL_HEADER.ImageBase
# function containing the fault is at VA 0x56d440; fault at 0x56d4a5
start_va = 0x56d440
end_va   = 0x56d4c0
rva = start_va - base
data = pe.get_data(rva, end_va - start_va)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = False
notes = {
 0x56d450: "save real ESP to a global",
 0x56d45f: "** point ESP into the destination surface **",
 0x56d46d: "ESP = surface + 2*len  (writes go downward)",
 0x56d498: "sample 8-bit source texel",
 0x56d4a5: "<<< FAULTING INSTRUCTION: write pixel to surface via PUSH (ESP)",
 0x56d4ab: "restore the real ESP",
}
print("; ---- Mech3.exe span blitter containing the crash (VA 0x56d440) ----")
for ins in md.disasm(data, start_va):
    note = notes.get(ins.address, "")
    marker = " ;  " + note if note else ""
    print(f"0x{ins.address:08x}  {ins.mnemonic:<7}{ins.op_str}{marker}")
    if ins.address >= 0x56d4ab and not note:
        pass
