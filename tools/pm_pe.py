import pefile, struct
p = r"C:\Games\PiratesMoon\game\mech3.exe"
with open(p,"rb") as f: head = f.read(64)
print("first bytes:", head[:2], "MZ?" , head[:2]==b"MZ")
try:
    pe = pefile.PE(p, fast_load=True)
    print("Machine:", hex(pe.FILE_HEADER.Machine), "(0x14c=x86)")
    print("Characteristics:", hex(pe.FILE_HEADER.Characteristics))
    print("Subsystem:", pe.OPTIONAL_HEADER.Subsystem, "(2=GUI,3=console)")
    print("Magic:", hex(pe.OPTIONAL_HEADER.Magic), "(0x10b=PE32)")
    print("DLLCharacteristics:", hex(pe.OPTIONAL_HEADER.DllCharacteristics))
    print("EntryPoint:", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
    print("ImageBase:", hex(pe.OPTIONAL_HEADER.ImageBase))
    print("NumberOfSections:", pe.FILE_HEADER.NumberOfSections)
    for s in pe.sections:
        print("  section", s.Name.rstrip(b"\x00").decode(errors="replace"), "vsz", hex(s.Misc_VirtualSize), "rawsz", hex(s.SizeOfRawData))
except Exception as e:
    print("pefile error:", e)
