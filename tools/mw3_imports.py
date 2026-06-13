import pefile
pe = pefile.PE(r"C:\Games\MechWarrior3\Mech3.exe", fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    dll = entry.dll.decode(errors="replace")
    if dll.lower().split(".")[0] in ("ddraw","d3dim","d3dimm","d3d8","d3d9","dsound","dinput","dinput8","winmm","glide2x","glide3x"):
        funcs = [imp.name.decode(errors="replace") if imp.name else f"ord{imp.ordinal}" for imp in entry.imports][:6]
        print(f"{dll}: {', '.join(funcs)}{' ...' if len(entry.imports)>6 else ''}")
print("--- all imported DLLs ---")
print(", ".join(sorted(e.dll.decode(errors='replace') for e in pe.DIRECTORY_ENTRY_IMPORT)))
