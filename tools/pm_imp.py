import pefile
pe = pefile.PE(r"C:\Games\PiratesMoon\game\mech3.exe", fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
print("Imported DLLs:", ", ".join(sorted(e.dll.decode(errors="replace") for e in pe.DIRECTORY_ENTRY_IMPORT)))
