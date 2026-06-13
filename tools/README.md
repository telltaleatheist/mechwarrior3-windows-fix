# Tools

Reverse-engineering and diagnostic scripts used to analyze the MechWarrior 3
mission-load crash. Python 3.11 with `pefile` and `capstone` (`pip install pefile capstone`).

- mw3_debug.py          - custom ctypes Win32 debugger; attaches to Mech3.exe and
                          captures the live guard-page exception stream (Exhibit C)
- mw3_disasm_clean.py   - prints the annotated disassembly of the faulting blitter (Exhibit B)
- mw3_crash_analysis.py - original fault-site analysis around Mech3.exe+0x16d4a5
- mw3_dispatch/setup/writers/xrefs/caller.py - deeper RE of the blitter dispatch tables and globals
- mw3_imports.py        - dumps Mech3.exe imports (proves graphics = ddraw.dll only)
- pm_pe.py / pm_imp.py  - PE-header / import checks (proves Pirate's Moon files were ISc-compressed)
- avi_codec.py          - reads an AVI header (proves FMVs are Indeo 5 / IV50, 640x480)
- output/               - raw capstone/xref dumps and the live debugger trace

NOTE: paths are hardcoded to C:\Games\MechWarrior3\ and C:\Games\PiratesMoon\ - adjust for your install.
