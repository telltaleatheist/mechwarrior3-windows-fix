If you're getting the instant crash the moment a mission loads, the fix is to stop using dgVoodoo. It's incompatible with MW3's software cockpit renderer. Use **DDrawCompat** instead:

1. **Swap the wrapper.** Delete dgVoodoo's files from the game folder (`DDraw.dll`, `D3DImm.dll`, `D3D8/9.dll`, `dgVoodoo.conf`) and drop in DDrawCompat's `ddraw.dll`. That alone kills the mission-load crash.
2. **Cap the framerate** (or the game runs ~5x too fast). Make a file `DDrawCompat.ini` next to the EXE containing: `FpsLimiter = flipstart(30)`
3. **If you get a "software render files not installed" video error,** import the registry value `InstallOptions=dword:00050707` under `HKLM\SOFTWARE\WOW6432Node\MicroProse\MechWarrior 3\1.0` (use `...\MechWarrior 3 EP1\1.0` for Pirate's Moon).
4. **If the intro videos fail,** register the Indeo 5 codec: `reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" /v vidc.iv50 /t REG_SZ /d ir50_32.dll /f`

Also: no Windows compatibility modes on the EXE (they break the wrapper). Works for both the base game and Pirate's Moon. Long version with the full technical breakdown of *why* dgVoodoo crashes it is in my other post.
