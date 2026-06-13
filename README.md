# MechWarrior 3 & Pirate's Moon on Windows 10/11 — Technical Breakdown

A reproducible analysis of why *MechWarrior 3* (1999) and its *Pirate's Moon* expansion fail on modern Windows, and the minimal set of fixes that make them run correctly. The headline finding is that the long-standing "crashes the instant a mission loads" failure is caused by the popular DirectDraw wrapper **dgVoodoo2**, and is eliminated by switching to **DDrawCompat**.

## Target / environment

- **Game:** MechWarrior 3 v1.2 (Zipper Interactive / MicroProse / Hasbro Interactive, 1999) and the standalone *Pirate's Moon* expansion.
- **Binary:** 32-bit x86 PE, image base `0x00400000`. Graphics via **DirectDraw** (`DirectDrawCreate`); 3D via DirectDraw's `IDirect3D` immediate-mode interface. The executable statically imports only `DDRAW.dll` for graphics — no separate Direct3D DLL.
- **OS tested:** Windows 11 (build 10.0.26100), 64-bit. Applies to Windows 10/11 generally.

---

## Issue 1 — Hard crash at mission start (the primary problem)

### Symptom
A deterministic crash the instant a mission's cockpit/HUD begins compositing. Menus and the mech lab work; the moment gameplay rendering starts, the process dies. Windows Error Reporting reports:

- `Mech3.exe`, `STATUS_GUARD_PAGE_VIOLATION (0x80000001)` at module offset **`+0x16d4a5`**, followed by
- a secondary `STATUS_ACCESS_VIOLATION (0xc0000005)` with a faulting/return address of **`0x424a424a`** — ASCII `"JBJB"`, i.e. *pixel data*.

### Root cause
The code at `+0x16d4a5` is a software, affine texture-mapped **span blitter** that uses a 1990s speed trick: it repurposes the CPU **stack pointer (ESP)** as the destination pixel write pointer and emits pixels with `push` instructions.

```asm
mov  [saved_esp], esp          ; stash the real stack pointer
mov  esp, [dest_surface_ptr]   ; point ESP into the render surface
add  esp, edi                  ; ESP = end of span (writes go downward)
loop:
  mov   al, [ebp+esi]          ; sample 8-bit source texel
  push  word [ebx+eax*2]       ; <-- FAULTS: write palette[texel] via ESP
  jne   loop
mov  esp, [saved_esp]          ; restore the real stack pointer
```

**dgVoodoo2** emulates video memory in system RAM and marks surface pages with the `PAGE_GUARD` attribute to perform dirty-tracking (so it knows which regions to re-upload to the GPU). Under normal rendering, every first write to a guarded page raises a guard-page exception, dgVoodoo's in-process handler clears the guard bit, records the page as dirty, and resumes. This is benign and happens thousands of times per frame.

The fatal case is this blitter. When a guard-page fault fires **while ESP points into the surface**, exception delivery itself fails: dispatching an exception requires pushing a context/exception frame onto the stack, but the stack pointer is aimed at the framebuffer, so the dispatch writes into surface memory and/or re-faults on the bogus stack. No in-process handler — including dgVoodoo's own — can run, and the process is terminated.

This mechanism is **inferred from the fault signature and the disassembly, not single-stepped** (see *Evidence* below). The chain rests on three observations: (1) the instruction at `+0x16d4a5` is a *write* through ESP, and the same function sets `ESP := surface pointer` a few instructions earlier; (2) WER records a guard-page **write** fault at exactly that instruction; (3) control flow then transfers to the unmapped address `0x424a424a` — a repeating printable byte pattern (ASCII `"JBJB"`) **consistent with** the call stack having been overwritten by surface/texel data, i.e. a `ret`/dispatch consuming pixel bytes as a code address. The `0x424a424a` value is not proven to be a specific palette entry; it is the corrupted control-flow target WER recorded, and its byte pattern is what one would expect if the "stack" were image data.

dgVoodoo's `FastVideoMemoryAccess = true` (intended to hand out unguarded memory) does **not** resolve this for the surface type MW3 uses.

### Evidence

- **Raw OS crash records:** [`tools/output/wer-crash-records.txt`](tools/output/wer-crash-records.txt) — the guard-page fault at `Mech3.exe+0x16d4a5` (`0x80000001`) and the secondary `0x424a424a` access violation, straight from the Windows Application event log.
- **Annotated disassembly** of the faulting routine: [`docs/crash-artifacts.md`](docs/crash-artifacts.md) (Exhibit B), regenerable with [`tools/mw3_disasm_clean.py`](tools/mw3_disasm_clean.py) — shows `mov esp, [surface]` preceding the faulting `push`.
- **Live debugger trace:** [`tools/output/live-debugger-trace.txt`](tools/output/live-debugger-trace.txt) — 157 first-chance guard-page faults confirming dgVoodoo guard-protects the surface and the game writes to it continuously. Note: this run executes the game *under* a debugger, which absorbs the guard-page faults out-of-process, so it demonstrates the guard-page mechanism but does **not** itself reach the fatal dispatch. The fatal path is established by the disassembly + WER signature above, not by this trace.

### Fix
Replace dgVoodoo2 with **DDrawCompat** (narzoul). DDrawCompat wraps the *real* Windows DirectDraw (still present and functional on Windows 10/11) and does **not** use guard-page dirty-tracking, so the ESP-as-framebuffer writes simply succeed and the crash mechanism cannot occur. Because MW3 imports only `ddraw.dll` for graphics, DDrawCompat's single `ddraw.dll` is sufficient — no Direct3D wrapper DLLs are needed. (dgVoodoo's `D3DImm.dll` / `D3D8.dll` / `D3D9.dll` should be removed.)

### Diagnostic method (for reproducibility)
1. WER provided the deterministic faulting offset.
2. The function at `+0x16d4a5` was disassembled (pefile + capstone) to identify the ESP-hijack blitter.
3. A purpose-built Win32 debugger (Python `ctypes`, `DEBUG_ONLY_THIS_PROCESS` + `Wow64GetThreadContext`) attached to the game and captured the live exception stream, confirming the guard-page mechanism — hundreds of first-chance guard-page faults on dgVoodoo's surface memory (sibling blitters at `+0x177ab7`, `+0x179809`, where ESP is still a valid stack and the faults are survivable). Because a debugger absorbs these faults out-of-process, the run does not reach the fatal dispatch; the fatal path is established by combining the disassembly (Step 2) with the WER fault signature (Step 1), not by single-stepping the crash.

---

## Issue 2 — FMV videos are mandatory (crash if missing or invalid)

**MechWarrior 3 has no graceful fallback for missing or corrupt full-motion video.** This is a hard requirement, not cosmetic:

- **Absent video files** → a fatal in-engine "Video Error" dialog at scripted playback points.
- **Present but invalid video files** → an `AVIFIL32.dll` access violation (`0xc0000005`) when the engine attempts to decode them, e.g. the campaign cutscene reached from the post-mission **salvage → continue** transition.

The common real-world trap: many ripped or partially-extracted distributions leave the FMVs as **InstallShield-compressed stubs**. These files have the byte signature `ISc(` rather than the AVI `RIFF` magic; the engine treats them as AVIs, hands them to the AVI subsystem, and crashes. (Several "RIP" releases also strip the videos entirely.)

**Fix:** ensure the genuine, decompressed video files are installed (copied from the retail CD/ISO `VIDEO\` directory). The MW3 FMVs are **Indeo 5 (`IV50`), 640×480**, so the Indeo 5 codec must also be registered (see Issue 4). Verify each file begins with `RIFF`, not `ISc(`. **Do not delete the videos to "save space" — the game depends on them.**

---

## Issue 3 — Game runs far too fast (frame-rate-coupled clock)

MW3's simulation clock is tied to the render loop. Uncapped on modern hardware it runs several times too fast (menus, animations, and weapon/heat timing all wrong). DDrawCompat resolves it with a frame limiter — `DDrawCompat.ini`:

```
FpsLimiter = flipstart(30)
```

30 FPS matches the era-intended pacing; `flipstart` is the high-compatibility limiter method for fullscreen page-flipping applications.

---

## Issue 4 — "Software render files component was not installed" error

A `Video Error` dialog reading *"rendering via the gamez engine is not supported because the software render files component was not installed during setup"* indicates the `InstallOptions` registry value is missing/incorrect. As a 32-bit application on 64-bit Windows, MW3 reads from the `WOW6432Node` view:

```
[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\MicroProse\MechWarrior 3\1.0]
"InstallPath"="C:\\Games\\MechWarrior3\\"
"Version"="1.2"
"InstallOptions"=dword:00050707
```

*Pirate's Moon* uses a separate key, `...\MicroProse\MechWarrior 3 EP1\1.0`, with the same `InstallOptions=dword:00050707`.

---

## Issue 5 — Grainy / low-quality graphics (software rasterizer)

By default the in-game **Graphics/Audio Options → VIDEO DEVICE** is set to **"Software Render"** at **320×240**, producing a heavily dithered, unfiltered, low-resolution image (the registry shows `HWCardDev = 0xFFFFFFFF`, i.e. no 3D device selected). The zoomed sniper reticule appears sharper only because its narrow field of view yields more detail per pixel.

**Fix (in-game):** set **VIDEO DEVICE** to the hardware **Direct3D HAL** device that DDrawCompat exposes, raise **RESOLUTION** (e.g. 1024×768), and enable Shadows/Lighting (disabled in software mode). The high-resolution targeting-reticule overflow crash of the original release is mitigated by the community timing/bounds patch (below), making higher resolutions safe.

---

## Issue 6 — Indeo 5 video codec not registered

Modern Windows does not register the Indeo 5 decoder by default. Register it (the DLL ships with the game; copy to `SysWOW64` if absent):

```
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" /v vidc.iv50 /t REG_SZ /d ir50_32.dll /f
```

---

## Additional notes

- **No Windows compatibility-mode shims** on the game EXE (Win95/98/XP modes break DirectDraw wrappers). The only useful flag is **High-DPI scaling override = Application**, which corrects mouse coordinate mapping when a low render resolution is scaled to a high-DPI desktop.
- **Community no-CD / timing patch:** running through the community "zipfixup" wrapper (which patches `GetTickCount` timing inaccuracies and adds target-box bounds checking) is recommended for the base game. It does not recognize the *Pirate's Moon* executable, but the DDrawCompat frame cap covers speed there.
- **Runtime DLLs:** the base-game uses `MSVCP50.dll` (VC++ 5.0) while *Pirate's Moon* uses `MSVCP60.dll`; both use `MFC42.dll` and `MSVCRT.dll`. `MFC42`, `MSVCP60`, and `MSVCRT` are generally present in `SysWOW64` on modern Windows, but **`MSVCP50.dll` (VC++ 5.0) frequently is not** — the retail base-game install ships it in the game folder, so stripped/RIP copies that omit it will fail to launch until `MSVCP50.dll` is dropped into the game directory. (This is the missing-DLL symptom older guides report.)
- **Pirate's Moon** is the same engine and requires the identical recipe (DDrawCompat + frame cap + Indeo codec + valid videos) plus its own `EP1` registry key.

---

## Summary table

| Symptom | Root cause | Fix |
|---|---|---|
| Crash the instant a mission loads | dgVoodoo2 guard-page dirty-tracking vs. MW3's ESP-as-framebuffer span blitter; exception undeliverable on a hijacked stack | Use **DDrawCompat** (no guard-page tracking) instead of dgVoodoo |
| Crash at cutscenes / salvage→continue, or "Video Error" | Missing or InstallShield-compressed (`ISc(`) FMV files; **videos are mandatory** | Install genuine decompressed `RIFF`/Indeo-5 videos from the CD/ISO |
| Game runs several times too fast | Frame-rate-coupled simulation clock | `FpsLimiter = flipstart(30)` in `DDrawCompat.ini` |
| "Software render files not installed" | Missing `InstallOptions` registry value | Set `InstallOptions=0x50707` (WOW6432Node; `EP1` key for PM) |
| Grainy / low-detail visuals | Default VIDEO DEVICE = Software Render @ 320×240 | In-game: select Direct3D HAL device, raise resolution |
| Cutscenes fail to decode | Indeo 5 codec unregistered | Register `vidc.iv50 = ir50_32.dll` |

---

## Summary

On 64-bit Windows 10 and 11, *MechWarrior 3* (1999) requires a DirectDraw compatibility layer because its 16-bit-era DirectDraw rendering does not function correctly on modern display drivers. The commonly recommended wrapper, dgVoodoo2, produces a consistent crash at the start of any mission: the game's software rasterizer repurposes the x86 stack pointer as a pixel-write pointer, and dgVoodoo2's guard-page–based surface tracking raises a memory exception that cannot be delivered while the stack pointer references the framebuffer, terminating the process. Substituting DDrawCompat — which wraps the operating system's native DirectDraw without guard-page tracking — resolves the crash. Additional steps for a stable installation include limiting the frame rate (the game's timing is coupled to the render loop), registering the Indeo 5 video codec, restoring the `InstallOptions` registry value, selecting the hardware Direct3D device in the in-game options, and ensuring the game's full-motion video files are present and uncompressed, as the engine crashes when they are missing or invalid.
