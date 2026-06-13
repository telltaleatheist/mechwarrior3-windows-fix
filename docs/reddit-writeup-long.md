# MechWarrior 3 (+ Pirate's Moon) on Windows 10/11 — fixing the instant mission-load crash

After years of failed attempts I finally have **MechWarrior 3** *and* the **Pirate's Moon** expansion running flawlessly on Windows 11. The thing that always beat me was a hard crash the instant any mission loaded — the cockpit would draw for a split second, then the game would vanish. If that's you, this is the fix.

**The one-line answer: use DDrawCompat as your DirectDraw wrapper, NOT dgVoodoo.** dgVoodoo is the popular recommendation and it gets you to the menus, but it is fundamentally incompatible with MW3's software cockpit renderer and crashes every mission. DDrawCompat doesn't. Details and the full setup below.

---

## Part 1 — Setup guide (the practical bit)

Assumes you have the game installed, patched to **v1.2**, with a **no-CD executable** (the game won't find a modern optical drive happily). Steps are the same for the base game and Pirate's Moon.

### 1. Wrapper: DDrawCompat (this is the crash fix)
1. Download the latest **DDrawCompat** (narzoul's, from its GitHub releases — it's just a single `ddraw.dll`).
2. If you previously used dgVoodoo, **remove its files from the game folder**: `DDraw.dll`, `D3DImm.dll`, `D3D8.dll`, `D3D9.dll`, `dgVoodoo.conf`, `dgVoodooCpl.exe`. (Back them up; don't just trust me.)
3. Drop DDrawCompat's `ddraw.dll` into the game folder (next to the game EXE).

MW3 only actually imports `ddraw.dll` for graphics — its 3D goes through DirectDraw's own Direct3D interface — so you do **not** need any D3D wrapper DLLs. DDrawCompat alone is enough.

### 2. Fix the game speed (otherwise it runs ~5x too fast)
MW3's game clock is tied to frame rate. Uncapped on a modern GPU it's comically fast and weapon/heat timing is wrong. Create a text file named **`DDrawCompat.ini`** in the game folder:

```
FpsLimiter = flipstart(30)
```

30 fps is the era-correct target and gives correct game speed. (You can try `flipstart(60)` for smoothness, but verify timing feels right.)

### 3. Fix the "software render files were not installed" video error
If you get a **Video Error** dialog saying *"rendering via the gamez engine is not supported because the software render files component was not installed during setup,"* the game's `InstallOptions` registry value is missing/wrong. Import this (elevated/admin), adjusting the path:

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\MicroProse\MechWarrior 3\1.0]
"InstallPath"="C:\\Games\\MechWarrior3\\"
"Version"="1.2"
"InstallOptions"=dword:00050707
```

The `WOW6432Node` path matters — MW3 is 32-bit, so on 64-bit Windows it reads from there. For **Pirate's Moon** the key is a separate one: `...\MicroProse\MechWarrior 3 EP1\1.0` with the same `InstallOptions=dword:00050707`.

### 4. Fix the intro/briefing videos (optional but recommended)
MW3's FMVs are **Indeo 5**, which modern Windows no longer registers. If videos fail or crash, register the codec (admin):

```
reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32" /v vidc.iv50 /t REG_SZ /d ir50_32.dll /f
```

`ir50_32.dll` ships in the game folder; copy it to `C:\Windows\SysWOW64\` if it isn't there.

### 5. Do NOT use Windows compatibility modes on the game EXE
Win95/98/XP compatibility checkboxes make DDrawCompat (and dgVoodoo) misbehave. Leave them off. The only flag that's safe/useful is **High DPI scaling override = Application** (helps the mouse map correctly at low render resolution on a high-DPI desktop).

### That's it
Base game and Pirate's Moon both run windowed-borderless via DDrawCompat, alt-tab cleanly, mouse behaves, correct speed, no mission crash.

**Pirate's Moon note:** it's a standalone expansion. The cleanest route is a pre-cracked RIP (already decompressed and no-CD) — then it's just steps 1–3 above plus its own `EP1` registry key. RIPs usually strip the FMV videos and high-quality sound set; if you want those, install from the ISO instead and apply a Pirate's Moon no-CD crack.

---

## Part 2 — Technical deep-dive (why dgVoodoo crashes it, and DDrawCompat doesn't)

This is the part that took the digging. The crash is **100% deterministic** at mission start, and Windows Error Reporting pins it to a fixed address: a `STATUS_GUARD_PAGE_VIOLATION` (`0x80000001`) at `Mech3.exe+0x16d4a5`, immediately followed by an access violation with a "return address" of `0x424a424a` — which is ASCII **`JBJB`**, i.e. *texture data*. The CPU tried to return into pixels.

### What the code at the fault does
Disassembling around `+0x16d4a5` reveals a classic 1990s software-rasterizer speed trick — a textured span-fill blitter that **uses the stack pointer (ESP) as its pixel write pointer**:

```
mov  [saved_esp], esp        ; stash the real stack pointer
mov  esp, [dest_surface_ptr] ; point ESP into the render surface
add  esp, edi                ; ESP = end of span (writes go downward)
...
loop:
  mov   al, [ebp+esi]        ; sample 8-bit source texel
  push  word [ebx+eax*2]     ; <-- FAULTS: write palette[texel] to surface via PUSH
  ...
  jne   loop
mov  esp, [saved_esp]        ; restore the real stack pointer
```

`push` is just "decrement a pointer and write" — so by hijacking ESP, the game writes two pixels' worth of data per instruction with no separate pointer bookkeeping. Fast in 1999. The cockpit/HUD compositor uses a whole family of these (specialized per texture width). This path runs every frame a cockpit is on screen — which is why it triggers exactly at mission start.

### Why dgVoodoo turns that into a fatal crash
dgVoodoo emulates video memory in system RAM and marks surface pages with **`PAGE_GUARD`** to do dirty-tracking — it needs to know which pixels changed so it can re-upload them to the real GPU. Normally every first write to a guarded page raises a guard-page exception, dgVoodoo's in-process handler catches it, clears the guard, records the page as dirty, and resumes. This fires **thousands of times per frame** and is completely benign — I confirmed it by attaching a debugger and watching the floods sail past harmlessly.

The fatal case is the ESP-hijack blitter. When a guard-page fault fires **while ESP is pointing into the surface**, Windows has to deliver the exception by pushing an exception/context frame onto the stack — but the stack *is the framebuffer*. The dispatch writes exception data over video memory and/or faults again on the bogus stack, dgVoodoo's handler never even gets to run, and the process dies. The `JBJB`/`0x424a424a` "return into garbage" is the smoking gun: exception dispatch landed on a stack full of pixels.

Crucially, dgVoodoo's `FastVideoMemoryAccess=true` (which is supposed to hand out unguarded memory) **does not fix it** — it doesn't apply to the surface type MW3 uses here. The guard pages stay, so the crash stays.

### Why DDrawCompat fixes it cleanly
DDrawCompat is a different kind of wrapper: it sits on top of the **real Windows DirectDraw** (still present and functional on Win10/11) and enhances it, rather than emulating video memory with guard-page tracking. No guard pages on the surface means the ESP-hijack blitter's `push` writes just succeed — there's no exception to mis-deliver, so the crash mechanism simply doesn't exist. The cockpit composites normally and missions run.

### Things that looked relevant but were red herrings
- **Sound / DirectInput / force-feedback** — ruled out; the fault is in the rasterizer, touches no imports.
- **Hardware vs. software renderer (the `Norend` registry value)** — no effect. The 3D scene can be hardware-accelerated, but the cockpit/HUD always composites in software, so the offending blitter runs regardless.
- **Resolution / the targeting-triangle overflow bug** — different issue; the fault marches through a fixed-size buffer, not an overflow.
- **CPU affinity / overlays (iCUE, NVIDIA) / compatibility modes** — none of it mattered. The crash is purely the guard-page-vs-ESP-blit conflict.

### Summary
| Symptom | Cause | Fix |
|---|---|---|
| Crash the instant a mission loads | dgVoodoo guard-page dirty-tracking collides with MW3's stack-as-framebuffer blitter; exception can't be delivered on a hijacked stack | Use **DDrawCompat** (no guard-page tracking) |
| Menus/game run ~5x too fast | Frame-rate-coupled game clock, uncapped | `FpsLimiter = flipstart(30)` in `DDrawCompat.ini` |
| "Software render files not installed" video error | Missing `InstallOptions` registry value | Import the `InstallOptions=0x50707` key (WOW6432Node) |
| Intro/briefing videos fail | Indeo 5 codec unregistered on modern Windows | Register `vidc.iv50 = ir50_32.dll` |

The lesson I took from this: for a deterministic, fixed-address crash, **read the faulting instruction** before you start swapping wrappers. Ten minutes of disassembly told me the exact mechanism; years of "try another setting" never could.
