# Appendix — Crash artifacts (MechWarrior 3 mission-load crash)

Supporting evidence for the analysis in the main breakdown. Three exhibits: the operating-system crash records, the disassembly of the faulting routine, and a live debugger trace of the guard-page mechanism. Together they establish the cause without ambiguity. `Mech3.exe` image base is `0x00400000`, so module offset `+0x16d4a5` = virtual address `0x0056d4a5`.

---

## Exhibit A — Windows Error Reporting records

Captured from the Application event log (`Application Error`) across repeated crashes. Two distinct, deterministic signatures.

**A1 — the primary fault (guard-page violation in the game's own code):**

```
Faulting application name: Mech3.exe, version: 1.2.22.0
Faulting module name:      Mech3.exe, version: 1.2.22.0
Exception code:            0x80000001   (STATUS_GUARD_PAGE_VIOLATION)
Fault offset:              0x0016d4a5
```

**A2 — the resulting cascade a few milliseconds later (exception dispatched onto a stack that is actually video memory):**

```
Faulting module name: unknown,    Exception code: 0xc0000005 (ACCESS_VIOLATION), Fault offset: 0x424a424a
Faulting module name: ntdll.dll,  Exception code: 0xc0000409 (STACK_BUFFER_OVERRUN / fail-fast), Fault offset: 0x000c436f
Faulting module name: ntdll.dll,  Exception code: 0xc0000029 (INVALID_UNWIND_TARGET),            Fault offset: 0x000c436f
```

`0x424a424a` is ASCII **`"JBJB"`** — texture/pixel data. The CPU attempted to use pixel bytes as a code/return address because exception dispatch landed on a "stack" that is really the framebuffer. This is the fingerprint of the bug.

**A3 — the separate, unrelated FMV crash (documented for completeness):**

```
Faulting application name: Mech3fixup.exe
Faulting module name:      AVIFIL32.dll
Exception code:            0xc0000005 (ACCESS_VIOLATION)
Fault offset:              0x0000740d
```

This is the video subsystem choking on an invalid/compressed FMV file (see main breakdown, Issue 2), not the renderer bug.

---

## Exhibit B — Disassembly of the faulting routine (`0x0056d440`)

The function containing the fault, disassembled from the retail `Mech3.exe` (capstone, x86-32). It is a software texture-span blitter that **moves the stack pointer (ESP) into the destination surface and writes pixels with `push`** — then restores ESP at the end.

```asm
0x0056d440  push   ebp
0x0056d441  mov    ebp, esp
0x0056d443  sub    esp, 8
0x0056d446  push   ebx
0x0056d447  push   esi
0x0056d448  push   edi
0x0056d449  mov    [ebp-4], edx
0x0056d44c  mov    [ebp-8], ecx
0x0056d44f  push   ebp
0x0056d450  mov    [0x74a338], esp        ; save the real stack pointer to a global
0x0056d456  mov    ecx, [ebp-8]
0x0056d459  mov    edx, [ebp-4]
0x0056d45c  mov    edi, [ebp+8]           ; span length
0x0056d45f  mov    esp, [0x72c278]        ; ** ESP := destination surface pointer **
0x0056d465  add    edi, edi               ; length *= 2 (16-bit pixels)
0x0056d467  mov    ebp, [0x72c268]        ; source texture base
0x0056d46d  add    esp, edi               ; ESP = surface_end (writes proceed downward)
0x0056d46f  mov    esi, [0x5efb98]
0x0056d475  mov    ebx, [0x72c26c]        ; 16-bit color LUT / palette
0x0056d47b  mov    eax, ecx               ; <-- loop top
0x0056d47d  and    esi, edx
0x0056d47f  sar    eax, 0x14              ; fixed-point U -> integer
0x0056d482  add    ecx, [0x72c270]        ; U += step_x
0x0056d488  shr    esi, 0x0d
0x0056d48b  and    eax, 0x7f              ; texel index & 0x7F (texture width 128)
0x0056d48e  add    esi, eax
0x0056d490  xor    eax, eax
0x0056d492  add    edx, [0x72c274]        ; V += step_y
0x0056d498  mov    al, [ebp+esi]          ; sample 8-bit source texel
0x0056d49c  mov    esi, [0x5efb98]
0x0056d4a2  sub    edi, 2
0x0056d4a5  push   word [ebx+eax*2]       ; <<< FAULT: write palette[texel] to the surface via ESP
0x0056d4a9  jne    0x56d47b               ; loop
0x0056d4ab  mov    esp, [0x74a338]        ; restore the real stack pointer
0x0056d4b1  pop    ebp
0x0056d4b2  pop    edi
0x0056d4b3  pop    esi
0x0056d4b4  pop    ebx
0x0056d4b5  mov    esp, ebp
0x0056d4b7  pop    ebp
0x0056d4b8  ret    4
```

The faulting instruction (`+0x16d4a5`) is the `push` — a *write* through ESP into the surface set up at `0x0056d45f`. When that surface page is guard-protected, the resulting exception cannot be delivered because the stack is the surface. (This is one of a family of size-specialized variants in the binary; the others are identical apart from the texture-width mask.)

---

## Exhibit C — Live debugger trace (the guard-page mechanism)

Captured by attaching a purpose-built Win32 debugger (`DEBUG_ONLY_THIS_PROCESS` + `Wow64GetThreadContext`) to the game while **dgVoodoo2** was the active wrapper. It demonstrates that dgVoodoo guard-protects its emulated video memory and the game faults on it continuously — 157 first-chance guard-page exceptions captured before the run ended, marching page-by-page through the surface region:

```
[+] image base = 0x400000

=== GUARD_PAGE firstChance=1 at 0x577ab7 (rva 0x177ab7) WRITE target=0x6384000
    EIP=0x00577ab7 ESP=0x0019fcb8 EBP=0x00000500
    EAX=0x06384000 EBX=0x03e79340 ECX=0x00000140 EDX=0x00000500
    ESI=0x062d7020 EDI=0x06384000

=== GUARD_PAGE firstChance=1 at 0x577ab7 (rva 0x177ab7) WRITE target=0x6385000
    EIP=0x00577ab7 ESP=0x0019fcb8 EBP=0x00000500
    EAX=0x06384f00 EBX=0x03e79340 ECX=0x00000100 EDX=0x00000500
    ESI=0x062d8020 EDI=0x06385000
... (157 guard-page faults total; write targets march 0x6384000 -> 0x53da400) ...
```

**What this proves:** dgVoodoo's surface memory (the `0x06xxxxxx` / `0x05xxxxxx` targets) is `PAGE_GUARD`-protected, and the game triggers a guard-page exception on essentially every page it touches. These particular faults are *survivable* because the faulting blitters here (`0x577ab7`, `0x579809`) address the surface through ordinary registers, so **ESP is a valid stack** (`0x0019fcb8`) and the OS can deliver and resume the exception.

The fatal routine in Exhibit B is the exception: it puts the surface pointer **into ESP itself**. A guard-page fault there has nowhere to dispatch — which is precisely what Exhibit A1/A2 records. (The debugger run did not reach a mission cockpit before exiting, so it captured the benign sibling faults rather than the fatal one live; the fatal path is established by Exhibit B + A.)

---

## Reproduction / methodology

1. Read the deterministic `Fault offset` from WER (Exhibit A).
2. Disassemble that offset in `Mech3.exe` with `pefile` + `capstone` to identify the routine (Exhibit B).
3. Attach a `ctypes` Win32 debugger to observe the live exception stream and confirm the guard-page surface mechanism (Exhibit C).
4. Confirm the fix by swapping dgVoodoo2 → DDrawCompat (no guard-page tracking) and verifying missions load.

Tooling used (all scripts available): `mw3_crash_analysis.py`, `mw3_disasm_clean.py` (Exhibit B), `mw3_debug.py` (Exhibit C), plus `pefile` and `capstone`.

> **Note on a literal post-mortem stack trace:** a conventional call-stack dump of this crash is not meaningful, because at the moment of the fault the stack pointer is aimed at the framebuffer — any "stack walk" simply reads pixel data (the `0x424a424a` "JBJB" in Exhibit A2 is exactly that). The disassembly + fault offset + the "JBJB" return address are the diagnostic, not a stack walk.
