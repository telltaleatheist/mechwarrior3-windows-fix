import ctypes as C
from ctypes import wintypes as W
import sys

k = C.windll.kernel32

DEBUG_ONLY_THIS_PROCESS = 0x00000002
DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT = 1
CREATE_PROCESS_DEBUG_EVENT = 3
EXIT_PROCESS_DEBUG_EVENT = 5
INFINITE = 0xFFFFFFFF

STATUS_GUARD_PAGE = 0x80000001
STATUS_ACCESS_VIOLATION = 0xC0000005

FAULT_RVA = 0x16d4a5  # relative to image base
EXE = r"C:\Games\MechWarrior3\Mech3.exe"
CWD = r"C:\Games\MechWarrior3"

class STARTUPINFO(C.Structure):
    _fields_ = [("cb", W.DWORD), ("lpReserved", W.LPWSTR), ("lpDesktop", W.LPWSTR),
                ("lpTitle", W.LPWSTR), ("dwX", W.DWORD), ("dwY", W.DWORD),
                ("dwXSize", W.DWORD), ("dwYSize", W.DWORD), ("dwXCountChars", W.DWORD),
                ("dwYCountChars", W.DWORD), ("dwFillAttribute", W.DWORD),
                ("dwFlags", W.DWORD), ("wShowWindow", W.WORD), ("cbReserved2", W.WORD),
                ("lpReserved2", C.POINTER(C.c_byte)), ("hStdInput", W.HANDLE),
                ("hStdOutput", W.HANDLE), ("hStdError", W.HANDLE)]

class PROCESS_INFORMATION(C.Structure):
    _fields_ = [("hProcess", W.HANDLE), ("hThread", W.HANDLE),
                ("dwProcessId", W.DWORD), ("dwThreadId", W.DWORD)]

class EXCEPTION_RECORD(C.Structure):
    pass
EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", W.DWORD), ("ExceptionFlags", W.DWORD),
    ("ExceptionRecord", C.POINTER(EXCEPTION_RECORD)),
    ("ExceptionAddress", C.c_void_p), ("NumberParameters", W.DWORD),
    ("ExceptionInformation", C.c_void_p * 15)]

class EXCEPTION_DEBUG_INFO(C.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", W.DWORD)]

class CREATE_PROCESS_DEBUG_INFO(C.Structure):
    _fields_ = [("hFile", W.HANDLE), ("hProcess", W.HANDLE), ("hThread", W.HANDLE),
                ("lpBaseOfImage", C.c_void_p), ("dwDebugInfoFileOffset", W.DWORD),
                ("nDebugInfoSize", W.DWORD), ("lpThreadLocalBase", C.c_void_p),
                ("lpStartAddress", C.c_void_p), ("lpImageName", C.c_void_p),
                ("fUnicode", W.WORD)]

class DEBUG_EVENT_U(C.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
                ("_pad", C.c_byte * 160)]

class DEBUG_EVENT(C.Structure):
    _fields_ = [("dwDebugEventCode", W.DWORD), ("dwProcessId", W.DWORD),
                ("dwThreadId", W.DWORD), ("u", DEBUG_EVENT_U)]

# WOW64_FLOATING_SAVE_AREA = 112 bytes
class WOW64_CONTEXT(C.Structure):
    _fields_ = [
        ("ContextFlags", W.DWORD),
        ("Dr0", W.DWORD), ("Dr1", W.DWORD), ("Dr2", W.DWORD),
        ("Dr3", W.DWORD), ("Dr6", W.DWORD), ("Dr7", W.DWORD),
        ("FloatSave", C.c_byte * 112),
        ("SegGs", W.DWORD), ("SegFs", W.DWORD), ("SegEs", W.DWORD), ("SegDs", W.DWORD),
        ("Edi", W.DWORD), ("Esi", W.DWORD), ("Ebx", W.DWORD), ("Edx", W.DWORD),
        ("Ecx", W.DWORD), ("Eax", W.DWORD),
        ("Ebp", W.DWORD), ("Eip", W.DWORD), ("SegCs", W.DWORD), ("EFlags", W.DWORD),
        ("Esp", W.DWORD), ("SegSs", W.DWORD),
        ("ExtendedRegisters", C.c_byte * 512)]

WOW64_CONTEXT_FULL = 0x00010007

k.OpenProcess.restype = W.HANDLE

def read_dword(hProc, addr):
    buf = (C.c_byte * 4)()
    n = C.c_size_t(0)
    ok = k.ReadProcessMemory(hProc, C.c_void_p(addr), buf, 4, C.byref(n))
    if not ok or n.value != 4:
        return None
    return int.from_bytes(bytes(buf), 'little')

def query(hProc, addr):
    class MBI(C.Structure):
        _fields_ = [("BaseAddress", C.c_void_p), ("AllocationBase", C.c_void_p),
                    ("AllocationProtect", W.DWORD), ("PartitionId", W.WORD),
                    ("RegionSize", C.c_size_t), ("State", W.DWORD),
                    ("Protect", W.DWORD), ("Type", W.DWORD)]
    mbi = MBI()
    r = k.VirtualQueryEx(hProc, C.c_void_p(addr), C.byref(mbi), C.sizeof(mbi))
    if not r:
        return None
    return mbi

PROT = {0x1:"NOACCESS",0x2:"READONLY",0x4:"READWRITE",0x8:"WRITECOPY",
        0x10:"EXECUTE",0x20:"EXEC_READ",0x40:"EXEC_RW",0x80:"EXEC_WC",
        0x100:"GUARD",0x200:"NOCACHE",0x400:"WRITECOMBINE"}
STATE = {0x1000:"COMMIT",0x2000:"RESERVE",0x10000:"FREE"}
TYPE = {0x20000:"PRIVATE",0x40000:"MAPPED",0x1000000:"IMAGE"}

def desc_prot(p):
    base = p & 0xFF
    extra = []
    if p & 0x100: extra.append("+GUARD")
    if p & 0x200: extra.append("+NOCACHE")
    if p & 0x400: extra.append("+WC")
    return PROT.get(base, hex(p)) + "".join(extra)

def main():
    si = STARTUPINFO(); si.cb = C.sizeof(si)
    pi = PROCESS_INFORMATION()
    ok = k.CreateProcessW(EXE, None, None, None, False,
                          DEBUG_ONLY_THIS_PROCESS, None, CWD, C.byref(si), C.byref(pi))
    if not ok:
        print("CreateProcess failed", k.GetLastError()); return
    base = None
    hProc = None
    seen_fault = 0
    de = DEBUG_EVENT()
    while True:
        if not k.WaitForDebugEvent(C.byref(de), INFINITE):
            break
        code = de.dwDebugEventCode
        cont = DBG_CONTINUE
        if code == CREATE_PROCESS_DEBUG_EVENT:
            base = de.u.CreateProcessInfo.lpBaseOfImage
            hProc = de.u.CreateProcessInfo.hProcess
            print(f"[+] image base = {base:#x}")
            sys.stdout.flush()
        elif code == EXCEPTION_DEBUG_EVENT:
            er = de.u.Exception.ExceptionRecord
            first = de.u.Exception.dwFirstChance
            ecode = er.ExceptionCode & 0xFFFFFFFF
            eaddr = er.ExceptionAddress or 0
            rva = (eaddr - base) if base else 0
            if ecode in (STATUS_GUARD_PAGE, STATUS_ACCESS_VIOLATION):
                hThread = k.OpenThread(0x1F03FF, False, de.dwThreadId)
                ctx = WOW64_CONTEXT(); ctx.ContextFlags = WOW64_CONTEXT_FULL
                got = k.Wow64GetThreadContext(hThread, C.byref(ctx))
                tag = {STATUS_GUARD_PAGE:"GUARD_PAGE", STATUS_ACCESS_VIOLATION:"ACCESS_VIOLATION"}[ecode]
                # exception info[0]=read/write flag, info[1]=target address
                rw = er.ExceptionInformation[0]
                tgt = er.ExceptionInformation[1] or 0
                print(f"\n=== {tag} firstChance={first} at {eaddr:#x} (rva {rva:#x}) "
                      f"{'WRITE' if rw==1 else 'READ' if rw==0 else 'EXEC'} target={tgt & 0xFFFFFFFF:#x}")
                if got:
                    print(f"    EIP={ctx.Eip:#010x} ESP={ctx.Esp:#010x} EBP={ctx.Ebp:#010x}")
                    print(f"    EAX={ctx.Eax:#010x} EBX={ctx.Ebx:#010x} ECX={ctx.Ecx:#010x} EDX={ctx.Edx:#010x}")
                    print(f"    ESI={ctx.Esi:#010x} EDI={ctx.Edi:#010x}")
                if rva == FAULT_RVA or (base and abs(rva - FAULT_RVA) < 0x10):
                    seen_fault += 1
                    g = lambda a: read_dword(hProc, a)
                    dest = g(0x72c278); src = g(0x72c268); lut = g(0x72c26c)
                    stepx = g(0x72c270); stepy = g(0x72c274); savedesp = g(0x74a338)
                    fmt = g(0x8007d8)
                    print(f"    --- renderer globals ---")
                    print(f"    [0x72c278] dest_base   = {dest if dest is None else hex(dest)}")
                    print(f"    [0x74a338] saved_esp    = {savedesp if savedesp is None else hex(savedesp)}")
                    print(f"    [0x72c268] src_tex_base = {src if src is None else hex(src)}")
                    print(f"    [0x72c26c] palette_LUT  = {lut if lut is None else hex(lut)}")
                    print(f"    [0x72c270] step_x       = {stepx if stepx is None else hex(stepx)}")
                    print(f"    [0x72c274] step_y       = {stepy if stepy is None else hex(stepy)}")
                    print(f"    [0x8007d8] pixfmt_sel   = {fmt if fmt is None else hex(fmt)}")
                    if dest is not None:
                        print(f"    ESP - dest_base = {ctx.Esp - dest:#x} ({ctx.Esp - dest} bytes) "
                              f"=> implied span len {(ctx.Esp - dest)//2} px")
                    for name, a in [("ESP_region", ctx.Esp), ("dest_region", dest or 0),
                                    ("target_region", tgt & 0xFFFFFFFF)]:
                        mbi = query(hProc, a)
                        if mbi:
                            print(f"    {name} @ {a & 0xFFFFFFFF:#x}: "
                                  f"AllocBase={(mbi.AllocationBase or 0):#x} "
                                  f"Size={mbi.RegionSize:#x} "
                                  f"State={STATE.get(mbi.State,hex(mbi.State))} "
                                  f"Prot={desc_prot(mbi.Protect)} "
                                  f"Type={TYPE.get(mbi.Type,hex(mbi.Type))}")
                    sys.stdout.flush()
                    if seen_fault >= 2:
                        print("\n[!] captured twice; detaching")
                        k.DebugActiveProcessStop(de.dwProcessId)
                        return
                k.CloseHandle(hThread)
                cont = DBG_EXCEPTION_NOT_HANDLED if not first else DBG_CONTINUE
                # for guard page first-chance, let OS handle (DBG_CONTINUE re-runs with guard cleared)
            else:
                cont = DBG_EXCEPTION_NOT_HANDLED
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print("[+] process exited")
            k.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE)
            break
        k.ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont)

if __name__ == "__main__":
    main()
