# 02 — Kernel driver (`EasyAntiCheat_EOS.sys` / `EasyAntiCheat.sys`)

The trust root. The user-mode agent could be lied to by anything in userspace, so EAC's design is "whenever something is security-sensitive, ask the driver." The driver observes the system through legal kernel callback APIs — no inline hooking of ntoskrnl, no SSDT shenanigans, nothing PatchGuard would blow up on — and the user-mode agent is really a reporting agent that bubbles the driver's observations to Epic's backend.

This doc is **the complete kernel-side reversal.** Byte-level offsets, every callback, every IOCTL, the ETW-TI subscription, the hash-dispatched API resolver, the flattened command dispatcher, the 46→45 module manifest. If something lives in kernel memory, it's catalogued here.

---

## Part 1 — The binary itself

### Build fingerprint

Current build (Nov 20 2026 Fortnite update, driver PE-timestamp Nov 17 2026):

```
File size      : 46,171,808 bytes (~46 MB on disk)
Sections       : 9 (unchanged from v3.2.0.0)
Entry point    : 0x27C438 (moved from 0x26F738 in v3.2.0.0)
ImageBase      : 0x140000000
SHA256         : 3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b
PE timestamp   : 2026-11-17 05:36:29 UTC
Signer         : Epic Games Inc.
Sign thumbprint: 3CD980E3BACD8FB6FB3F532AFF62753FB7DE47A8
Sign CA        : DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
Cert validity  : 2026-02-01 → 2029-02-01
Imports        : ONE — FLTMGR.SYS!FltRegisterFilter (never called, load-order hint only)
```

Reference prior build (MinaMeow's analysis, UC thread 781475, Nov 14 2026):

```
Driver version : v3.2.0.0 (per MinaMeow — note she pasted the SERVICE EXE hash,
                 not the driver hash, in her post — the hash 0bbe6d48...340b9 is
                 actually EasyAntiCheat_EOS.exe, not the driver)
File size      : 40,189,592 bytes
Entry point    : 0x26F738
Source thread  : https://www.unknowncheats.me/forum/anti-cheat-research/781475-reversal-eac-detection-dma-driver-hwid-collection.html
```

**Growth Nov 20 2026 vs v3.2.0.0**: +~6 MB file, +~54 KB `.text`, +~6.5 MB monster section.

### Layout (current-build teardown)

Target build fingerprint: 40 MB driver, 9 sections, entry at end of `.text` (`0x26F738`). If your `.sys` is smaller / entry at start, you have a different build — the *patterns* here apply, the numbers may have shifted.

```
.text     0x1000    - 0x26F764   plain MSVC code (~1490 functions w/ unwind)
.rdata    0x270000  - 0x31552C
.data     0x316000  (vsize 0x51740, only 0x2200 raw)
(unnamed) 0x368000  + 0x7B00
.rsrc     0x370000  (version info)
.reloc    0x371000  (0x30DC, 6121 DIR64 entries)
(unnamed) 0x375000  + 0x7E00   <- the "cage" (exec, ~52 KB)
(unnamed) 0x37D000  + 0x2316000 (~35 MB monster section)
.pdata    0x2693000 (0x103E0, 5544 RUNTIME_FUNCTIONs)
```

### Quirks

- **Several raw pointers overlap between sections.** Sloppy on purpose or just sloppy — either way it breaks lazy parsers.
- **Entry point at the END of `.text`** (`0x26F738`). Easy to miss.
- **"Image B" at `0x37D350 – 0x46A616`** — another ~1 MB of plain code with 4054 of its own pdata functions inside the monster section. The rest (`0x46A616` up to `~0x2693000`) is the compressed blob.
- **`.text` internal calls: 7586. Image B internal: 5815. Cross-calls between them: zero.** They only meet through the cage and pointer tables.
- **Import table: exactly ONE import.** `FLTMGR.SYS!FltRegisterFilter` (import dir `0x30CCA0`, IAT `0x30CCD8`). **Never called.** Zero static xrefs. It's only there to force fltmgr to load before `eac.sys`.
- **Debug directory `0x30CBE0`** has entries zeroed, but leftover strings sit right below:
  - `"RSDSd2L"` at `0x30CC18`
  - `"LLD PDB."` at `0x30CC24`
  - **`"Core.pdb"` at `0x30CC30`** — the engine module is called `Core`.
- **~1.1 MB of `.text`** (0x13415F bytes across 60+ islands) has **no `.pdata` coverage**. All hand-written glue: cage entry stubs, trampolines, stack switchers. Islands at:
  ```
  0x23B9BF – 0x24DC00
  0xD0590  – 0xD9E1A
  0x132A31 – 0x1399B1
  0x1472C9 – 0x14D945
  0x222AE  – 0x286ED
  ```

### Entry chain (`0x26F738`)

```asm
0x26F708  mov    rax, qword ptr [rip + 0xa6a79]     ; -> 0x316188
0x26F70F  test   rax, rax
0x26F712  je     0x26f72f
0x26F714  movabs rcx, 0x2b992ddfa232
0x26F71E  cmp    rax, rcx
0x26F721  je     0x26f72f
0x26F723  not    rax
0x26F726  mov    qword ptr [rip + 0xa6a63], rax     ; -> 0x316190
0x26F72D  ret
```

Security-cookie companion check (cells `0x316188` / `0x316190`). Then `0x26F738` calls it, then calls the real main with the original `(DriverObject, RegistryPath)` args. **Main is at `0x6595E`**, hand-written prologue, immediately jumps into the cage at `0x3B7FE0`.

---

## Part 2 — The obfuscation stack (byte-level)

The file is **not packed**. `.text` is plain MSVC output. The "protection" is obfuscation layered on top.

### 2.a — The cage (`0x375000 – 0x37D350`)

Unnamed exec section, ~52 KB of small trampolines, mostly no unwind info. Every trampoline shuffles the VM context (r12-relative slots), reloads state from `[r12+0x190]` / `[r12+0x198]`, jumps where it has to.

**Calling convention is "context struct", not x64 ABI.**

Example chain: `0x3B7FE0` thunks into `0x1DFF28`. Other stubs `jmp` to `0xE9C129`, `0x1365BBC`, `0x206D8DE`, `0xBD7D0A`, …

**Cage prologue** — saves everything, sets r12 = ctx frame:

```asm
0x37D00F  mov [rsp+8], r15 ... (push r15/r14/r13/r12/rsi/rdi/rbp/rbx)
          movups [rsp+..], xmm6/xmm10/xmm7/...
          pushfq                       ; save rflags
          lea r12, [rsp+8]
          ret
```

Matching restore epilogue at `0x37D134`.

### 2.b — The stack switcher (`0x23B9BF`)

Appears exactly once in the whole 40 MB. Runs callback logic on a caller-supplied stack. Call chains vanish from normal unwinders.

```asm
0x23B9BF  90            nop
0x23B9C0  57            push rdi
0x23B9C1  48 8B FC      mov  rdi, rsp
0x23B9C4  4C 8B D1      mov  r10, rcx
0x23B9C7  48 8B E2      mov  rsp, rdx        ; <- private stack
0x23B9CA  49 8B C8      mov  rcx, r8
0x23B9CD  49 8B D1      mov  rdx, r9
0x23B9D0  41 FF D2      call r10
0x23B9D3  48 8B E7      mov  rsp, rdi
0x23B9D6  5F            pop  rdi
0x23B9D7  C3            ret
```

### 2.c — The hash mix (CHANGED in Nov 20 2026 build)

**Old build (MinaMeow v3.2.0.0)**: splitmix64 finalizer, constant `0x9E3779B185EBCA87`, 1071 sites.

**New build (Nov 20 2026)**: MurmurHash3-style finalizer, constant `0xFF51AFD7ED558CCD`, 1176 sites in driver `.text`. `0x9E3779B185EBCA87` has **0 occurrences** in the new driver.

Only the FIRST MurmurHash3 finalizer multiplier is present — MurmurHash3's second `0xC4CEB9FE1A85EC53` has 0 sites. EAC uses a custom finalizer with just the one multiplier. "SplitMix-variant with MurmurHash3's first constant" is the right characterization.

**Impact**: hash-reverse tables derived against MinaMeow's splitmix64 constant are now invalid for the driver. New tables must be built against `0xFF51AFD7ED558CCD`.

Note: the user-mode agent DLL (`b.dll`) still has 4 sites of the old `0x9E3779B185EBCA87` — different hash functions per module.

Pattern:

**Old build (MinaMeow v3.2.0.0) pattern:**

```asm
0x214A7   shl  rdi, 0x1a               ; (arg1 << 26) | arg2  -> packed id
0x214AB   or   rdi, rcx
0x214AE   movabs rax, 0x9E3779B185EBCA87     ; <-- OLD constant (splitmix64)
0x214BB   imul rdx, rax
0x214C2   shr  rbx, 0x20
0x214C9   shr  rcx, 0x3c
0x214CD   shr  rbx, cl                 ; variable shift by top nibble
0x214D0   xor  rbx, rdx
0x214D3   imul rbx, rax
0x214D7   xor  rbx, rdi                ; = final id
```

**New build (Nov 20 2026)** uses the same pattern with `movabs rax, 0xFF51AFD7ED558CCD` in place of the splitmix64 constant. Offsets have shifted — the pattern now lives further into the enlarged `.text` section.

### 2.d — Hash-dispatched API resolving

The **actual "protection" of the call surface.** Every resolved call looks like the resolver at `0x21495`:

```asm
0x214DA   movabs rax, 0x40AA7C5B80C670F3
0x214E4   imul   rax, rbx              ; rbx = id from (c)
0x214E8   mov    rcx, [rip+0x2E64A1]   ; head pointer cell
0x214EF   neg    rax
0x214F2   mov    rcx, [rcx+rax]        ; <- function pointer, negative index
...
0x214F6   movabs rax, 0x6BDA2DE65E67AC64
0x21500   imul   rax, rbx
...
0x21514   movabs rax, 0xE32AB254512044E6
0x2151E   imul   rax, rbx
0x21522   mov    r9,  [rip+0x2E1397]
0x21529   sub    r9, rax
0x2152C   call   r9
```

**Each call site has its own multiplier constant.** Observed constants:

```
0x40AA7C5B80C670F3    0x6BDA2DE65E67AC64    0x3B93F13D663608E5
0xE32AB254512044E6    0xCE85B092C28DC0C2    0x4184EE92079B85D5
0xC351225F85EEC1CB    0x7544DBE290F73374    0xF429BCED6E7FBF5
0x2702763407B864F8    0x8C4A27E4BC905BC9    0x16A493048208C5AC
```

Head-pointer cells sit in `.data` / `.rdata` (near `0x302xxx`). Per-site index dictionaries live at `0x30B6C0 – 0x30BE14` (arrays of negative-looking dwords, `FFDB45xx` style).

**Result: static analysis shows no API surface at all. IDA shows nothing.** That's the point.

### 2.e — Flattening + selector + kill switches (feature flags)

`0x18C0E6 – 0x18FE5D`, size `0x3D77`, one function. All commands get hashed, the selector picks one of 4 jump-table ranges:

```asm
0x18C146  movzx  ecx, word ptr [r8]       ; cmd word from the request record
0x18C14A  imul   eax, edi, 0x2B79
0x18C150  movzx  eax, ax
0x18C153  xor    eax, 0xAF3E
0x18C158  and    eax, ecx                 ; cmd word AND-masks the selector
0x18C15A  imul   ebp, edi, -0x3C
0x18C160  xor    r13b, 0xE5
0x18C164  cmp    eax, 0x1B3               ; range split 1
0x18C169  jle    ...
0x18C16B  cmp    eax, 0x296               ; range split 2
0x18C176  cmp    eax, 0x31A               ; range split 3
          -> movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax   (4 tables)
```

**The feature-flag bit per handler** — every handler checks its own flag before running:

```asm
0x18C19F  mov  dl, byte ptr [r11+2]      ; flags byte from request record
          mov  eax, r10d; shl eax,5; add eax,r10d; neg eax
          xor  cl, 0x55                   ; shift1 = -(33*k) ^ 0x55
          shr  dl, cl                     ; -> flags >> shift1
          imul ecx, r10d, 0x3C
          xor  cl, 0x1F                   ; mask = (k*0x3C) ^ 0x1F
          and  cl, dl                     ; test = flags & mask
          je   <skip handler>             ; == 0 -> handler is OFF
          cmp  edx, 1                     ; == 1 -> primary path
```

**EAC can switch individual detection routines on/off per session, per game, remotely, by just setting bits in the request.** Bypass one check and you haven't bypassed the system — the backend just rotates a flag. This IS the trust-score mechanism in practice. See [04 user-mode agent](04-user-mode-agent.md) for the backend side.

Other flattened routines with the same pattern:

```
0x10E7E  – 0x124A4  (0x1626)      0x200F70 – 0x202284 (0x1314)
0x2CFF2  – 0x2E5CB  (0x15D9)      0x21C0C  – 0x222AE  (0x6A2)
0x4D4AA  – 0x4EAA7  (0x15FD)      0xC43FA  – 0xC5A0D  (0x1613)
0xC77A0  – 0xC8DE8  (0x1648)      0x268C00 – 0x269DD7 (0x11D7)
0x914B2  – 0x92E78  (0x19C6)
```

Rule of thumb: **anything ≥ ~`0x600` bytes is flattened.**

### 2.f — The 34 MB blob (CORRECTION — it's PLAIN, not encrypted/compressed)

`0x46A616` up to `~0x2692400` raw. **Plain unencrypted VM stream / handler store.**

**Correction note:** Earlier revisions of this doc (and some third-party writeups) described this blob as Oodle-compressed. MinaMeow's current-build teardown (Nov 2026) tested this and confirmed the blob is **plain** — the Oodle codec names present in `.rdata` at `0x30C9B0 – 0x30CB48`:

```
Kraken Selkie Mermaid Leviathan Hydra LZHLW LZBLW LZNIB LZNA LZB16
VeryFast SuperFast default BitKnit Too High subandf aggressive disable
Optimal1..Optimal5 HyperFast1..HyperFast4
"newlz chunk type %d = %s [%d->%d]"
```

...are **compiled-in but unused** against this particular blob. The Oodle decompressor is present (part of the 5544 functions), but the "monster section" payload after `0x46A616` is **plain handler/VM stream bytecode** that gets interpreted directly by the custom VM. No decompression step is performed on the blob itself; VMProtect-style handlers walk it in place.

This is actually *worse* for a reverser than if it were compressed — the blob's size (~34 MB) is entirely in-band obfuscation that slows your tooling without meaningful protection. MinaMeow's words: "a giant plain 34 MB handler blob that slows your tooling down way more than it actually protects anything."

### Why this correction matters

Previous common assumption: "crack the Oodle key and the blob reveals cheat-rules-like data." Actual reality: the blob **is** the VM program — walking it with an Oodle decoder gives you garbage. The way to understand the blob is to reverse the VM interpreter + handler dispatch, then disassemble the bytecode in place.

---

## Part 3 — DriverEntry

Predictable sequence.

### 3.1 — Self image check

Hash own `.text`, compare to baked-in SHA256, bail on mismatch. Catches naive "patch the sys on disk" attacks, which are useless anyway because the file has a WHQL cross-signature.

### 3.2 — Kernel API resolution by name

Older builds (pre-2019) had static imports. Current builds have maybe five imports; everything else is resolved at runtime via `MmGetSystemRoutineAddress`, cached into a global struct, XORed with a per-boot cookie so a kernel memory snapshot doesn't leak a clean pointer table.

### 3.3 — Device + symlink

```c
IoCreateDevice(drv, sizeof(DEV_CTX), <randomized name>,
               FILE_DEVICE_UNKNOWN, 0, FALSE, &g_devObj);
IoCreateSymbolicLink(L"\\DosDevices\\EasyAntiCheat", <device name>);
```

Device name has a random suffix. Symbolic link name stable because the user-mode agent needs to `CreateFile` it.

### 3.4 — Dispatch

```c
drv->MajorFunction[IRP_MJ_CREATE]         = eac_dispatch_create;
drv->MajorFunction[IRP_MJ_CLOSE]          = eac_dispatch_close;
drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = eac_dispatch_ioctl;
drv->DriverUnload                         = eac_unload;
```

### 3.5 — Callbacks installed

Current builds install:

| Callback | API | Purpose |
|-|-|-|
| Process create | `PsSetCreateProcessNotifyRoutineEx2` (win11 23H2+) <br> or `…Ex` (fallback) | Classify every new process, flag known-bad loaders. Ex2 allows pre-creation veto. |
| Thread create | `PsSetCreateThreadNotifyRoutine` | Flag unusual thread start addresses in protected processes. |
| Image load | `PsSetLoadImageNotifyRoutine` | SHA256 every loaded DLL, match against rules.bin. |
| Handle open (proc) | `ObRegisterCallbacks(PsProcessType)` | **The strip.** |
| Handle open (thread) | `ObRegisterCallbacks(PsThreadType)` | Same, for thread handles. |
| Registry | `CmRegisterCallbackEx` | Watch tamper on EAC keys + CI + BCD. |
| ETW-TI | `EtwRegisterEx` | Subscribe to kernel-asserted suspicious events. |

---

## Part 4 — IOCTL dispatcher — where you'll live

```c
NTSTATUS eac_dispatch_ioctl(PDEVICE_OBJECT dev, PIRP irp)
{
    auto sp = IoGetCurrentIrpStackLocation(irp);
    ULONG raw = sp->Parameters.DeviceIoControl.IoControlCode;
    ULONG code = raw ^ g_dev->ioctlXorKey;

    if (!eac_is_authed(irp->FileObject)) {
        irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }

    switch (code) { /* big switch — see IOCTL inventory below */ }
}
```

### The XOR key

32-bit, randomized at driver init, stored encrypted with the boot cookie in the device context. Lift live with a kernel debugger; statically it looks like another global. First time I reversed EAC I spent an afternoon wondering why IOCTL codes didn't match anything sensible until I caught the xor.

### Session auth at CREATE time

At first `CreateFile`, the client has to issue `IOCTL_EAC_SESSION_AUTH` with a blob containing:
- The launcher's cert chain
- A signed proof of `(pid, timestamp, nonce)`
- The game pid

Driver verifies the signature chain against a baked-in Epic public key, confirms the pid belongs to a process whose image was launched by an authenticated EAC launcher, and stamps the file object with a trust bit. Without that bit every other IOCTL short-circuits to `ACCESS_DENIED`.

### IOCTL inventory

Symbolic names mine; numbers rotate per version.

| IOCTL | Purpose |
|-|-|
| `SESSION_AUTH` | Handshake (covered above). |
| `READ_MEM` | Kernel-side read of target VA range. `polite` path = `MmCopyVirtualMemory`; `attach` path = `KeStackAttachProcess` + `ProbeForRead` + SEH. |
| `WRITE_MEM_PROBE` | Reads one page, hashes, returns hash. Proves to backend that the game's `.text` at offset X still looks like Y. |
| `GET_MODULES` | LDR module list for a pid. |
| `GET_VAD` | **Full VAD tree walk.** The manual-mapped detector's ground truth. |
| `ENUM_HANDLES` | All open handles system-wide filtered to a target pid. Catches pre-callback-race handles + `LIMITED_INFORMATION` escalators. |
| `ENUM_THREADS` | Thread list + start addresses. |
| `PATTERN_SCAN` | Byte-pattern match against a VA range. Expensive, used sparingly. |
| `PROC_INFO` | PEB/TEB fields without touching user memory. |
| `DRIVER_LIST` | Loaded kernel drivers + hashes + signer cert thumbprints + **WDAC block-list match state**. |
| `CALLBACK_DUMP` | Enumerate `PsSet*` callback entries + Ob entries, hash owning driver each. |
| `PHYS_READ` | Physical-memory read via `MmMapIoSpace`. Classic current build; gone on EOS variant. |
| `SELF_CHECK` | Driver signs `(hash || nonce || bootCookie)` with embedded Ed25519 key. Agent forwards to backend. |
| `HEARTBEAT` | Keepalive. |
| `REPORT_FLAG` | Agent → driver: "I found this, add to session report." |

### READ_MEM struct

```c
struct eac_read_in  { HANDLE pid; PVOID va; SIZE_T size; ULONG flags; };
struct eac_read_out { NTSTATUS status; SIZE_T got; UCHAR data[]; };
```

---

## Part 5 — Process / thread / image callbacks

### Process callback

Classifies by image path hash.

- **Game process** → tracked in protected-pid table.
- **Known-bad loader** → flagged.
- **With Ex2 veto flag set** → `CreationStatus = STATUS_ACCESS_DENIED`, creation fails. Used sparingly, only against high-severity blocklist entries.

The driver never kills a running process. Veto is pre-creation only.

### Thread callback

Reacts only on threads in a protected process. Reads `StartAddress` from `ETHREAD` (offset floats by Windows build — EAC has a dynamic resolver), classifies:

| Start address | Verdict |
|-|-|
| Known-good game module | ok |
| EAC's own modules | ok |
| `ntdll!LdrpInitializeThunk` | ok (normal creation path) |
| Non-whitelisted module | flag |
| Not in **any** LDR module | **flag hard** |

That last case is "a thread started in a VAD region with no backing module" — shellcode or a manually-mapped image.

### Image-load callback

Fires on every DLL load. Filters to protected processes. SHA256 first N pages. Matches against rules.bin's module section.

- Hash match → highest severity
- Path-suffix or byte-pattern match → medium
- Unsigned DLL under `system32` → own flag (unusual even outside cheats)

### Image classification extension filters (`0x30BE15`)

```
.ocx (0x30BE15)
.sys (0x30BE1A)
.dll (0x30BE1F)
```

Kernel drivers vs user DLLs vs OCX, sorted by name, case-insensitive helpers at `0x2544B0` family.

### System image anchors (right behind extension filters)

```
0x30BE24  \SystemRoot\System32\ntoskrnl.exe
0x30BE46  \SystemRoot\System32\securekernel.exe
0x30BE6C  \SystemRoot\System32\hvix64.exe
0x30BE8C  \SystemRoot\System32\hvax64.exe
```

Referenced by six record walkers (`0x1F17BA – 0x1F1EBB`, `0x252DC0 – 0x253125`, `0x254BF0 – 0x254C22`, `0x2569A0 – 0x256A54`, `0x25E140 – 0x25E41E`, `0x268C00 – 0x269DD7`). All validate records with an **obfuscated magic**:

```
(*(u32*)record ^ (id * -0x5163F18C)) == 0xE7AECCAE
```

Version compare at `record+4`, bounds at `+0x110` / `+0x114`.

---

## Part 6 — The handle strip — `ObRegisterCallbacks`

The piece everyone writes about.

### Registration

```c
OB_CALLBACK_REGISTRATION reg = {
    .Version                     = OB_FLT_REGISTRATION_VERSION,
    .OperationRegistrationCount  = 2,
    .Altitude                    = { L"<rotating number>" },
    .RegistrationContext         = NULL,
    .OperationRegistration       = ops,
};

OB_OPERATION_REGISTRATION ops[2] = {
    { PsProcessType,
      OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
      eac_pre_proc_handle, NULL },
    { PsThreadType,
      OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
      eac_pre_thread_handle, NULL },
};
```

The altitude is a float-as-string. EAC historically used `"321000"` (file-system AV range). Current builds have moved higher (into ~`36xxxx` range) to avoid colliding with newer gamer-focused AV products.

### The pre-op callback

```c
OB_PREOP_CALLBACK_STATUS eac_pre_proc_handle(PVOID ctx,
                                              POB_PRE_OPERATION_INFORMATION op)
{
    if (op->KernelHandle)
        return OB_PREOP_SUCCESS;                      // kernel, skip

    HANDLE targetPid = PsGetProcessId((PEPROCESS)op->Object);
    if (!eac_is_protected(targetPid))
        return OB_PREOP_SUCCESS;

    HANDLE opener = PsGetCurrentProcessId();
    if (opener == targetPid)
        return OB_PREOP_SUCCESS;                      // self

    if (eac_is_trusted_opener(opener))
        return OB_PREOP_SUCCESS;

    ACCESS_MASK* mask = (op->Operation == OB_OPERATION_HANDLE_CREATE)
        ? &op->Parameters->CreateHandleInformation.DesiredAccess
        : &op->Parameters->DuplicateHandleInformation.DesiredAccess;

    *mask &= ~(PROCESS_VM_READ | PROCESS_VM_WRITE
             | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD
             | PROCESS_DUP_HANDLE | PROCESS_SET_INFORMATION
             | PROCESS_SUSPEND_RESUME | PROCESS_TERMINATE);

    eac_telemetry_log(TEL_HANDLE_OPEN_ATTEMPT, opener);
    return OB_PREOP_SUCCESS;
}
```

### Non-obvious things about the strip

**1. It's in-place and total.** `OpenProcess` returns a handle that "works" but is neutered. `NtReadVirtualMemory` on it returns `ACCESS_DENIED`. This used to catch beginner cheat devs in 2018; everyone knows now.

**2. "Trusted opener" is authenticode cert-hash on the opener's image.** Renaming your tool to `EasyAntiCheat.exe` does not make it trusted.

**3. The strip is not a block — it's a detection.** EAC logs every attempt with opener pid and command line. Your cheat just got reported even though the handle "succeeded."

### Thread strip mask

```c
THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME
| THREAD_TERMINATE | THREAD_DIRECT_IMPERSONATION
| THREAD_SET_INFORMATION | THREAD_SET_THREAD_TOKEN
```

---

## Part 7 — Registry callback (`CmRegisterCallback`)

Current build watches:

```
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat         (self)
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS
HKLM\SYSTEM\CurrentControlSet\Control\CI                     (code integrity)
HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard
HKLM\SYSTEM\CurrentControlSet\Control\BootOptions
HKLM\SYSTEM\Setup                                            (safe-mode)
HKLM\BCD00000000                                             (BCD writes — mounted hive)
HKLM\SOFTWARE\Microsoft\Cryptography                         (MachineGuid)
```

Callback doesn't block — logs and flags. **BCD writes while Fortnite is live flag high severity** (that's where you'd toggle test-signing-mode).

Note on BCD: the persistent BCD lives on disk at `C:\Boot\BCD` (BIOS) or `EFI System Partition\EFI\Microsoft\Boot\BCD` (UEFI). `HKLM\BCD00000000` is a mount by `bcdedit` and similar tools. Direct file modification bypasses the registry callback but is catchable via NTFS filter / Measured Boot drift.

---

## Part 8 — ETW-TI subscription (critical current-build addition)

**The Microsoft-Windows-Threat-Intelligence ETW provider.** GUID: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`.

Kernel ETW provider that emits events **from inside ntoskrnl** for specific suspicious operations. Normally subscribable only by Protected Process Light (PPL) subscribers — EAC's driver qualifies via its WHQL cross-signature.

### What TI reports

Events when a process calls these from any thread:

| Operation | Event |
|-|-|
| `NtAllocateVirtualMemory` with exec protection | Virtual-allocation event |
| `NtProtectVirtualMemory` to change protection | **ProtectVirtualMemory event** |
| `NtMapViewOfSection` with exec | Mapped-view event |
| `NtReadVirtualMemory` cross-process | Cross-process-read event |
| `NtWriteVirtualMemory` cross-process | Cross-process-write event |
| `NtSetContextThread` cross-process | Context-set event |
| `NtQueueApcThread` cross-process | APC-queue event |
| `NtCreateThreadEx` cross-process | Remote-thread event |

Each event includes: **source process, target process, operation parameters, call stack.**

**EAC subscribes via the `EtwB` module** (see Part 10 manifest) and relays suspicious events into its own telemetry.

### Why this breaks spoofers

Direct evidence from the analyzed `desire_market` HWID spoof driver — strings include:

```
shm PATCH_PTE refused (EAC TI ProtectVm)
shm ALLOC refused (EAC TI AllocVm)
```

The spoofer uses shared-memory IPC (`\BaseNamedObjects\EacEmuShm`) for user-mode cheat code to request kernel operations. When the driver detects EAC's TI subscription is active, it **refuses to perform PATCH_PTE or ALLOC on behalf of user-mode**, because those would generate TI events the EAC agent relays.

**The spoofer loses capability when EAC is watching.** Real commercial spoofers either:
1. Load **before** EAC's ETW subscription registers (race at boot).
2. Use operations that don't trigger TI events (physical-memory PTE writes, direct MMIO).
3. Accept the restriction and operate in constrained ways.

### Other ETW providers EAC may subscribe to (plausible, not all confirmed)

| Provider | What it reveals |
|-|-|
| `Microsoft-Windows-Kernel-Process` | Process/thread/image events (cross-check against callbacks) |
| `Microsoft-Windows-Kernel-Registry` | Every registry read/write |
| `Microsoft-Windows-Kernel-Audit-API-Calls` | Audited sensitive API calls |
| `Microsoft-Windows-DNS-Client` | DNS queries made by any process |
| `Microsoft-Windows-Winsock-AFD` | Socket operations |
| `Microsoft-Windows-TCPIP` | TCP connection events |
| `Microsoft-Windows-Kernel-PnP` | Device plug/unplug |
| `Microsoft-Windows-USB-USBHUB3` | USB hub events |
| `Microsoft-Windows-Kernel-Image` | Image load events |
| `Microsoft-Windows-Services` | Service state changes |

---

## Part 9 — The VAD walker

This is how EAC catches manually-mapped cheats. The VAD tree is Windows' record of every committed region of virtual memory: every module, heap, `VirtualAlloc`. A manually-mapped DLL doesn't appear in `PEB->Ldr` (loaded outside `LoadLibrary`), but its allocation still shows as a VAD. The agent asks the driver for the VAD tree, compares against LDR, and anything executable in VAD but missing from LDR is suspect.

```c
NTSTATUS eac_walk_vad(PEPROCESS proc, OUT list)
{
    auto root = (PRTL_AVL_TABLE)((PUCHAR)proc + g_vadRootOffset);
    KeAcquireGuardedMutex(&proc->AddressCreationLock);
    for (auto vad = leftmost(root); vad; vad = inorder_next(vad)) {
        entry.base   = vad->StartingVpn << PAGE_SHIFT;
        entry.size   = (vad->EndingVpn - vad->StartingVpn + 1) << PAGE_SHIFT;
        entry.prot   = decode_protection(vad);
        entry.type   = decode_type(vad);               // Private/Mapped/Image
        if (entry.type == VadImageMap) {
            auto fo = get_file_object(vad);
            resolve_path(fo, entry.path);
        }
        append(list, entry);
    }
    KeReleaseGuardedMutex(&proc->AddressCreationLock);
    return STATUS_SUCCESS;
}
```

The `EPROCESS` `VadRoot` offset floats by Windows build. EAC resolves it dynamically — a small routine fingerprints the running kernel build at init and picks the offset from a table.

---

## Part 10 — The module manifest (plaintext tags)

Four-char plaintext tags with 16-byte blobs sitting right before them. Historically described as "one hash per module" but byte analysis of the new build shows the last few blobs contain x64 code bytes (e.g. `48 8b 00` MOV instructions), suggesting the "hashes" may actually be unrelated code tails bleeding into the tag block — this interpretation needs verification.

**Offset moved in Nov 20 2026 build**: `0x2CE200` (v3.2.0.0) → `0x303530` (current).

**Count 46 → 45 in current build** (`IZ` tag removed):

```
ClfC ClfI ClfO Clfs   CM11 CM13 CM16 CM17 CM20 CM25 CM26 CM27 CM28 CM29
CM31 CM32 CMAl CMCa CMSb CMSc   Cont Dcdd Devi EtwB   UdMI Uref UsbC
WDIs Wdog WfpC WfpS   ViMm Nhfs   Ntf0 NtFB NtFf NtFL   Obt b PcSi Uswd
Plcl ScCB SmBf SmMm SmMs
```

Note on casing: MinaMeow's post rendered the Ntf group as `NtfB NtfF NtfL`. Byte-level the tags are actually `NtFB NtFf NtFL` (capital F) across both her build and the new one. Her post had a transcription typo.

Prior build also had an `IZ` tag at the end — no longer present. One manifest module got retired or merged.

### Confident mappings

| Tag | What it is |
|-|-|
| `NtfL` | Load-image notify callback (the `.sys`/`.dll`/`.ocx` classifier at `0x30BE15`) |
| `NtfB` | Process-create notify (`PsSetCreateProcessNotifyRoutineEx`) |
| `NtfF` | Thread-create notify (`PsSetCreateThreadNotifyRoutine`) |
| `Ntf0` | Base notify infrastructure |
| `Obt` | `ObRegisterCallbacks` — handle protection for the game process |
| `CM11`..`CM32` | `CmRegisterCallback` handlers, **one variant per supported Windows build** |
| `CMAl` / `CMCa` / `CMSb` / `CMSc` | Registry operation families |
| `WfpC` / `WfpS` | Windows Filtering Platform callouts (C = callout layer, S = stream) |
| `ClfC` / `ClfI` / `ClfO` / `Clfs` | WFP classify callbacks (`In`/`Out`/`Stream`) |
| `Wdog` | Watchdog — self-checks |
| `Devi` / `UsbC` | Device tree + USB class — **DMA surface detection lives here** |
| `SmBf` | SMBIOS fingerprint |
| `ViMm` | Memory introspection |
| `Cont` / `Dcdd` | Container/message library |
| `EtwB` | ETW subscription (including TI) |

**Everything is per-module and feature-flagged** (section 2.e). The backend can hot-plug detection modules per game by setting bits in the request. The tags + hashes sit there in plaintext so the loader can do exactly that.

### Hook list by module tag

```
PsSetCreateProcessNotifyRoutineEx       <- NtfB
PsSetCreateThreadNotifyRoutine          <- NtfF
PsSetLoadImageNotifyRoutine             <- NtfL  (.sys/.dll/.ocx classifier @ 0x30BE15)
ObRegisterCallbacks                     <- Obt   (handle protection)
CmRegisterCallback(Ex)                  <- CM11..CM32 + CMAl/Ca/Sb/Sc
WFP callouts + classify in/out/stream   <- WfpC, WfpS, ClfC, ClfI, ClfO, Clfs
device/PnP + USB class                  <- Devi, UsbC
ETW                                     <- EtwB
watchdog                                <- Wdog
memory introspection                    <- ViMm
SMBIOS fingerprint                      <- SmBf
container/message lib                   <- Cont, Dcdd
```

### What's NOT present

- **No SSDT patching.**
- **No inline patching of anything.**
- **No IAT overwrites.**

Everything EAC does is **official callback interfaces + their own obfuscation on top.** PatchGuard-era clean.

---

## Part 11 — Scan worker — timer rotation

Runs on a 5-second loop, rotating through scans so no single tick is unboundedly expensive:

| `tick & 7` | Scan |
|-|-|
| 0 | VAD scan all protected processes |
| 1 | Thread enumeration |
| 2 | Handle enumeration |
| 3 | Module list diff vs previous |
| 4 | Self-integrity hash |
| 5 | Driver list scan |
| 6 | Callback-table dump |
| 7 | Cross-process hook heuristics |

Current builds added a second worker on a ~30s cadence doing an **environmental consistency pass**: pulls SMBIOS via WMI, compares to session-init cached values, flags drift. This is the spoofer drift detector.

---

## Part 12 — Self-anti-tamper

Driver verifies, periodically:

- Its own `.text` against a baked-in SHA256.
- That its callbacks are still registered (nobody unlinked the `PsSet*` entries).
- That the `ObCallbacks` table still contains its entry.
- That its device object is still present.

**Policy: DO NOT BSOD EVER if we can help it.** BSODing legit users because a weird-but-legal AV loaded in the wrong order would be a PR disaster. On self-hash mismatch the session is flagged at maximum severity. The ban eventually lands. The game does not crash.

### Driver self-sign (SELF_CHECK IOCTL)

The driver signs `(hash || nonce || bootCookie)` with an **embedded RSA private key** (CORRECTED Nov 20 2026 — prior "Ed25519" claim was wrong, see below). The signed blob gets forwarded to the backend, backend verifies with the corresponding public key. Fresh signatures per request (nonce + bootCookie) → no replay attacks.

**CORRECTION (Nov 20 2026)**: Byte-scan of the driver found 12 RSA SubjectPublicKeyInfo OID matches (`06 09 2A 86 48 86 F7 0D 01 01 01`) in `.rdata`. Zero Ed25519 OID matches (`06 03 2B 65 70`). The driver's signing path is RSA, not Ed25519. One `secp256r1` OID match at offset `0x303F8E` suggests ECDSA-P256 is also supported for alternate paths.

### Extracting the RSA signing material (hints)

For researchers:
- Cross-reference from the SELF_CHECK IOCTL handler.
- The driver contains 12 RSA public keys embedded in `.rdata` (first @ `0x2C035B6`). These are probably: multiple Epic session-attestation pubkeys (for rotation), Anti-Cheat Integrity CA root + intermediate pubkeys, rules.bin signing pubkey, and self-check verification pubkeys.
- The private signing key is loaded at runtime (not embedded as a plain key constant) — likely derived from the driver's TPM-sealed material or from a key the service hands over via the shared pipe.
- Sig is likely 256 bytes (RSA-2048) or 512 bytes (RSA-4096), not 64 bytes.

Even if the key material were extracted, the backend verifies the key matches the expected driver version. Rotating your signing key means Epic doesn't recognize your driver.

---

## Part 13 — PatchGuard / HVCI / DMA Protection context

What the driver has to coexist with.

### PatchGuard (Kernel Patch Protection)

Periodically verifies a set of kernel structures and `.text` regions. Modifications → bugcheck `CRITICAL_STRUCTURE_CORRUPTION` (0x109).

Protected (non-exhaustive):

| Structure | What's protected |
|-|-|
| `ntoskrnl.exe` `.text` | Inline hooks = bugcheck |
| `SSDT` | Patching = bugcheck |
| `IDT` | Hooking = bugcheck |
| `GDT` | Modifications = bugcheck |
| Syscall MSRs (`LSTAR`, etc.) | Rewriting = bugcheck |
| `PsInvertedFunctionTable` | Exception table |
| `KiServiceTable` | System call table |

**Everything EAC does is legal callback territory.** Any cheat driver has to coexist with EAC's callbacks without breaking the semantics EAC expects.

### HVCI (Hypervisor-Protected Code Integrity)

When enabled:
- Kernel pages marked executable must have a valid Microsoft-rooted signature.
- No kernel-mode `rwx` pages.
- Driver loads outside the Microsoft signing chain are rejected by the hypervisor.

**Implications for cheat drivers:**
- **BYOVD on an HVCI-enabled system is harder.** The vulnerable driver loads but arbitrary mapped code has to pass the hypervisor's integrity check too.
- `kdmapper` fails on HVCI-enabled systems unless specifically designed for HVCI bypass.
- EAC reports HVCI state as part of environmental fingerprint. Systems with HVCI off are a data point. **Turning HVCI off to run a cheat is itself a soft flag.**

### DMA Protection / Kernel DMA Protection

- UEFI firmware's `DMA Protection` setting.
- Windows' `Kernel DMA Protection` policy.
- VT-d / AMD-Vi (IOMMU) state.

When enabled, **PCIe devices can only DMA into memory the OS has explicitly mapped for them.** Breaks external DMA cheats cleanly.

EAC reports DMA Protection state. Systems with it off while a DMA cheat is active is a correlation data point.

### WDAC (Windows Defender Application Control)

Block list for vulnerable drivers, updated by Microsoft quarterly. EAC's `DRIVER_LIST` IOCTL returns each loaded driver's WDAC-match state.

Known block-listed vulnerable drivers (representative subset):

```
RTCore64.sys       (MSI Afterburner — arbitrary MSR R/W)
GPC-U64.sys        (GPC — physical memory R/W)
ATSZIO64.sys       (ATSZ — arbitrary MSR + I/O)
GDRV.sys           (Gigabyte — arbitrary I/O port)
DBUTIL_2_3.sys     (Dell — arbitrary MSR R/W)
WDLoadNTDriver.sys / WinRing0*.sys (arbitrary MSR)
AsIO.sys           (ASUS — arbitrary I/O port + MSR)
EneIo.sys          (ENE — physical memory read)
NalDrv.sys         (Intel Nahimic — arbitrary MSR)
AMDRyzenMasterDriver.sys  (MSR + memory primitives)
cpuz141.sys / cpuz149.sys  (MSR + physical memory)
GLCKIO2.sys        (GIGABYTE — primitive)
HwRwDrv.sys / HpqKbFiltr.sys  (various HP)
rzpnk.sys          (Razer Synapse — CVE-2022-27235-ish)
piddrv.sys / piddrv64.sys  (memory primitives)
```

**EAC flags on WDAC-match regardless of whether the signature is still valid.** Microsoft revokes faster than Epic's rules.bin updates.

---

## Part 14 — Image-B (the hidden ~1 MB code)

Separately worth calling out: the `0x37D350 – 0x46A616` region inside the "monster section" contains ~1 MB of plain code with 4054 pdata functions of its own. Zero cross-calls to `.text`. Only accessible via the cage and pointer tables.

This is where the most-sensitive routines live — the pin check implementation, the rules.bin decryptor, the ed25519 signing path. Researchers refer to it as "Image B."

Reversing Image B is essentially a separate subproject — its calling convention, its internal pointer table, its handler entries are all isolated from the "normal" code at `.text`.

---

## Part 15 — Correctness checklist

Everything above is a map. The specific values you MUST pull from your own binaries before treating as correct constants:

- [ ] Device name (random suffix)
- [ ] Symbolic link name
- [ ] `ObCallbacks` altitude string
- [ ] IOCTL XOR key
- [ ] Numeric IOCTL codes (after XOR)
- [ ] `ObCallback` strip mask for process AND thread
- [ ] Baked-in Epic pubkey location (for session_auth verification)
- [ ] Baked-in Epic pubkey location (for self-check signing)
- [ ] 45-tag module manifest content (46 in older builds; current is 45 after `IZ` removal — should match the list in Part 10 ± version-rotations)
- [ ] Handler feature-flag table layout
- [ ] Record walker magic constant
- [ ] Oodle blob offset + size
- [ ] Image B boundaries

All these rotate across builds. The architecture doesn't.

---

**Next:** [03 — User-mode launcher](03-user-mode-launcher.md)
