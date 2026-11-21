# 12 — Cheat detection surface — what EAC flags & how cheats work

The complete map of **what EAC detects** across every cheat category, **how each cheat architecture works** at the technical level, **real published exploits + BYOVD history**, and **the spoofability-vs-detection economics** of each cheat tier.

Consolidates detection surface + published exploits + advanced cheat architectures (hypervisor EPT page-splitting, SMM, UEFI bootkits, DMA hardware, GPU-executed cheats, process manipulation).

---

## Part 1 — Kernel driver indicators

What EAC's driver looks at in other drivers.

### Direct identification

| Check | Section in rules.bin |
|-|-|
| Image hash match | `0x30` |
| Name match | `0x31` |
| Signer cert thumbprint match | `0x32` |

### Environment

| Check | Flag |
|-|-|
| WDAC block-list state | high severity |
| Authenticode signature validity | moderate |
| Image path — non-standard paths (UNC `\\.\`, temp dirs, downloaded content) | moderate |
| Load reason — boot-bulk window vs ad-hoc late load | moderate |

### Manual-map indicators

- `PsLoadedModuleList` entry missing when image exists in `PsLoadedModuleList`'s backing allocation (unlink patterns)
- Driver image not present on disk at the recorded path
- Image lacks a valid PE header structure

### Known-bad signed drivers (BYOVD set)

Drivers with valid signatures containing exploitable primitives that cheat loaders abuse. **EAC's `DRIVER_LIST` IOCTL marks each loaded driver with its WDAC-match state.** Match → flag high severity.

Full catalog with capabilities + eras:

| Driver | Vendor | Primitive | Use era | Status |
|-|-|-|-|-|
| `RTCore64.sys` | MSI (Afterburner) | Arbitrary MSR R/W via IOCTL | 2018-2021 | WDAC blocked |
| `GDRV.sys` | Gigabyte (AppCenter) | Arbitrary port I/O + MSR | 2017-2021 | WDAC blocked |
| `DBUTIL_2_3.sys` | Dell (BIOS util) | Arbitrary MSR R/W (CVE assigned) | 2020-2022 | WDAC blocked |
| `ATSZIO64.sys` | ASUS | Arbitrary MSR + I/O | 2019-2022 | WDAC blocked |
| `AsIO.sys` / `AsIO2.sys` / `AsIO3.sys` | ASUS | Arbitrary port I/O | long history | WDAC blocked versions-specific |
| `EneIo.sys` | ENE Technology | Physical memory R/W | 2018-2022 | WDAC blocked |
| `NalDrv.sys` | Nahimic (Intel audio) | Arbitrary MSR | 2019-2022 | WDAC blocked |
| `AMDRyzenMasterDriver.sys` | AMD (Ryzen Master) | MSR + memory primitives | 2020-2023 | WDAC blocked |
| `cpuz141.sys` / `cpuz149.sys` | CPUID (CPU-Z) | MSR R/W + physical memory | long history | WDAC blocked variants |
| `GLCKIO2.sys` | GIGABYTE (G Lock) | Primitive | 2021-2023 | WDAC blocked |
| `WDLoadNTDriver.sys` / `WinRing0.sys` | WinRing0 (open source) | MSR + I/O | ancient-ish | WDAC blocks versions; new variants rotate |
| `HwRwDrv.sys` / `HpqKbFiltr.sys` | various HP | Various | 2019-2022 | WDAC blocked |
| `piddrv.sys` / `piddrv64.sys` | various | Memory primitives | 2020+ | WDAC blocked variants |
| `rzpnk.sys` | Razer Synapse | Arbitrary primitive (CVE-2022-27235-ish) | 2021-2023 | WDAC blocked |

### How to find new BYOVDs (defender perspective)

- **DeviceTree** on a loaded system — enumerate every driver and check for CreateFile-accessible device objects.
- **IDA plugin to spot vulnerable primitive functions** — IOCTL handlers that call `MmMapIoSpace`, `ZwReadVirtualMemory`, raw MSR intrinsics.
- **Static scan of common WHQL vendor drivers** — any driver that exposes physical memory read/write via IOCTL is a candidate.
- **loldrivers.io** — community catalog of known-vulnerable drivers.

### iqvw64e specifics (the kdmapper-bundled Intel driver)

The Intel Ethernet Diagnostics driver (`iqvw64e.sys`) is the specific BYOVD bundled with kdmapper itself. Confirmed fingerprints (via KDStealer thread 781974):

| Field | Value |
|-|-|
| PE timestamp | `0x5284EAC3` |
| Device object | `\Device\Nal` |
| IOCTL | `0x80862007` |
| Copy command format | `0x33` |

Status in current blocklists: **almost certainly blocked** by current rules.bin driver sections (per community consensus — Kepiteo thread 781598). Using `kdmapper` with its stock bundled `iqvw64e.sys` against current-build Fortnite EAC will flag within session.

### KDStealer — adjacent threat (xvorost9, Nov 2026)

A third-party tool (not from EAC) that:
- Loads via `kdmapper` to monitor other `kdmapper` operations.
- Hooks Intel driver's device control.
- Dumps any driver mapped through it to `C:\mapped_driver_N.bin`.
- Idea from KDStinker (2019).

**Why this matters for cheat developers:** if any software on the user's machine includes KDStealer (or similar), their kdmapper'd cheat driver can be captured to disk by a third party. Not an EAC detection — a parallel ecosystem threat.

### Hypervisor-based cheat detection

A type-2 or stealth type-1 hypervisor that reads game memory from the host. Historically theorized to be detected by:
- Anti-VM signals ([08 protection stack](08-protection-stack.md))
- APIC ID topology anomalies
- CPUID timing baseline deviation *(disputed — see note below)*
- CPUID leaf 0x16 (frequency) returning unexpected values
- rdtsc timing of operations that would cause vmexits under a hypervisor *(disputed — see note below)*

**Disputed / historical — adversemiller correction (thread 781548, see [14 Part 10.5](14-blind-spots.md)):** community teardown reports that **EAC does NOT actually care about VM timing** in the current build — KVM-based paths (Nika-Read-Only, AutoVirt) are viable and not flagged by timing baselines. Treat the CPUID-timing / rdtsc-vmexit-timing entries above as legacy / theoretical rather than active signals until byte evidence confirms otherwise.

A well-written stealth hypervisor can defeat most individually. EAC's answer: raise to "suspicious" rather than "fatal" and let server-side ML correlate over multiple sessions.

---

## Part 1.5 — Launcher-wrapper explicit tool blacklist (Nov 20 2026)

The launcher wrapper (`EasyAntiCheat.packed (1).dll`, 36 MB, signed by Epic) performs **pre-flight tool/driver detection BEFORE the game launches**. All entries below are literal byte-strings extracted from the Nov 20 2026 build:

### Anti-cheat conflicts (refuses to launch alongside)

```
BattlEye                    (Fortnite's historical AC before 2021)
ACE-BASE                    (ACE anticheat — Chinese games)
EchoAC                      (Chinese anticheat)
MyhProt2                    (anticheat variant)
```

### Cheat tools (literal process-name match)

```
Cheat Engine
Xenos Injector              (public DLL injector)
HideToolz                   (rootkit hider)
Global Hack                 (specific cheat name/family)
Iuebesks                    (short name — possibly a specific cheat variant ID)
```

### Reverse-engineering / debug tools

```
WinDbg
LiveKD
PCHunter64
PowerTool X64
WIN64AST                    (Chinese RE suite — "Windows 64-bit All Security Tools")
Windows Kernel Explorer
BlEM, CAIs, WinD64          (short-name identifiers for specific tools)
TermDD
```

### System / fingerprint / BYOVD-source tools

```
CPU-Z                       (source of cpuz141.sys / cpuz149.sys BYOVDs)
WinIO                       (BYOVD — kernel I/O driver)
RWDrv                       (BYOVD — read/write driver)
WinPmem                     (memory-forensics driver; usable as memory dumper)
WinDivert                   (packet filter driver; usable for network cheats)
```

### Streaming / overlays

```
Moonlight Engine            (NVIDIA GameStream FOSS clone — potential overlay surface)
```

### Specific exploit variant fingerprints (code-pattern matches, not process names)

```
"SMEP Bypass (B)"
"SMEP Bypass (C)"
```

EAC has specific code-pattern detection for known SMEP (Supervisor Mode Execution Prevention) bypass variants. Variants (A, D, etc.) likely exist in the fingerprint set but aren't visible as plain strings.

### Possible cheat-family / variant ID codes

Short identifiers also present in the blacklist region:

```
B957, S10, S11, S12, S13, N11, N14, XT15, UZF1, 2RT5, 99fT,
2r@W, 01DB42, W2U8_ERROR
```

These look like internal identifier codes for specific detected cheat families or variants, each mapping to a signature in the backend's correlation database.

### Impact

A classic "rename Cheat Engine to notcheat.exe" bypass **no longer works** against this literal-name list. Need:
- Remove the original from PATH and launched-process lists.
- Don't have any of the listed tools mapped into memory.
- Kernel drivers with these names in their `.rdata` or filename also fail.

The blacklist is additive to EAC's rules.bin dynamic blacklist. The launcher refuses to spawn the game before EAC's driver/scanner even get a chance to run their scans.

## Part 1.6 — Launcher-wrapper new pre-flight error codes (Nov 20 2026)

Full `launcher_error.*` taxonomy extracted from packed.dll strings in the current build:

```
error_already_running                    error_patched
error_another_launcher                   error_patched_boot_loader  (NEW)
error_bad_exe_format                     error_process_crash
error_bitset_64                          error_safe_mode
error_case_sensitive_game_path  (NEW)    error_service_update_timeout
error_certificate_validation             error_set_environment_variables
error_configuration_validation           error_start
error_debugger                           error_uncpath_forbidden
error_deleted_driver                     error_unknown_game
error_disk_space                         error_unknown_process
error_dotlocal                  (NEW)    error_unrecognized_blacklisted_driver (NEW)
error_driver_handle                      error_unsigned_driver
error_driver_verifier_enabled   (NEW)    error_unsupported_arm64    (NEW)
error_dtrace_enabled            (NEW)    error_win10_22h2_required  (NEW)
error_failed_path_query                  success_loaded
error_failed_to_execute
error_forbidden_driver
error_forbidden_tool
error_game_running
error_game_security_violation
error_generic / error_generic_ex
error_incompatible_driver_version
error_incompatible_service
error_instance_count_limit
error_kernel_debug
error_kernel_dse
error_kernel_modified            (NEW — PatchGuard-equivalent integrity check)
error_memory / error_memory_ex
```

`setup_error.*`:
```
error_encrypted (EFS / ransomware setup folder)
error_not_installed
error_rights (admin required)
error_service_ex
```

`game_error.*`:
```
error_missing_secure_core_feature  (NEW — Windows 11 Secure-Core PC requirement)
error_tool_forbidden
error_virtual (VM detected)
```

### Specific new detection behaviors (Nov 20 2026)

| Error key | What triggers it |
|-|-|
| `error_dtrace_enabled` | Windows DTrace (Dynamic Tracing) installed/enabled. DTrace is a newer Microsoft-provided tracing framework — EAC blocks it to prevent trace-based cheat analysis. |
| `error_dotlocal` | A `.local` directory next to an EXE forces Windows to resolve DLLs from that directory first — classic DLL hijack vector. EAC detects and blocks. |
| `error_patched_boot_loader` | `bootmgr.efi` / `winload.efi` integrity measurement failed — detects BlackLotus-class UEFI bootkits. Error string: `"Patched Windows boot loader detected. (Kernel Patch Protection disabled)"` |
| `error_missing_secure_core_feature` | Windows 11 Secure-Core PC features (HVCI, VBS, DMA Protection) required on supported hardware. Future-looking requirement. |
| `error_unsupported_arm64` | ARM64 Windows explicitly not supported by EAC. |
| `error_win10_22h2_required` | Minimum supported OS is Windows 10 22H2. Older builds refused. |
| `error_driver_verifier_enabled` | Driver Verifier running → block (EAC presumably has compatibility issues with Verifier-generated artificial faults, or simply treats it as a "cheat development environment" signal). |
| `error_unrecognized_blacklisted_driver` | Generic bucket for drivers detected as "cheat-like" by heuristics rather than specific name match. |

### Specific driver-detection prose strings

```
"The driver {0} is loaded but its file is missing. Please reboot your
 system to unload the driver."
     → Detects kdmapper-dropped drivers (loaded but no on-disk file).

"The driver {0} is loaded without valid signature. Please reboot your
 system to unload the driver."
     → Detects manually-mapped / self-signed cheat drivers in kernel memory.
```

---

## Part 2 — Injection indicators

What EAC looks at for cheat DLL injection:

| Indicator | Source |
|-|-|
| **New thread in protected process with start address not in any module** | Shellcode — flag hard |
| **New thread with start address not in whitelisted module** | Flag |
| **VAD entry mapped as Image not in `PEB->Ldr`** | Unlinked module — flag |
| **VAD entry with executable + private protection** | Raw code memory — flag |
| **Transient-executable regions** (R/W at snapshot T, R/X at T+2s) | Runtime unpacking — flag |
| **APC queue entries from non-whitelisted senders** | Current-build inspects `ETHREAD->Tcb.ApcState` for suspicious queue contents |
| **Reflective loader stubs** | Characteristic byte patterns — rules.bin pattern sections catch |
| **DLL side-loading / proxy DLLs** | Current-build EAC tracks dependency tree + flags system DLL resolved from non-system path |
| **Thread hijacking** | `SetThreadContext` from non-whitelisted caller → thread strip mask + handle open log |
| **Manual-map shellcode in the game process's own allocations** | Pattern matched |

### The common 2026 cheat pattern

Manual-mapping a cheat DLL into the game process via a kernel-mode writer, bypassing the ObCallback strip. This leaves:
- A VAD entry (type `Image` if polite, type `Private` if not)
- No LDR entry
- Thread(s) with start addresses in the mapped region OR a hijacked existing thread
- IAT entries resolved manually

**The VAD walker catches this on the first scan tick after the map.**

### Cheat counter-measures and EAC's counter

| Cheat approach | EAC response |
|-|-|
| Map as RW initially, flip to RX momentarily to run | Transient executable detector catches the flip |
| Use existing executable VADs (hollowing a legit module) | Integrity timer catches the `.text` hash change |
| Run cheat code from pure data references with ROP | Expensive, slow, limited — mostly research territory |

---

## Part 2.5 — Function-unwind / call-stack detection + frame-counting

Per **alexanderyy** (UC legend, trust 78 — thread 778933):

> They are checking call chain from specific functions, if a frame leaves a specified module within x amount of frames they know it is hooked.

And per **Reubinator13** (UC legend, thread 781256):

> you need the stack to be 1:1 flawless (function unwind detection)

**EAC does call-chain / frame-counting detection on external invokers AND on hooked internal calls.** Two specific mechanisms:

### Mechanism 1: Frame-counting from instrumented functions

EAC places call-stack-capturing probes at specific points inside the game. From those probes, it walks the stack upward. If a frame **leaves a specified module within X frames** of the probe, that's an anomaly — it means the natural call chain was redirected outside the expected module (e.g. your external invoker's code sits outside the game's modules).

Example: EAC probes a specific UE function. It expects the call stack to go `GameCode → GameCode → GameCode → ...` within the game's modules. If frame-2 is outside any legit module, the call chain leaked → hooked.

### Mechanism 2: Function-unwind detection

EAC walks the call stack via `RtlCaptureStackBackTrace` or similar unwind APIs at specific instrumented points inside the game process. Stack frames that don't correspond to function-unwind-data-valid return addresses → flag.

This is why the "external invoker to call internal UFUNCTIONs" approach has a limited lifespan — the stack walk catches it even if the data read/write succeeds.

### Requirements for a working call-stack spoofer against Fortnite EAC

- **Must be 1:1 flawless** — the stack must look exactly like a legit UE internal invocation.
- All frames must be within whitelisted game modules.
- Unwind data must be consistent — return addresses must correspond to real function prologues.
- RSP alignment must match what a natural call chain would produce.
- Need to replicate: return addresses, RBP frames, unwind data consistency, stack pointer alignment.

Simple "gadget-based" call spoofers don't work against current-build EAC.

---

## Part 3 — Hooking patterns

| Hook type | Detection |
|-|-|
| **Inline hooks in system DLL `.text`** | Direct byte diff via hook detector against bundled baselines |
| **IAT hooks in game modules** | Periodic export-pointer re-resolve checks |
| **EAT hooks** | Same mechanism from the other direction |
| **`KiUserCallbackDispatcher` hijack** | Current-build checks dispatcher's first few bytes against expected prologue |
| **Vectored exception handlers registered by non-whitelisted callers** | `AddVectoredExceptionHandler` leaves a global list the agent walks |
| **HWBP-based hooks** | `Dr0..Dr3` inspection via `GetThreadContext` |
| **Instrumentation callback hooks** | `ProcessInstrumentationCallback` nonzero without EAC's knowledge → flag |
| **PT (Processor Trace) / LBR abuse** | Current-build queries MSR `0x1D9` (`DEBUGCTL`) via the driver to detect LBR active unexpectedly |

**Why "hook briefly" has a shelf life:** The hook detector runs on a ~2-5 second rotation. A cheat that hooks for 500ms, does its thing, unhooks for 2 seconds has **maybe a 25% chance per cycle of being caught**. Over a match's ticks that's effectively guaranteed.

---

## Part 4 — Process manipulation technique catalog

Each has been used in cheat deployment. EAC's countermeasures are current-build state.

### 4.1 — Process hollowing

1. `CreateProcess` in `CREATE_SUSPENDED`.
2. `NtUnmapViewOfSection` on the suspended process's image base.
3. `VirtualAllocEx` at the same base.
4. `WriteProcessMemory` the cheat image.
5. Set new entry point via `SetThreadContext`.
6. `ResumeThread`.

**Catch:** PE header at base, ImageFileName in EPROCESS, LDR entries all become inconsistent → VAD walker + integrity scan catches.

### 4.2 — Process Doppelgänging

1. Use NTFS Transactional File System (TxF) to create a transient view of a legitimate PE.
2. Commit a modified version to the transactional view.
3. `NtCreateSection` from the transactional file handle.
4. Roll back the transaction.
5. `NtCreateProcess` from the section.

Effect: process on disk appears legitimate (modification was rolled back), but running process's memory is modified PE.

**Catch:** process memory hash doesn't match on-disk file hash → integrity check catches.

### 4.3 — Process Herpaderping

1. Open a legitimate PE file.
2. Create a section from it.
3. Modify the file on disk (while section is referenced).
4. Create process from the section.

Effect: on-disk file modified post-process-creation; running process's memory is pre-modification view.

**Catch:** file-on-disk change observed via NTFS filter / MFT timestamp drift.

### 4.4 — Phantom DLL Hollowing (Forrest Orr, 2020)

1. Allocate executable memory not backed by a file.
2. Load a legitimate signed module into that memory.
3. Modify the module's code sections after load.

**Catch:** no file-backing → appears in VAD as `VadPrivate` with executable protection → caught by shellcode-region detection.

### 4.5 — Early Bird APC injection

1. Create process in `CREATE_SUSPENDED`.
2. Queue an APC to the initial thread.
3. Resume thread → APC runs before any legitimate code.

**Catch:** current EAC's ETHREAD.Tcb.ApcState inspection + ETW-TI `NtQueueApcThread` event.

### 4.6 — Atom Bombing

1. Write shellcode into the global atom table.
2. Trigger `NtQueueApcThread` with `GlobalGetAtomName` as the APC function.
3. Shellcode executes in target process.

**Catch:** ETW-TI + current ObCallbacks on APC-related handles.

### 4.7 — COM Hijacking (per-user)

1. Register a per-user COM CLSID that masquerades as a frequently-loaded system component.
2. Target process loads your DLL via COM.

**Catch:** EAC's load-image notify callback sees the DLL's path (non-system) and flags via rules.bin's path-suffix section.

### 4.8 — Shadow-mapping via sections (NtMapViewOfSection + SEC_IMAGE)

1. Create a section with `SEC_IMAGE` flag from a legit file.
2. Map into own process.
3. Modify the section's backing.

**Catch:** EAC's integrity-timer hash comparison. Section-level modifications still produce different in-memory hashes.

### 4.9 — Thread hijacking

1. Open existing thread with `THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT`.
2. `SuspendThread`.
3. `GetThreadContext`.
4. Save current RIP.
5. Set RIP to jump to cheat code.
6. `SetThreadContext` + `ResumeThread`.

**Catch:** `THREAD_SET_CONTEXT` stripped by ObCallbacks on protected process.

### 4.10 — Ghost writing

Allocate executable memory in target, write code, but never create a thread. Rely on a legitimate thread to hit a specific function pointer you've overwritten.

**Catch:** write-to-target requires PROCESS_VM_WRITE → ObCallback strip.

### 4.11 — Memory-mapped file injection

1. `CreateFileMapping` with cheat code.
2. `NtMapViewOfSection` on target process's handle.

**Catch:** target process handle requires PROCESS_VM_OPERATION → ObCallback strip.

### 4.12 — Reflective DLL injection

1. Allocate executable memory in target.
2. Write a shellcode loader + DLL image to the memory.
3. Create thread at the loader's entry.
4. Loader parses DLL headers, fixes imports, calls DLL entry.

**Catch:** VAD-walker catches `VadPrivate` with executable protection; no LDR entry.

### 4.13 — Manual DLL mapping (ulfrisk's MapLibrary-style)

Mimics LoadLibrary without going through LDR:
1. Allocate memory for DLL in target.
2. Copy PE to memory.
3. Resolve imports by walking kernel-known IAT.
4. Fix relocations.
5. Call `DllMain(DLL_PROCESS_ATTACH)`.

Variation: inject via a kernel-mode writer, bypassing ObCallback strip.

**Catch:** VAD-walker sees Image-type VAD with no LDR entry → "unlinked image" flag.

### 4.14 — ETW manipulation to bypass TI

Advanced: register as a PPL subscriber to the TI provider, consume events before EAC does, selectively drop events relating to the cheat's own operations.

**Catch:** PPL requires specific signing; cheat doesn't have it. Attempts to register without proper signing fail.

---

## Part 5 — Hypervisor-based cheats with EPT page splitting

The gold standard of cheat stealth. Expensive to develop, hard to detect, limited operator population.

### 5.1 — What a type-1 cheat hypervisor is

A thin hypervisor that:
- Installs before or alongside Windows.
- Runs the Windows kernel as a VMX guest (Intel) or SVM guest (AMD).
- Can intercept specific CPU events via VM-exits.
- Uses EPT (Extended Page Tables on Intel) / NPT (Nested Page Tables on AMD) to control what physical memory the guest sees.

### 5.2 — EPT / NPT basics

Two-level translation:
- **Guest virtual → Guest physical** (controlled by Windows).
- **Guest physical → Host physical** (controlled by the hypervisor via EPT/NPT).

### 5.3 — Page-splitting trick

The specific technique commercial stealth hypervisors use:

```
For a given guest physical page P:
- When the guest ACCESSES P for READ:    map to host page P' (modified)
- When the guest ACCESSES P for EXECUTE: map to host page P (original)
```

Implemented via EPT permission bits + VM-exit on permission violations:
1. Mark page as execute-only in EPT.
2. On read access → VM-exit → swap EPT mapping to the modified copy, make it read-only.
3. On execute access → VM-exit → swap back to the original executable copy.
4. Optional: single-step with MTF (Monitor Trap Flag) after each access to reset the trap.

**Effect:** when EAC reads a page to verify its hash, EAC sees the **modified** version (byte-identical to what EAC expects). When the CPU executes that page, it sees the **original** executable code.

### 5.4 — Classic page-splitting use case

The cheat wants to hook `MmCopyVirtualMemory` to return fake data when EAC's driver tries to read game memory:

1. Cheat hypervisor identifies the physical page containing `MmCopyVirtualMemory`'s entry.
2. Creates two copies of the page:
   - **Read view** — unmodified, matches EAC's expected hash.
   - **Execute view** — modified with a jump at the function prologue to the cheat's hook.
3. EPT configured: read access → read view; execute access → execute view.
4. EAC's integrity scan sees unmodified bytes → hash matches expected.
5. CPU executes MmCopyVirtualMemory → sees modified bytes → jumps to hook → hook returns fake data.

### 5.5 — What EAC can observe

Historically theorized detection surface — MSR state primarily, with timing as a secondary (now disputed) axis:

- **CPUID timing** *(disputed)* — VM-exits on CPUID increase its cost; timing baseline *was* theorized to flag. Per adversemiller (thread 781548, [14 Part 10.5](14-blind-spots.md)) the current build **does NOT care about VM timing** — KVM paths (Nika-Read-Only, AutoVirt) run without being flagged on this axis.
- **MSR state anomalies** — some hypervisors leak state in MSRs the guest can read.
- **APIC ID topology** inconsistencies.
- **TSC-adjust MSR** nonzero when hypervisor adjusts TSC.
- **LBR / Intel PT state** — `IA32_DEBUGCTL` MSR observable.
- **PT-mode checks** — RDMSR patterns that vmexit return data that doesn't match bare-metal.

Current 2026 state: a well-written stealth hypervisor is **not caught by individual-session analysis**. MSR / APIC state and behavioral ML correlating across sessions are the real detection — timing alone is not, per the adversemiller correction.

### 5.6 — Public hypervisor projects

- **SimpleVisor (Satoshi Tanda)** — educational hypervisor. Base for many stealth hypervisor cheats. Repo-public, well-commented.
- **HyperDbg (wbenny)** — hypervisor-based debugger. Not a cheat tool but the primitives are directly applicable.
- **DdiMon (Satoshi Tanda)** — hypervisor-based device driver interface monitor. Teaches the EPT-based function-hooking primitive.
- **Daax Rynd's Intel PT research** — reading game state via PT without touching memory.

### 5.7 — Hypervisor install paths

**Boot driver (`ServiceGroup = Boot`):**
- Loads early in boot sequence.
- Before PatchGuard initialization.
- Visible as a loaded driver → EAC's `DRIVER_LIST` sees it → flagged.

**Via BYOVD, late-load:**
- Uses a vulnerable signed driver to map the hypervisor into kernel memory.
- Harder to transition cleanly — Windows may already be in a state the hypervisor's entry handler doesn't gracefully take over.
- Not visible in LDR (manual-mapped).

**Via UEFI bootkit:**
- Runs before Windows boots.
- Loads a hypervisor that Windows boots under.
- From Windows' perspective, there's always been a hypervisor.

---

## Part 6 — SMM (System Management Mode) cheats

### 6.1 — What SMM is

- **Ring -2** on x86 (lower privilege than hypervisor).
- Entered via SMI (System Management Interrupt).
- CPU saves state, jumps to SMM handler in SMRAM.
- SMRAM is physically isolated — OS/hypervisor can't touch it.
- Returns via RSM instruction.

### 6.2 — SMM as a cheat primitive

**Capabilities:**
- Read any physical memory (including kernel + hypervisor memory).
- Write any physical memory (within SMM security constraints).
- Not visible from OS or hypervisor.
- Not interruptible by PatchGuard, HVCI, or any OS-level anti-cheat.

**Install requirements:**
- Firmware vulnerability allowing writes to SMRAM.
- Persistence requires either UEFI variable-based payload loader OR direct SPI flash modification.

### 6.3 — Published SMM attack research

- "Attacking SMM Memory via Intel CPU Cache Poisoning" (Duflot et al., 2009).
- ThunderStrike (Trammell Hudson, 2015) — Mac firmware attack with SMM relevance.
- Thinkpwn (2016) — Lenovo laptop SMM exploit.
- Intel SA-00086 (2017) — ME CSME vulnerabilities interacting with SMM boundary.
- CVE-2019-0090 / "Downgrade" — Intel converged security engine issues.

### 6.4 — Why SMM cheats are rare

- **Firmware exploit discovery is expensive.** Each OEM's SMM is different.
- **Persistence across firmware updates is hard.** Every BIOS update potentially closes the vulnerability.
- **No standard interface** — cheat code has to know specific firmware's SMM layout.
- **Not needed for most cheat markets** — DMA cheats at $500-2000/wk give similar stealth with much lower engineering cost.

End state: SMM cheats exist in nation-state APT toolkits, not consumer cheat markets.

### 6.5 — What EAC can observe

Essentially nothing from the OS side. SMM is invisible.

**Indirect signals:**
- **SMI count anomalies** — on some CPUs, SMI entry/exit is counted in a non-privileged MSR.
- **Firmware version + vendor** via SMBIOS.
- **TPM PCR 0-1** — measures firmware. SMM-cheat-modified firmware changes these values.
- **Secure Boot DB/DBX hashes** — if firmware is in a non-standard state, attestation fails.

TPM-based attestation is Windows' main defense against SMM-level cheats.

---

## Part 7 — UEFI bootkits

### 7.1 — The UEFI boot sequence

1. Firmware (UEFI) runs.
2. UEFI loads Windows Boot Manager (bootmgr.efi) from EFI System Partition.
3. Boot Manager loads Windows OS Loader (winload.efi).
4. OS Loader loads ntoskrnl + boot drivers.
5. Kernel starts.
6. Services start.
7. User logon.

**UEFI bootkits intercept somewhere in 2-4** — before step 4's kernel integrity verification.

### 7.2 — Bootkit architecture for cheat loading

**Stage 1 — ESP payload:**
- Modified bootmgr.efi OR additional UEFI driver loaded via `BootOrder`.
- Signed to pass Secure Boot (if possible — requires private key access OR CVE like Baton Drop).

**Stage 2 — Transition hook:**
- Hooks ExitBootServices or similar transition point.

**Stage 3 — Kernel memory writer:**
- After kernel loads, modifies kernel memory to install the cheat driver's entry points.
- Pre-empts PatchGuard initialization.

**Stage 4 — Runtime cheat driver:**
- Lives in kernel memory, callbacks wired.
- Operates as kernel-mode cheat.

### 7.3 — BlackLotus (2023) — publicly documented

First publicly-disclosed UEFI bootkit that bypassed Secure Boot (via CVE-2022-21894 — the "Baton Drop" vulnerability).

- Bootkit signed with legit Microsoft-signed vulnerable bootmgr that BlackLotus chain-loaded.
- Secure Boot verifies the signed bootmgr → bootkit chain-loads from it → runs with Secure Boot's blessing.
- Post-boot, patches winload.efi and kernel in memory.

Relevance to cheats:
- **Can install a cheat driver that persists across OS reinstalls** (lives in ESP, not NTFS).
- **Can disable HVCI selectively** → unsigned cheat drivers run.
- **Pre-dates EAC's service start** → EAC's baseline captures the bootkit's effects as "normal."

Not publicly sold as cheat — forum-level sales at $5000+ per copy.

### 7.4 — CosmicStrand

Another UEFI implant, more stealthy than BlackLotus (doesn't touch bootmgr; lives in SMM via vulnerable firmware).

### 7.5 — How EAC handles bootkits

Current EAC:
- Reads TPM PCR values — bootkits modify PCR 4/5/7/8, drift detectable.
- Reports Secure Boot state — disabled flags.
- Reports HVCI state — disabled flags.
- Reports WBCL (Measured Boot Log) via the `BootEfiActiveSec` surface.

So while bootkits can run cheat code, they produce **massive HWID anomalies** that correlate against the ban hash. End-state: works for a while, then HWID ban; next machine requires fresh bootkit install.

### 7.6 — Persistence economics

- Bootkit requires physical install (one-time admin access).
- Survives OS reinstall (lives in ESP).
- Survives drive wipe if not specifically targeting ESP.
- Removed by firmware reflash or explicit ESP mount + cleanup + Secure Boot DBX refresh.

---

## Part 8 — DMA cheats — deep implementation

### 8.1 — Hardware tiers

| Tier | Device | Approximate price (2026) | Capability |
|-|-|-|-|
| Entry | PCILeech + Screamer M.2 | $200-400 | Basic memory R/W, limited bandwidth |
| Mid | Spartan Edge + custom firmware | $500-1000 | Faster R/W, configurable PCI identity |
| High | Custom FPGA development boards | $1500-5000 | Full PCI identity spoofing, high bandwidth, multiple channels |
| Elite | Purpose-built DMA rigs with KVM integration | $5000-15000 | Everything + capture card for second-PC setups |

### 8.2 — How they work

PCIe FPGA cards are secondary PCs on the PCIe bus:
1. Plug into M.2 or PCIe slot on game PC.
2. Second PC (control PC) talks to the FPGA via USB or secondary network.
3. FPGA issues PCIe memory read/write transactions to game PC's memory.
4. Transactions bypass CPU → bypass any CPU-only anti-cheat.
5. Game state read by control PC; aim/ESP decisions computed there; commands sent back via USB input injector (kmbox-style) to game PC.

### 8.3 — PCI config space of a DMA card

**Raw FPGA (unspoofed):**
- Vendor ID: Xilinx `0x10EE`, Lattice `0x1204`, or Altera `0x1172`.
- Device ID: FPGA family + part number.
- Class: often `0x058000` (Other Memory Controller).

**Spoofed to look like NVMe SSD:**
- Vendor ID: Samsung `0x144D`, WD `0x15B7`, etc.
- Device ID: specific SSD model.
- Class: `0x010802` (NVMe controller).
- Capability list: NVMe-mandatory capabilities.

### 8.4 — What EAC observes

- **PCI config space enumeration** via `Devi` module.
- For each device, reads capability list.
- Compares against "what capabilities would this device have if real."

Specific anomalies:
- NVMe spoof without MSI-X properly configured → flag.
- NVMe spoof with unusual BAR sizing → flag.
- Multiple identical subsystem IDs across devices → flag.

Behavioral anomalies:
- The "NVMe" never shows up as a block device in Windows → flag.

### 8.5 — Bandwidth considerations

PCIe Gen 3 x1 — approximately 985 MB/s theoretical, ~700 MB/s practical.

For a DMA cheat reading game state:
- Fortnite game state fits in ~50-200 MB of reads per second.
- Entry-level Screamer (PCIe x1): sufficient but slow.
- M.2 PCIe Gen 3 x4: comfortable headroom.

### 8.6 — IOMMU / Kernel DMA Protection

When enabled, every DMA transaction goes through address translation.

**Attacker response:**
- Install DMA card in a slot that's not IOMMU-protected (cold-plug internal PCIe slot).
- Convince user to disable IOMMU in BIOS.
- Use firmware vulnerabilities to disable DMA remapping.

### 8.7 — MemProcFS + PCILeech

Specific publicly-available tooling: **MemProcFS** (ulfrisk).

What it is: an open-source tool that uses DMA hardware to present remote PC memory as a filesystem on the control PC.

Technical flow:
1. Install Screamer-class DMA hardware in game PC.
2. Run MemProcFS on control PC.
3. MemProcFS configures FPGA to issue PCIe memory reads.
4. Memory is enumerated: every process, every thread, every module.
5. Data is accessible as files: `/proc/4567/memory.dmp` is process 4567's memory, readable as image.

Trivial to write a user-mode program on control PC that opens `/proc/<game_pid>/memory.dmp`, parses game structures, and outputs ESP coordinates.

### 8.8 — Prominent DMA vendor history

Not endorsements — names that come up in RE context:

- **PCILeech** — ulfrisk / Ulf Frisk's academic DMA research tool. Foundational.
- **MemProcFS** — ulfrisk's follow-up. Works with Screamer hardware.
- **Screamer PCIe** — commercial hardware based on PCILeech.
- **FT601** chip — common USB 3.0 interface for DMA rigs.
- Various Chinese FPGA board projects — rotate as markets shift.

---

## Part 9 — Kmbox / hardware input injection

### 9.1 — What kmbox is

A device that sits between your mouse and your game PC. Receives mouse input over USB, can inject arbitrary USB HID events into the game PC's USB stack.

Used for:
- Recoil compensation.
- Aim assist (second PC reads game state via DMA, kmbox injects aim corrections).
- Anti-detection — events look like normal mouse events because they come through actual USB HID path.

### 9.2 — Detection surface

- **USB device enumeration** sees the kmbox as a HID device. VID/PID is a fingerprint.
- **HID report descriptor hash** — another fingerprint.
- **Input anomaly ML** — kmbox-injected events have characteristic timing differing from human input.

### 9.3 — Kmbox variants

- **Kmbox B+** — Bluetooth-controlled.
- **Kmbox Pro / Kmbox Net** — Network-controlled.
- **Arduino-based variants** — DIY, use Leonardo/Pro Micro with HID firmware.

### 9.4 — Counter-measures

- EAC's mouse driver chain inspection walks `\Driver\MouseClass` device stack.
- Kmbox typically sits as a transparent HID so driver chain looks normal.
- Detection falls to behavioral ML.

---

## Part 10 — External / capture-card second-PC setups

Frame-grab from first PC into second PC's inference pipeline, aim commands sent back via kmbox.

**Game PC side**: EAC agent sees only input events coming in.

**Actual cheat logic**: on another machine.

**Input anomaly is the only detection surface here.**

This is the hardest cheat category to catch. Current-build input ML is specifically trained on these patterns, with mixed success.

---

## Part 11 — GPU-executed cheats

### 11.1 — Why interesting

- The game's rendered frame lives in GPU memory.
- CUDA/OpenCL/DirectCompute can execute on GPU alongside the game.
- GPU memory access from a sibling process doesn't go through CPU.

### 11.2 — Architecture

```
Game Process:
  CPU → D3D11/DXGI → GPU → Rendered frames → GPU Memory

Cheat Process (sibling):
  CPU → CUDA API → GPU
   (compute kernels read framebuffer)
   → Analysis results back to CPU
```

Specific implementation:
- Cheat attaches to GPU as CUDA context.
- Uses CUDA to enumerate textures (`cudaGraphicsD3D11RegisterResource`).
- Finds the game's framebuffer / specific textures.
- Reads frame data.
- CUDA kernel analyzes frame for enemies.
- Returns ESP data to cheat's CPU side.

### 11.3 — Detection

- Enumerate GPU processes via NVAPI (`NvAPI_GetProcessList`).
- For each, check if whitelisted.
- Non-whitelisted GPU processes while game is running → flag.

### 11.4 — Why rare in deployed cheats

- Setup complexity high; CUDA context sharing across processes finicky.
- Game-specific texture layout knowledge required.
- Easier to just run a user-mode cheat and read process memory directly.

Published as PoC in academic papers but not widely deployed.

---

## Part 12 — Game-state manipulation indicators

Reading game memory from outside the process (handle strip prevents) moves kernel-side. Can be caught via telemetry **if the cheat's visible effects correlate:**

- Impossibly consistent trajectory tracking (ML on movement data)
- Sub-tick reactions (ML on input vs event timing)
- Occluded-target reactions (ML on fire-events against line-of-sight info the server knows)

**Inside the process, memory reads are invisible.** Flag path is behavioral: once the cheat uses what it read, server-side correlation catches it.

### Trigger-bot pixel sampling

Reading screen pixels to detect a colored target region, then auto-firing.

Caught via:
- Input-anomaly detector's time-to-shot-after-input pattern.
- Current-build frame-capture ML looking for aim-circle overlays.
- Pixel-reader code paths read from the swapchain.

### Macro input

Hardware or software that generates recoil-compensation mouse patterns.

Caught by input anomaly detector's distributional analysis. Real human recoil compensation has characteristic noise; macros don't.

---

## Part 13 — Signature-based patterns in rules.bin

Rules.bin ships thousands of specific byte patterns targeting known cheat frameworks:

- Manual-mapper boilerplate (reflective-loader stubs, IAT fixup loops)
- Common cheat UI framework strings (ImGui class names and strings)
- Popular trainer frameworks' signature constants
- Cheat loader PE header anomalies (TLS callback positions, section-name patterns)
- DMA-card driver fingerprints
- SMBIOS spoofer fingerprints

Pattern matching runs per module load and periodically against each VAD.

---

## Part 14 — Real published EAC-specific research

### Secret Club — multi-year EAC series

The deepest public research body on EAC. Core pieces:

**"How anti-cheats detect system emulation":**
- Detailed every anti-VM technique EAC uses.
- Hypervisor brand string + CPUID timing detection.
- Registry probes + MAC prefix checks.
- CPU-timing baseline calibration.

**"How anti-cheats work" series:**
- Explained PsSetCreate*NotifyRoutine usage in EAC.
- Walked ObRegisterCallbacks handle-strip mechanism.
- Showed VAD walking for manual-map detection.

**"Exploiting an Integer Overflow in EAC":**
- Specific CVE-worthy bug in EAC's pipe parser.
- Allowed memory corruption in the agent.
- Impact: code exec in agent context.
- Fix: patched within one EAC build cycle.

### Mellow / handle-only researchers — EAC teardowns

Several multi-year posts on EAC internals:
- Pipe protocol reverse engineering.
- Rules.bin decryption methodology.
- Pin check location tricks.
- Technique for extracting rules.bin root key by xref-walking.

### UC-forum driver reversal

The source of this repo's [02 kernel driver](02-kernel-driver.md) content. Current-build teardown with real RVAs.

### can1357 / NoVmp

Tool that makes current EAC tractable. VMProtect devirtualizer that lifts to VTIL IL. 70-85% handler coverage on current builds.

### Public EAC-adjacent CVEs

- **CVE-2022-21894 ("Baton Drop")** — Secure Boot bypass → enabled BlackLotus UEFI bootkit.
- **CVE-2023-24932** — BlackLotus patch (updated Secure Boot DBX).
- **CVE-2024-{quarterly}** — ongoing BYOVD disclosures.

---

## Part 15 — EAC Oy cert leak (historical)

Alleged circa 2020:
- Chatter on private forums about a leaked EAC Oy code-signing certificate.
- Cert used to sign arbitrary drivers that passed SmartScreen's publisher check.
- Short-lived — Microsoft revoked within weeks.
- **Did NOT compromise session-attestation keys** — only the publisher cert.

Status: treat as "alleged" rather than "confirmed" publicly.

### Nvidia / LAPSUS$ 2022

LAPSUS$ breach of Nvidia leaked code-signing certs. Several malware families signed with the leaked certs before revocation. Cheat developers briefly used them. Microsoft revoked, WDAC updated.

### Microsoft's attestation-signing program abuses

Mandiant documented multiple cases of malicious actors obtaining Microsoft-signed drivers through the attestation signing program. Each signing certificate approved got individual drivers signed that WDAC later blocked.

---

## Part 16 — Detection-category summary

| Cheat architecture | Primary detection | Secondary |
|-|-|-|
| In-process DLL (classic) | VAD scan, module scan, handle-open log | Thread scanner, hook detector |
| In-process manual-mapped | VAD walker (ground truth) | Transient-exec detector, entropy check |
| In-process hollowing | Integrity timer | Pattern scan on hollowed region |
| Kernel driver (BYOVD) | `DRIVER_LIST` + WDAC state | `CALLBACK_DUMP` |
| Kernel driver (manual-mapped) | `CALLBACK_DUMP` | VAD scan can't see it; behavioral |
| Hypervisor cheat | Anti-VM (CPUID timing, APIC, HV brand) | Behavioral correlation |
| Hypervisor + EPT splitting | Timing + MSR state only | Behavioral correlation (primary) |
| SMM cheat | Firmware fingerprint + TPM PCR drift | Behavioral correlation (primary) |
| UEFI bootkit | TPM PCR drift + Secure Boot state + HVCI state | HWID anomaly correlation |
| External PCIe DMA | PCI config space enum + config hash | Behavioral correlation |
| kmbox / external input | Mouse driver chain inspection | Input anomaly ML |
| Capture-card second-PC | Input anomaly ML only | — |
| GPU-executed cheat | GPU process enumeration | — |
| Trigger-bot pixel sampler | Input time-to-shot + frame-capture ML | — |
| Macro / recoil script | Input distributional ML | — |

**The pattern:** EAC catches client-process anomalies. Fortnite's server-authoritative checks catch game-state anomalies. Behavioral ML correlates across both. External cheats evade EAC but can't evade game-state checks because the cheat has to affect game state to be useful.

---

## Part 17 — Detection timeline economics

| Cheat tier | Real-world detection | Timeline to catch |
|-|-|-|
| Public user-mode-only cheats | Instant | Seconds to minutes per session |
| BYOVD-based kernel cheats (RTCore-era tier) | Fast | Session to hours |
| Manual-mapped kernel cheats (kdmapper-tier) | Medium | Days to weeks |
| Hypervisor-based cheats (SimpleVisor-derived) | Slow | Weeks to months |
| DMA-card cheats (Screamer tier) | Slow — behavioral mostly | Months with KDP off; indefinite with KDP on |
| Hardware input injectors (kmbox + arduino) | Slow — behavioral only | Months |
| Capture-card + second-PC + aim injection | Hardest to catch — behavioral only | Can run indefinitely at low skill; months at high skill |
| UEFI bootkit cheats | Slowest | Years, if ever, by current EAC |
| SMM-based cheats | Theoretical, almost no real deployment | Essentially undetectable from OS |

**Practical reality:** every cheat caught eventually unless it's hardware-external. The variable is time horizon.

Commercial cheat markets price accordingly:
- Public cheats: $5/week
- Private cheats: $50-200/week
- UEFI/hypervisor cheats: $500-2000/week
- DMA setups: $200-15000 hardware + weekly subscription

---

## Part 18 — Attack synthesis — combined architectures

The highest-end cheats combine multiple techniques:

```
Boot:
  UEFI bootkit (persistence)
    → loads hypervisor driver pre-OS
      → Windows boots as VMX guest
        → EAC loads normally
          → Cheat's hypervisor hides from EAC's anti-VM checks via timing spoof
        → Cheat kernel driver loaded into kernel memory by hypervisor
          → No LDR entry, no callbacks registered that EAC sees
            → Patches EAC's pin-check function via EPT page-split
              → MITM EAC's TLS traffic, read session state
                → Spoof HWID queries via ACPI + SMBIOS + storage filter
                  → EAC's env_worker reads return consistent spoofed values

Runtime:
  Game runs normally
    → Cheat hypervisor hooks CR3 switches to track process boundaries
      → Reads game memory via EPT-level access without PROCESS_VM_READ
        → Computes ESP/aim decisions
          → Writes via another EPT-level page-split to inject input

Operator:
  Buys cheat for $2000/month
    → Gets installer + weekly key update
      → Discord support channel for troubleshooting
```

### What survives detection

- Memory-level: hypervisor EPT magic hides everything.
- Kernel callback-level: no cheat callbacks registered.
- Driver-list level: cheat driver not in `PsLoadedModuleList`.
- VAD-level: cheat code lives in kernel memory.
- TPM-level: PCRs may drift. **This is the eventual loss condition.**
- Behavioral: aim statistics across hundreds of matches eventually correlate.

End state: lives for 3-6 months per hardware setup. HWID ban. Operator buys new hardware OR migrates to a different account chain.

---

## Part 19 — Why most cheaters get caught

**Not because the cheat was bad.** Because they got greedy with it.

- Statistical aim perfection over hundreds of sessions is the detection.
- The per-handler feature-flag system (see [04 user-mode agent Part 16](04-user-mode-agent.md#part-16--trust-score-model-how-eac-decides-what-runs-on-your-machine)) rotates detections per session — "I bypassed check X" doesn't help when backend rotates to check Y.
- Trust-score accumulates across sessions. Spoofing one machine identifier helps; spoofing all 20+ identifiers consistently is the full problem.

---

## Part 20 — Where new research goes

Active research surfaces as of 2026:

- **CET (Control-flow Enforcement) interactions with injection** — shadow stack + indirect-branch tracking changes what injection techniques work.
- **Intel TDX / AMD SEV-SNP confidential compute** — potential for hiding cheats in enclave-like regions.
- **DRTM (Dynamic Root of Trust) attacks** — trying to break the measured launch chain.
- **PCIe gen 5+ DMA with ReBAR interactions** — new DMA spoofing surface.
- **USB4 / Thunderbolt 5 DMA** — new input/memory attack surfaces.

Each of these will spawn new cheat-development approaches and new counter-measures over the next 2-3 years.

---

**Next:** [13 — EAC emulation + live-server bypass reality](13-eac-emulation.md)
