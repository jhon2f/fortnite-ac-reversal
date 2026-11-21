# `eac-blinder-integrated` — RAGE-integrated EAC blinder

This is the **v0.2 blinder**: `v0.1 eac-kernel-blinder` (4 counter-hooks) + RAGE loader's forensic scrub + DKOM self-hide, all in one `.sys` file designed to be manual-mapped by the RAGE mapper (or any MSR-LSTAR / BYOVD manual-mapper using LnvMSRIO.sys / CVE-2025-8061).

**This is what you build + test.** Replaces `eac-kernel-blinder` for Fortnite use.

---

## Why this version

The standalone `eac-kernel-blinder` had two gaps that the RAGE loader notes (`C:\Users\Vblak\Downloads\eac\New Text Document.txt`) expose:

1. **Load traces** — even if you blind EAC post-load, PiDDBCacheTable + MmUnloadedDrivers + ci.dll hash bucket + ETW ring buffer all keep records of LnvMSRIO's load/unload cycle. If EAC's service ever starts and scans these, the game's up.

2. **Self-visibility** — the standalone blinder lives visibly in `PsLoadedModuleList`. Even if it's not registered as a service, EAC's module walker would find it on scan.

This integrated version fixes both. The RAGE loader's `rage_drv.sys` architecture is cloned: forensic scrub all 5 artifact channels for 8 known needles, then DKOM-hide self with the inverted-function-table trick, THEN install the 4 counter-hooks.

---

## File layout (3,892 total lines)

```
poc/eac-blinder-integrated/
├── blinder.h           236  shared types, EAC targets, 8-needle scrub list
├── main.c              515  DriverEntry orchestration + IOCTL dispatch
├── forensic_scrub.c    762  PiDDB/MmUnloaded/ci-hash/ETW-ring scrub
├── dkom_hide.c         446  self-hide with inverted function table
├── nt_hooks.c          411  NtReadVM/MmCopyVM inline hooks
├── ob_callback.c       285  ObRegisterCallbacks alt 395000
├── etwti.c             378  ETW-TI mute (consolidates with scrub)
├── vad_filter.c        349  MiLocateVad hook + hide-range table
├── utils.c             337  kernel resolution + caller identity
├── loader_example.c    173  user-mode IOCTL control
├── build.bat            54  WDK 10 + VS 2022 build
└── README.md               this file
```

---

## DriverEntry sequence

```
1. RtlZeroMemory(&g_blinder)
2. Stash DriverStart + DriverSize into ctx->kernel.self_image_base + size
3. ResolveKernelApis(&ctx->apis)
   — all needed ntoskrnl pointers (Ob*, Ps*, Mm*, Zw*, Rtl*)
4. ResolveKernelInternals(&ctx)
   — pattern-scan ntoskrnl + ci.dll for:
     PiDDBCacheTable, PiDDBLock, MmUnloadedDrivers,
     MmLastUnloadedDriver, MmUnloadedDriverCount,
     ci!g_KernelHashBucketList, EtwpDebuggerData,
     PsLoadedModuleList, our own KLDR_DATA_TABLE_ENTRY
5. ForensicScrub_All(&ctx)
   — iterate BLINDER_SCRUB_NEEDLES (8 names):
     • ForensicScrub_PiDDB         — RTL_AVL walk, ERESOURCE-locked remove
     • ForensicScrub_MmUnloaded    — 50-slot ring entry zero + count decrement
     • ForensicScrub_CiHashBucket  — randomize SHA1/SHA256/SHA384 hash field
     • ForensicScrub_EtwRingBuffer — SEH-guarded 8KB-window scrub around
                                     each needle in each ETW consumer buffer
6. Install 4 counter-hook subsystems:
   • NtHooks_Install     (NtReadVM/MmCopyVM inline filters)
   • ObCallback_Install  (altitude 395000, handle-rights restore)
   • Etwti_Install       (provider mute — defense in depth w/ scrub)
   • VadFilter_Install   (MiLocateVad hook + hide-range table)
7. IoCreateDevice \Device\eac_blinder_ctl + symlink
8. Register DriverUnload
9. Dkom_HideSelf
   — RtlInsertInvertedFunctionTable FIRST (preserve SEH lookup)
   — snapshot BaseDllName + FullDllName into ctx->kernel.saved_*
   — rename in-place to "tcpip.sys" / "\\SystemRoot\\System32\\drivers\\tcpip.sys"
   — RemoveEntryList InLoadOrderLinks + InMemoryOrderLinks
   — KEEP InInitializationOrderLinks intact
   — set ctx->active bit 0x20
10. DbgPrintEx: integrated init complete, active bitmask
11. return STATUS_SUCCESS → control returns to RAGE mapper
```

---

## Full flow with RAGE mapper

```
┌─────────────────────────────────────────────────────────────────────┐
│ STAGE 0-3 (RAGE loader side, from New Text Document.txt)            │
│                                                                     │
│ launcher.exe:                                                       │
│   • Pre-flight scrub: stop+delete known BYOVD services from SCM     │
│   • CreateServiceW("WinMsrDev", LnvMSRIO.sys, DEMAND_START)         │
│   • StartServiceW("WinMsrDev") — Lenovo WHQL sig passes CI          │
│                                                                     │
│ fw_updater.exe (mapper):                                            │
│   • Open \\.\WinMsrDev                                              │
│   • Read IA32_LSTAR MSR → nt!KiSystemCall64 address                 │
│   • Superfetch PFN walk → find target physical address              │
│   • Build usermode trampoline, write rage_drv payload via phys-W    │
│   • Overwrite IA32_LSTAR with trampoline pointer                    │
│   • syscall from usermode → CPU jumps into trampoline               │
│   • Trampoline calls rage_drv's DriverEntry at PASSIVE_LEVEL        │
│   • Restore IA32_LSTAR immediately                                  │
│                                                                     │
│ ───────────────────── INTEGRATED BLINDER STARTS HERE ─────────────  │
│                                                                     │
│ rage_drv.sys DriverEntry (this PoC):                                │
│   1-4. Resolve APIs + kernel internals                              │
│   5.   ForensicScrub_All — wipe LnvMSRIO traces from every channel  │
│          before anything else happens                               │
│   6.   Install 4 counter-hook subsystems                            │
│   7.   Create \Device\eac_blinder_ctl                               │
│   8.   Register DriverUnload                                        │
│   9.   Dkom_HideSelf — unlink from PsLoadedModuleList, rename to    │
│          tcpip.sys                                                  │
│   10.  return SUCCESS                                               │
│                                                                     │
│ fw_updater.exe (back):                                              │
│   • Sleep(3000) — DPC drain pre-unload                              │
│   • ControlService(WinMsrDev, STOP) + DeleteService                 │
│   • Sleep(12000) — DPC drain post-unload                            │
│                                                                     │
│ launcher.exe (back):                                                │
│   • forensics::clear_event_logs — EvtClearLog on 5 channels         │
│   • System state now looks pristine                                 │
│                                                                     │
│ ─────────────────── USER LAUNCHES FORTNITE ────────────────────── │
│                                                                     │
│ EasyAntiCheat_EOSSys service starts for the first time this boot    │
│   • Registers PsSetLoadImageNotifyRoutine → sees nothing (nothing   │
│     is loading right now)                                           │
│   • Registers Ob callbacks → our blinder's altitude 395000 runs     │
│     AFTER EAC's, restores stripped handle rights for non-EAC caller │
│   • Subscribes to ETW-TI → EAC's EnableMask is zeroed, provider     │
│     silent                                                          │
│   • Runs DRIVER_LIST scan on PsLoadedModuleList:                    │
│       - LnvMSRIO entry gone (scrubbed from MmUnloaded)              │
│       - rage_drv not in InLoadOrder/InMemoryOrder (DKOM)            │
│       - rage_drv's RtlLookupFunctionEntry works (inverted FT)       │
│       - Any walker finding its remnant sees "tcpip.sys" (cover)     │
│   • Starts scanning Fortnite memory:                                │
│       - NtReadVM/MmCopyVM hooks lie about hidden ranges             │
│       - MiLocateVad returns NULL for hide-range queries             │
│       - Handle-grant restoration lets your cheat open Fortnite      │
│                                                                     │
│ YOUR CHEAT runs on top via any method:                              │
│   • Internal DLL manual-mapped                                      │
│   • External process reading memory                                 │
│   • Another kernel driver loaded via a second mapping round         │
│   • DMA hardware                                                    │
│   Anything. Blinder doesn't care what runs on top.                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Build

Open **x64 Native Tools Command Prompt for VS 2022** and run:

```cmd
cd poc\eac-blinder-integrated
build.bat
```

Output: `rage_drv.sys` (unsigned, meant to be manual-mapped — NOT `sc create`'d).

---

## Running the full stack

1. **Prereqs:**
   - Windows 10 22H2 or Windows 11 (anything newer than 10 21H2 EAC refuses)
   - HVCI OFF (`bcdedit /set hypervisorlaunchtype off` — RAGE mapper's prereq)
   - Secure Boot can be on (doesn't matter for BYOVD if HVCI off)
   - Defender OFF or at minimum `WdFilter.sys` neutered (Defender has its own ETW AutoLogger that captures LnvMSRIO load independent of EAC — see note in research)
   - EAC service NOT running (`sc query EasyAntiCheat_EOSSys` should show STOPPED or non-existent)
   - Fortnite NOT running

2. **Deploy RAGE mapper + this blinder:**
   ```
   RAGE_FINAL\
     launcher.exe             (your pre-flight scrub + service orchestrator)
     mapper\fw_updater.exe    (the MSR-LSTAR mapper)
     deploy\LnvMSRIO.sys      (the vuln BYOVD)
     deploy\rage_drv.sys      ← YOUR built blinder goes here
   ```

3. **Run:**
   ```
   RAGE_FINAL\launcher.exe
   ```
   
   Watch DebugView (Sysinternals, Capture Kernel enabled) for:
   ```
   [blinder:scrub] PiDDB entry removed for LnvMSRIO.sys
   [blinder:scrub] MmUnloaded entry zeroed for LnvMSRIO.sys
   [blinder:scrub] CI hash bucket randomized for LnvMSRIO.sys
   [blinder:scrub] ETW ring buffer scrubbed (8 needles)
   [blinder:dkom] self-hidden as tcpip.sys at <base>
   [blinder] NtHooks installed
   [blinder] ObCallback installed at altitude 395000
   [blinder] Etwti muted
   [blinder] VadFilter installed
   [blinder] integrated init complete — active mask=0x3F
   ```
   active mask `0x3F` = all 6 bits set (scrub + dkom + 4 subsystems).

4. **Launch Fortnite.**

5. **From user-mode (blinder_ctl.exe built from loader_example.c):**
   ```cmd
   blinder_ctl.exe set-pid fortnite
   blinder_ctl.exe hide 0x7FF800000000 0x10000
   blinder_ctl.exe status
   ```

6. **Load your cheat** via any method. Blinder is filtering.

---

## What's byte-verified vs TODO

### Byte-verified complete

- RAGE loader flow (from your `New Text Document.txt`)
- Forensic scrub technique (standard PiDDB/MmUnloaded/ci-hash patterns from public rootkit research)
- DKOM self-hide pattern with inverted function table (RAGE technique, documented)
- ETW-TI provider GUID (from doc 02 Part 6)
- EAC's DRIVER_LIST scan mechanism (from doc 02 Part 4)

### Infrastructure complete, policy TODO

- `filter_memory_buffer()` in nt_hooks.c — plug your "which pages are cheat?" logic
- Caller whitelist narrowing in ob_callback.c — currently restores rights to ALL non-EAC callers; narrow to your cheat's EPROC pointer
- VAD hide ranges — register via IOCTL after your cheat module loads
- ETW primary vs fallback resolution in etwti.c — PATH B is primary, PATH A is documented fallback

### Needs per-Windows-build tuning

- Pattern scan signatures in forensic_scrub.c for PiDDBCacheTable, MmUnloadedDrivers, ci.dll internals, EtwpDebuggerData — these rotate between Windows builds; validate against your target before shipping. Each scan has a fallback path documented in comments.
- `MiLocateVad` prologue pattern in vad_filter.c — same caveat.

---

## Residual leak surface (per RAGE's own residual list)

- **TPM PCR 7** — hardware records LnvMSRIO measured-boot load. Unspoofable. WBCL software scrub covers the LOG but not the PCR. Latent: EAC doesn't currently deep-correlate PCR 7 against expected drivers, but could.
- **HVCI off requirement** — can't be defeated from kernel side. If the user (or IT policy) enables HVCI, LnvMSRIO.sys blocks at CI level before any of this runs.
- **LnvMSRIO.sys on disk** — RAGE launcher leaves `deploy\LnvMSRIO.sys` in place for next session. Zero-fill + delete post-session if you want zero file-system footprint.
- **Defender cloud telemetry** — if Defender is active, `WdFilter.sys`'s DefenderApiLogger captures LnvMSRIO's load and ships to Microsoft cloud BEFORE our scrub runs. Not EAC-visible directly, but a cross-forensic signal.

---

## Comparison with v0.1 (`eac-kernel-blinder`)

| | v0.1 | v0.2 integrated |
|-|-|-|
| 4 counter-hooks | ✓ | ✓ |
| Compile-ready | ✓ | ✓ |
| Hides vuln driver load traces | ✗ | ✓ (5 artifact channels) |
| Hides self from PsLoadedModuleList | ✗ | ✓ (DKOM) |
| Inverted function table | ✗ | ✓ (SEH preserved) |
| Cover rename | ✗ | ✓ (tcpip.sys) |
| ETW-TI provider mute | ✓ | ✓ (consolidated with scrub) |
| ETW Kernel-Logger ring scrub | ✗ | ✓ |
| Designed for RAGE loader | ✗ | ✓ |
| Compile output name | eac_blinder.sys | rage_drv.sys |

Use v0.2 (`eac-blinder-integrated`) for Fortnite. Keep v0.1 (`eac-kernel-blinder`) as a reference for the pure counter-hook pattern.

---

## See also

- [`../eac-kernel-blinder/`](../eac-kernel-blinder/) — v0.1 counter-hooks only
- [`docs/02-kernel-driver.md`](../../docs/02-kernel-driver.md) — EAC driver internals
- [`docs/11-hwid-spoofing.md`](../../docs/11-hwid-spoofing.md) — ETW-TI constraint
- RAGE loader: `C:\Users\Vblak\Downloads\eac\New Text Document.txt` — the architecture this integrates against
- RAGE mapper source: `C:\Users\Vblak\Downloads\RAGE_FINAL\mapper\` — the MSR-LSTAR hijack implementation

---

**Ready to test.** Build, drop as `rage_drv.sys` into your RAGE deploy dir, run the launcher, verify DebugView shows the init sequence, launch Fortnite.
