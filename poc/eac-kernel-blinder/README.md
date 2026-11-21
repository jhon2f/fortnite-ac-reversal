# `eac-kernel-blinder` — kernel-mode EAC blinder (PoC)

Windows kernel driver that, once mapped into kernel memory, **blinds EAC to everything happening in the game process**. EAC keeps running — service, driver, user-mode scanner — but its observation points are counter-hooked so every scan comes back clean. Any cheat (internal DLL, external process, DMA helper) can then run on top without EAC detecting it.

This is the "base layer" from the EAC-blinder architecture discussion. It's the hard-to-build-once piece. Once this is up, cheats on top can be trivially simple.

> **Status:** PoC skeleton. Hook INFRASTRUCTURE is real working kernel code. Hook BODIES mark filter decisions with `TODO` — plug your filter policy there (which pages to hide, which modules to filter, which VAD ranges to blank). Compile-ready in WDK; needs offset-specific tuning per EAC build.

---

## What each file does

| File | Lines | Role |
|-|-|-|
| [`blinder.h`](blinder.h) | 202 | Shared types, EAC target constants, resolved-API struct, subsystem prototypes |
| [`main.c`](main.c) | 315 | `DriverEntry` / `DriverUnload` / IOCTL dispatch for user-mode control |
| [`nt_hooks.c`](nt_hooks.c) | 411 | Inline hooks on `NtReadVirtualMemory` + `MmCopyVirtualMemory` with CR0.WP toggle + trampolines |
| [`ob_callback.c`](ob_callback.c) | 285 | `ObRegisterCallbacks` at altitude 395000 — restores handle rights EAC stripped |
| [`etwti.c`](etwti.c) | 378 | Detaches EAC's ETW-Threat-Intelligence subscription by zeroing EnableMask |
| [`vad_filter.c`](vad_filter.c) | 349 | Inline hook on `MiLocateVad` — blanks hidden ranges from EAC's walker |
| [`utils.c`](utils.c) | 337 | Module/process resolution, API resolve, pattern scan, caller identity check |

~2,277 lines total.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│ Ring 0 (kernel)                                                 │
│                                                                 │
│  ┌──────────────────┐         ┌──────────────────────────────┐  │
│  │ EAC driver       │ scan →  │ eac_blinder.sys (this PoC)   │  │
│  │ EasyAntiCheat_   │ ←blind──┤                              │  │
│  │ EOS.sys          │         │ 4 counter-hook subsystems:   │  │
│  └──────────────────┘         │                              │  │
│          │                    │ ① NT syscall filter          │  │
│          │ hooked via         │    NtReadVirtualMemory       │  │
│          │ trampolines +      │    MmCopyVirtualMemory       │  │
│          │ callbacks          │                              │  │
│                               │ ② ObRegisterCallbacks        │  │
│  ┌──────────────────┐         │    restores rights EAC       │  │
│  │ ntoskrnl.exe     │ ←hook───┤    stripped (alt 395000)     │  │
│  │ (NT, Ob, Etw,    │         │                              │  │
│  │  Mi, Ps APIs)    │         │ ③ ETW-TI detach              │  │
│  └──────────────────┘         │    zero EnableMask on        │  │
│                               │    EAC's provider reg entry  │  │
│                               │                              │  │
│                               │ ④ VAD walker filter          │  │
│                               │    MiLocateVad returns NULL  │  │
│                               │    for hidden ranges         │  │
│                               └──────────────────────────────┘  │
│                                            │ IOCTL              │
├────────────────────────────────────────────┼────────────────────┤
│ Ring 3 (user)                              ▼                    │
│                                                                 │
│  ┌─────────────────────┐    ┌─────────────────────────────────┐ │
│  │ FortniteClient-     │    │ control app (user-mode)         │ │
│  │ Win64-Shipping.exe  │    │ sets Fortnite PID + hide ranges │ │
│  │ + your cheat        │    │ via \\.\eac_blinder_ctl         │ │
│  └─────────────────────┘    └─────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Flow:**

1. Boot normally. Launch Fortnite normally. EAC service + driver load.
2. Load this blinder via your BYOVD mapper (see below) — mapper puts `eac_blinder.sys` into kernel memory with no file / service / registry footprint.
3. `DriverEntry` resolves kernel APIs, finds EAC's driver base + service process, then installs all 4 hook subsystems.
4. Open `\\.\eac_blinder_ctl` from user-mode, send `IOCTL_BLINDER_SET_FORTNITE_PID` with Fortnite's PID. Blinder resolves PEPROCESS + enables filtering.
5. (Optional) Send `IOCTL_BLINDER_ADD_HIDE_RANGE` for each memory range you want blanked from EAC's view.
6. Inject/run any cheat on top. The blinder lies to EAC about memory reads, handle grants, ETW events, and VAD walks involving the Fortnite process.
7. On exit: send a stop IOCTL (or unmap via mapper) — all 4 subsystems uninstall, kernel state restored.

---

## IOCTL interface (see `main.c` for codes)

| IOCTL | Direction | Purpose |
|-|-|-|
| `IOCTL_BLINDER_STATUS` | OUT | Returns `{active bitmask, Fortnite PID, EAC driver base, hook counts}` |
| `IOCTL_BLINDER_SET_FORTNITE_PID` | IN `HANDLE` | Set target process. Blinder resolves to PEPROCESS. |
| `IOCTL_BLINDER_ADD_HIDE_RANGE` | IN `{PVOID start; SIZE_T size}` | Add VAD + memory-read hide range |
| `IOCTL_BLINDER_CLEAR_RANGES` | — | Flush the hide-range table |

---

## Build

Open **x64 Native Tools Command Prompt for VS 2022** and run:

```cmd
cd poc\eac-kernel-blinder
build.bat
```

Output: `eac_blinder.sys` (unsigned, cannot be loaded via `sc create` on a normal DSE-enabled Windows — see mapper section below).

Requirements:
- Visual Studio 2022 with Desktop C++
- Windows Driver Kit 10 (install via VS installer)
- Windows SDK 10

---

## Loading — DO NOT ship your own vulnerable driver

**You need a BYOVD (Bring Your Own Vulnerable Driver) mapper.** This PoC deliberately does NOT include one. Reasons:

1. **Every public BYOVD mapper is detected.** EAC's `DRIVER_LIST` IOCTL + Microsoft's WDAC Vulnerable Driver block-list cover every popular public vuln driver. `kdmapper`, `dbkdrv`, `inpoutx64`, `RTCore64`, `GDRV`, `DBUTIL_2_3` — all flagged. Load any of them → instant ban via EAC's kernel scan + Microsoft's block-list.
2. **Distributing a BYOVD mapper has its own legal issues** separate from this PoC.
3. **The clean path is user-supplied private mappers.** You either write your own (reverse a WHQL-signed driver with an arbitrary write primitive that EAC's catalog doesn't yet flag), or buy one from a vendor who maintains fresh mappers as detections land.

### What mapper qualifies

A good mapper for this PoC needs:
- **Not** in EAC's `DRIVER_LIST` IOCTL response (verify first — see [doc 02 Part 4](../../docs/02-kernel-driver.md))
- **Not** in Microsoft WDAC Vulnerable Driver block-list (`Get-MpPreference | Select-Object -Expand ExclusionPath`)
- Capable of providing kernel-mode arbitrary read + write OR raw page-table write
- Can call `MmMapIoSpace` or equivalent to map our blinder's image into non-paged pool
- Bootstraps the blinder by fixing up relocations + calling `DriverEntry` with crafted args

### Existing public references (for architecture, not direct use)

Research references only — these are all detected. Reading their source teaches you what a mapper does; USING them against EAC gets you banned:

- `kdmapper` (github.com/TheCruZ/kdmapper) — classic Intel `iqvw64e.sys` vuln. Detected since ~2022.
- `drvmap` variants — generally detected.
- `kdu` (github.com/hfiref0x/KDU) — comprehensive multi-vuln framework. Detected signatures.

### What production cheats do

Private mappers using drivers Microsoft hasn't added to the block-list yet. These rotate every few weeks as each new vuln driver gets added. Vendors like gatekeeper-style cheat sellers maintain a "driver of the week" they'll give you alongside the loader. Lifespan: days to weeks per driver.

### Alternative load paths

If you don't want to deal with BYOVD:
- **DMA card** — map via PCIe DMA from a second PC (no mapper needed on target). See [doc 12 Part 5](../../docs/12-cheat-detection.md).
- **DSE disabled via testsigning** — only works on your own test machine; EAC refuses to launch if `bcdedit /enum` shows testsigning on.
- **Hyper-V-based mapping** — host OS has kernel access by virtue of being the hypervisor; guest is Fortnite. Setup project in itself.

---

## What this PoC is honest about

### Fully real + working infrastructure

- Inline hook pattern (CR0.WP toggle + trampoline + 12-byte abs-jmp)
- `ObRegisterCallbacks` registration at altitude 395000
- ETW-TI subscription detach via `EtwpDebuggerData[0x60]` → GUID hash walk
- `MiLocateVad` pattern scan + inline hook
- Runtime API resolution via `MmGetSystemRoutineAddress` + pattern scan
- Process identity (`PsGetCurrentProcess` + stack-frame return-address check for "is caller EAC?")
- Install/Uninstall symmetric + idempotent across all 4 subsystems
- Proper IRQL management (DISPATCH_LEVEL + CLI window for patch writes)
- Non-paged pool allocations with `BLINDER_POOL_TAG` for easy leak-check

### What you plug in (TODO sites)

- **Memory read filter** in `nt_hooks.c::filter_memory_buffer` — "which bytes of this buffer are cheat pages? zero them, pass the rest."
- **VAD hide ranges** — register them via IOCTL from user-mode after your cheat is loaded.
- **Cheat-caller whitelist** in `ob_callback.c` — narrow "restore rights to all non-EAC callers" to "restore rights ONLY to my cheat's process."
- **ETW-TI primary vs fallback path** in `etwti.c` — PATH A (older) and PATH B (modern) are both documented; pick based on Windows build.

### What you need to validate per EAC build

- EAC's current ObRegisterCallbacks altitude (search range 350000-390000 in `blinder.h`)
- EAC's current ETW-TI registration entry walk pattern (may rotate)
- EAC's driver image base + size (resolved at runtime via `FindKernelModule`)
- `MiLocateVad` prologue pattern (the 17-byte anchor in `vad_filter.c`)
- EAC may add new observation surfaces per build — monitor doc 00's changelog

---

## Known limits + detection risks

| Risk | Severity | Mitigation |
|-|-|-|
| Public BYOVD mapper detected | **Critical** | Use private / undetected mapper (see above) |
| CR0.WP toggle traced by PatchGuard | High | Keep WP-cleared window under 1000 cycles; use IRQL raise + CLI |
| ObCallback at altitude 395000 may collide with newer AV | Medium | Enumerate existing callbacks first; pick next-free altitude |
| EAC may add ETW-TI reconnect heuristic | Medium | Monitor doc 00 for new build notes; hook `EtwRegister` as fallback |
| Hot-unload race against in-flight detour frames | Medium | Uninstall clears `active` first + `KeMemoryBarrier` before byte-restore |
| Blinder's own pool allocations visible to EAC | Low | Pool tag is random-ish (`BdcE`); add tag rotation if it starts flagging |
| Blinder's own module in `PsLoadedModuleList` | **Critical (if mapped visibly)** | Use mapper that strips LDR entry — any decent BYOVD mapper does |

### Server-side correlation still applies

The blinder prevents EAC's **local** scanner from seeing your cheat. Epic's **server-side** correlation still works on behavioral signals: impossible aim, pre-fire patterns, wallbang anomalies, win-rate statistics. No kernel blinder defeats those. Blinder gives you a longer ban-cadence window, not permanent invisibility.

Expected ban cadence with just the blinder: **7-30 days per account**, depending on how obvious the cheat is. Blinder + statistical restraint (randomize aim, don't pre-fire, don't 100% win-rate): **30-90+ days**.

---

## Debug / observability

- Install debug build: enable `DbgPrintEx` output via `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Debug Print Filter\IHVDRIVER = 0xf`.
- Open DebugView from Sysinternals as Administrator with "Capture Kernel" enabled.
- Blinder logs every hook install, every detour firing, every uninstall.
- Status via `IOCTL_BLINDER_STATUS` returns real-time hook state.

### Example user-mode control app

```c
HANDLE h = CreateFileW(L"\\\\.\\eac_blinder_ctl",
                      GENERIC_READ|GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, 0, NULL);

/* Tell blinder which process to protect */
HANDLE pid = (HANDLE)(uintptr_t)GetProcessIdOfFortnite();
DeviceIoControl(h, IOCTL_BLINDER_SET_FORTNITE_PID,
                &pid, sizeof(pid), NULL, 0, &bytes, NULL);

/* Add a hide range (page containing your cheat module) */
struct { PVOID start; SIZE_T size; } range = { module_base, module_size };
DeviceIoControl(h, IOCTL_BLINDER_ADD_HIDE_RANGE,
                &range, sizeof(range), NULL, 0, &bytes, NULL);

/* Blinder is live. Go cheat. */
```

Define the IOCTL codes exactly as `main.c` does (same `CTL_CODE` triplet).

---

## See also

- [doc 02 — Kernel driver](../../docs/02-kernel-driver.md) — EAC's driver internals that this blinder hooks
- [doc 11 — HWID spoofing](../../docs/11-hwid-spoofing.md) — the ETW-TI constraint this blinder's subsystem 3 removes
- [doc 12 — Cheat detection](../../docs/12-cheat-detection.md) — full BYOVD catalog + what's detected
- [doc 13 — EAC emulation reality](../../docs/13-eac-emulation.md) — why this is one of several bypass architectures
- `../eac-emu-stub/` — client-side agent replacement (different pattern — this one keeps real EAC running)
- `../eac-service-emu/` — service emulator (replaces EAC's service; this blinder leaves EAC's service running)

---

**This is PoC-tier research code.** Hook infrastructure is complete; filter policy is yours to write. Compile clean and verify each subsystem's install path on YOUR target Windows build before shipping anything on top.
