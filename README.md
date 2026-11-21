# fortnite-ac-reversal

Deep reverse-engineering notes on Fortnite's full anti-cheat stack: Easy Anti-Cheat (classic + EOS variant), Fortnite's own integrity layer, HWID / fingerprint surface, trust-score mechanics, ETW-TI hazards, real-world emulator architectures, and an EAC emulation PoC.

Current-build era: **late-2026** (EAC agent `EAC_2026_*`, EAC driver v3.2.0.0 Nov 2025 sign, Fortnite UE5).

**Refreshed Nov 19 2026** with UC community intel — see [doc 14 Part 10.5](docs/14-workflow-and-checklist.md#part-105--uc-community-intel-sources-nov-2026-pass) for source thread attribution.

> **Read before trusting any specific constant:** this is a map of the *architecture*. Offsets inside `EPROCESS`, altitude strings, XOR keys, AES salts, numeric IOCTL codes, pin hashes, and flag IDs rotate every few builds. Always re-derive constants against your own pulled binaries.

---

## Contents

**Fortnite anti-cheat covered end-to-end in 15 core docs + analysis of 3 real emulators.** Each doc is a comprehensive reference for its category — nothing split across scattered files.

### Core docs

| | Doc | What's in it |
|-|-|-|
| 00 | [Current-build notes + Fortnite EAC history](docs/00-current-build-notes.md) | What's new vs historical. Fortnite's BattlEye → dual-stack → EAC-only timeline. Milestone cheat events that triggered hardening. **Read first.** |
| 01 | [On-disk inventory](docs/01-on-disk-inventory.md) | Every file EAC + Fortnite ship, every path. |
| 02 | [Kernel driver](docs/02-kernel-driver.md) | `EasyAntiCheat_EOS.sys` complete teardown. Raw offsets, splitmix64 hash dispatch, the cage, flattened dispatcher, 46-module manifest, ETW-TI subscription, VAD walker, ObCallbacks strip. **Everything kernel-side.** |
| 03 | [User-mode launcher](docs/03-user-mode-launcher.md) | `EasyAntiCheat.exe` — spawn, inject, session token chain. |
| 04 | [User-mode agent](docs/04-user-mode-agent.md) | `EasyAntiCheat_x64.dll` complete teardown. Every scanner, telemetry endpoints with exact URLs + event catalog + body format, trust-score model, per-handler feature flags, pin check, severity taxonomy, ban-timing reality. **Everything agent-side.** |
| 05 | [Pipe protocol](docs/05-pipe-protocol.md) | Frame format, opcodes, handshake, REMOTE_MODULE_LOAD, driver↔service frame protocol. |
| 06 | [rules.bin](docs/06-rules-bin.md) | File format, key derivation, every section type with entry shapes. |
| 07 | [Fortnite integrity layer](docs/07-fortnite-integrity.md) | What Fortnite adds beyond base EAC — UE5 integration, server-authoritative movement/weapons/building, replay integrity, UEFN Verse sandbox, account trust signals, FNCS tournament integrity, cross-play trust, mobile AC, cosmetic verification, match-level fraud. **Everything Fortnite-specific.** |
| 08 | [Protection stack](docs/08-protection-stack.md) | VMProtect, custom VM, CFG flattening, anti-debug, anti-VM, anti-dump, IAT obfuscation. |
| 09 | [EOS variant delta](docs/09-eos-variant.md) | What's different in `EasyAntiCheat_EOS.*`. |
| 10 | [Cleaner & ban traces](docs/10-cleaner-ban-traces.md) | Every on-disk artifact EAC + Windows leaves. Prefetch, Amcache, Shimcache, BAM, MUICache, SRUM, USN journal, VSS, WER, Timeline, Shellbags, Thumbcache, UserAssist, DPAPI, LSA secrets, DriverStore, NTFS low-level, memory dumps. Full cleaner inventory. Why cleaning doesn't beat HWID bans. **Everything trace-side.** |
| 11 | [HWID spoofing surface](docs/11-hwid-spoofing.md) | Every hardware identifier field (CPUID, SMBIOS, disk, MAC, EDID, TPM, PCI, ACPI, firmware, RAM, Windows identity). Per-field spoofer mechanics. ETW-TI constraints (`shm PATCH_PTE refused`). Full spoof.sys deep dive. BYOVD catalog. WDAC. Spoofer architecture requirements + spoofability hierarchy. **Everything spoofer-side.** |
| 12 | [Cheat detection surface](docs/12-cheat-detection.md) | What EAC flags across every cheat category. Kernel drivers, injection indicators, hooking patterns, process manipulation catalog (14 techniques), hypervisor cheats with EPT page splitting, SMM, UEFI bootkits (BlackLotus, CosmicStrand), DMA hardware (Screamer tier, PCILeech, MemProcFS), kmbox, GPU-executed cheats. Real published EAC exploits. BYOVD history. **Everything cheat-side.** |
| 13 | [EAC emulation + live-server bypass reality](docs/13-eac-emulation.md) | Why live-server bypass is cryptographically hard (full signature chain analysis). What real private-server projects do (Project Reboot catalog, service mock list). Three emulator architectures compared. Working PoC. **Everything emulation-side.** |
| 14 | [Workflow, checklist, audit](docs/14-workflow-and-checklist.md) | Day-by-day reversal plan, environment setup, tooling, verification checklist, and audit of specific claims in earlier docs. |
| 15 | [Protocol recreation dossier](docs/15-protocol-recreation.md) | **Recreate-level dossier.** Byte-verified export tables for `a.dll` + `b.dll`, full IPC surface, 23× `ErrRpt_*` registry schema, 7× setup CLI, EventLog subscription mechanism, telemetry upload channels + event names, PKI chain, agent error enum, 15-DLL dependency graph, binary-offset quick reference. **Enough to rebuild the on-host stack from scratch.** |

### Real-world artifact analysis

Three different emulator / bypass architectures, analyzed from actual binaries + source:

| | Doc | What |
|-|-|-|
| — | [Analysis index](docs/analysis/00-index.md) | Overview of the three approaches |
| 01 | [desire_market full EAC-EOS emulator](docs/analysis/01-desire-market-emulator.md) | Self-provisioned EOS product + bundled HWID spoof driver. Includes full `spoof.sys` HWID-surface analysis. |
| 02 | [UC Linux-proxy emulator](docs/analysis/02-uc-linux-proxy-emulator.md) | Windows → Linux EOS/EAC proxy. Full dual-side source analysis. |
| 03 | [MCC in-process bypass](docs/analysis/03-mcc-in-process-bypass.md) | Runtime RVA-patch on EOS integrity check + XUID spoof. User-mode only. |

### Code

Three composable on-host emulation stubs. Together they stand up the full local stack (minus the kernel driver, which is covered in doc 02). **None bypass server-side session signing** — see doc 15 Part 13.

- [`poc/eac-emu-stub/`](poc/eac-emu-stub/) — compilable stub `EasyAntiCheat_x64.dll` (client-side EOS SDK + byte-verified `b.dll` 5-ordinal shape at RVAs `0x4FEA3 / 0x22DE30 / 0x30A0E0 / 0x4FCE2 / 0x2F2760`).
- [`poc/eac-service-emu/`](poc/eac-service-emu/) — service emulator (`EasyAntiCheat_EOSSys`). Pipe server, 3 named events, 64 KB shared memory mapping, 23× `ErrRpt_*` registry baseline, TPM status stubs, all 7 setup CLI subcommands.
- [`poc/eac-launcher-wrapper/`](poc/eac-launcher-wrapper/) — launcher wrapper replacement (`a.dll`). 5 named exports `a,b,c,d,e` matching byte-verified Nov 20 2026 ordinal layout.

### Raw originals

- [`original/fortnite_anticheat_reversal.txt`](original/fortnite_anticheat_reversal.txt) — recon/roadmap in plain text.
- [`original/fortnite_anticheat_reversed_internals.txt`](original/fortnite_anticheat_reversed_internals.txt) — the full teardown as a single plain text file.

---

## How to read this repo

- **New to EAC reversing:** [00 current-build notes](docs/00-current-build-notes.md) → [14 workflow](docs/14-workflow-and-checklist.md) → architecture docs 02 → 09 in order.
- **Want the deepest byte-level reversal:** [02 kernel driver](docs/02-kernel-driver.md) + [04 user-mode agent](docs/04-user-mode-agent.md) are the byte-level teardowns.
- **Investigating a ban / planning a clean:** [10 cleaner & ban traces](docs/10-cleaner-ban-traces.md). For HWID binding, [11 HWID spoofing](docs/11-hwid-spoofing.md).
- **Understanding cheats:** [12 cheat detection](docs/12-cheat-detection.md) is the full map — what gets flagged, what works, what doesn't.
- **Building EAC emulation / private servers:** [13 EAC emulation](docs/13-eac-emulation.md) for architecture + live-server bypass reality, [`poc/eac-emu-stub/`](poc/eac-emu-stub/) for code, and the three [analysis](docs/analysis/00-index.md) docs for real-world precedent.
- **Fortnite-specific additions:** [07 Fortnite integrity layer](docs/07-fortnite-integrity.md) covers everything Epic adds on top of base EAC (server-authoritative checks, replay, UEFN sandbox, FNCS, cross-play, mobile).
- **Whole thing in one plain-text file:** [`original/fortnite_anticheat_reversed_internals.txt`](original/fortnite_anticheat_reversed_internals.txt).

---

## What this repo covers

Every category has one comprehensive doc. No scattered references.

- **Kernel driver** → [02](docs/02-kernel-driver.md) covers RVAs, callbacks, IOCTLs, ETW-TI, 46-module manifest, VAD walker, ObCallbacks, PatchGuard/HVCI/DMA Protection context.
- **User-mode agent** → [04](docs/04-user-mode-agent.md) covers every scanner, telemetry endpoints, trust model, feature flags, pin check, severity taxonomy, event catalog.
- **Fortnite-specific** → [07](docs/07-fortnite-integrity.md) covers UE5 integration, server checks, replay, UEFN, FNCS, cross-play, mobile, cosmetic verification.
- **Ban traces** → [10](docs/10-cleaner-ban-traces.md) covers every on-disk forensic artifact.
- **HWID spoofing** → [11](docs/11-hwid-spoofing.md) covers every hardware identifier + per-field spoofer mechanics + ETW-TI constraints + BYOVD catalog + full spoof.sys deep dive.
- **Cheat detection** → [12](docs/12-cheat-detection.md) covers injection catalog, hooking patterns, hypervisor cheats w/ EPT page splitting, SMM, UEFI bootkits, DMA hardware, kmbox, GPU-executed cheats, real published exploits.
- **Emulation** → [13](docs/13-eac-emulation.md) covers live-server bypass reality + private-server architectures + PoC + three analyzed emulator comparisons.

---

## Confidence tiers

- **Verified by public RE** (Secret Club, published teardowns, this repo's analysis of shipping artifacts) — correct at architectural + behavioral level; constants rotate.
- **Reconstructed from behavior** — observed via live tracing, pipe captures, driver probing. Correct at "what it does"; specific instruction sequences will differ per build.
- **Inferred** — strong educated hypothesis from adjacent facts. Starting hypothesis for your own IDA session.

Verify everything against your own pulled binaries. The [verification checklist](docs/14-workflow-and-checklist.md#part-4--verification-checklist) is the list of specific values you must lift locally.

---

## Not in scope

- **Help getting unbanned.** Nothing here is an exploit or a way to beat server-side correlation. The emulation PoC explicitly does not bypass live-server session signing.
- **Current-build cheat code.** This document covers the *detection surface*. It does not ship cheats.
- **Binaries.** Pull them yourself from your own Fortnite install.

---

## Ack

Standing on public work:

- [Secret Club](https://secret.club/) — repeated EAC teardowns.
- [can1357 / NoVmp](https://github.com/can1357/NoVmp) — VMProtect devirtualizer.
- [VTIL-Core](https://github.com/vtil-project/VTIL-Core) — the IL NoVmp emits.
- [hasherezade / pe-sieve](https://github.com/hasherezade/pe-sieve).
- [wbenny / HyperDbg](https://github.com/wbenny/HyperDbg) — hypervisor-level debugger.
- UnknownCheats teardown threads whose authors go by handle-only — the deep-reversal in [02](docs/02-kernel-driver.md) is one of these, consolidated.
- `mrdhanz` / `@ShimadaNanaki` — UC EAC/EOS Linux-proxy emulator (analyzed in [analysis/02](docs/analysis/02-uc-linux-proxy-emulator.md)).

---

_Research notes. No license. Use responsibly — treat the repo as "notes a researcher might dump to a friend," not a how-to guide._
