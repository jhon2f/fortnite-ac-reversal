# 14 — Workflow, verification checklist, and audit corrections

How to approach reversing EAC against Fortnite, the environment setup, the specific values you must verify against your pulled binaries, and an audit of specific claims elsewhere in this repo.

---

## Part 1 — Reversal plan

No magic. Plan on 2-3 weeks of focused work for a specific EAC version.

### Week 1

**Days 1-2 — File acquisition.**

- Pull everything per [01 on-disk inventory](01-on-disk-inventory.md).
- Hash it all.
- Snapshot copies that you never touch, work on the copies.

**Days 3-4 — Kernel driver.**

- Static pass in IDA.
- Identify all callback registrations.
- Document the IOCTL dispatcher.
- Enumerate every IOCTL's semantics.

This is the foundation — everything else depends on understanding what services the driver provides.

### Week 1-2

**Days 5-9 — User-mode agent.**

- Dump from memory, fix IAT with scylla.
- Devirt VMProtect with NoVmp.
- Hand-fix residual handlers.
- Label the subsystems.

This is the longest single chunk.

### Week 2

**Day 10 — rules.bin.**

- Find the root key.
- Implement decrypt.
- Dump the plaintext.

Biggest-payoff-for-smallest-effort item.

**Day 11 — Pipe protocol.**

Short, since you already understand most of it from reversing the agent.

**Days 12-13 — Network layer.**

- Find the pin.
- Patch it.
- MITM a session.
- Decode telemetry packets.

### Week 2-3

**Days 14-16 — Fortnite game-side integrity.**

- Big binary (200+ MB).
- UE5 reflection dumps (unreal-dumper and similar) for type info first.
- Then focused reversing on `IOnlineAntiCheatCommon` and the movement/weapon validation code.

### Week 3

**Day 17 — EOS variant delta pass.** Quick if you did classic EAC first.

**Day 18 — Writeup.** Consolidate IDBs, notes, extracted artifacts into a single document. (This repo is the shape that writeup should take.)

### Time scaling

- Double all time estimates if you've never done kernel RE or VMProtect devirt.
- Triple them, honestly.

---

## Part 2 — Environment setup

### Do not reverse on your gaming machine

EAC telemetry is continuous even when Fortnite isn't running — the service stays up, the driver keeps its callbacks installed. Running IDA alongside Fortnite will not immediately ban you, **but** having the EAC backend observe IDA's process tree on the same hardware ID that plays Fortnite is a data point they can use.

### Dedicated VM

- Hyper-V or VMware.
- Fresh Windows install.
- Snapshots before every EAC launch.
- Second NIC for isolation.

### Do not run Fortnite inside the VM

Unless you have a hidden-hypervisor build of your hypervisor — EAC's anti-VM flags will surface and your account's fingerprint will tie to that VM's "hardware."

### Kernel driver work needs test-signing-mode or a DSE bypass

Do that on a machine you don't care about. HVCI will fight you — disable it on your research VM. Secure Boot same.

### Keep two copies of everything

EAC updates overwrite the on-disk files silently if the service runs. One copy you work on, one copy you never touch so you always have a known-good version.

### PatchGuard is accidentally your friend

Modern Windows kernel policy means EAC cannot inline-hook ntoskrnl or do SSDT games — they have to use legal callback APIs. That bounds what the driver can do and what you need to look for.

---

## Part 3 — Tooling

### Disassembler / decompiler

- **IDA Pro 8.4+** with Hex-Rays x64 decompiler — gold standard.
- **Ghidra 11+** — free alternative, weaker on VMProtect.
- **Binary Ninja 4.x** — strong HLIL.

### Unpackers / deobfuscators

- [`can1357/NoVmp`](https://github.com/can1357/NoVmp) + [`vtil-project/VTIL-Core`](https://github.com/vtil-project/VTIL-Core) — VMProtect devirtualizer + IL.
- Scylla (via x64dbg) — IAT reconstruction.
- UnpacMe (online) — convenience.
- Unicorn Engine — emulation helper.

### Debuggers

- **x64dbg** — user-mode.
- **WinDbg (preview)** — kernel.
- **KD** with VirtualKD or network kernel debugging — pair host + guest VM.
- [`wbenny/HyperDbg`](https://github.com/wbenny/HyperDbg) — hypervisor-based, bypasses EAC's anti-debug cleanly.

### Memory & process tools

- Process Hacker 2 / System Informer
- Process Monitor (procmon)
- ETW (Event Tracing for Windows) — WPA
- PE-bear / CFF Explorer — PE inspection
- [`hasherezade/pe-sieve`](https://github.com/hasherezade/pe-sieve)

### Network

- Wireshark 4.2+ with TLS 1.3 decryption support via keylog.
- mitmproxy 10+.
- Fiddler Everywhere.

### Kernel / driver

- DriverView (Nirsoft)
- DSEFix / KDMapper — **only on test systems.** Used to load an unsigned inspector driver for scanning EAC's driver. **Do not point these at production game sessions.**

### Note-taking

- Obsidian or plain markdown
- Hex-Rays Lumen for collaborative IDA DBs

---

## Part 4 — Verification checklist

Everything in the docs is a map. The specific values you MUST pull from your own pulled binaries before treating as correct constants:

### Kernel driver ([02](02-kernel-driver.md))

- [ ] Device name (random suffix)
- [ ] Symbolic link name
- [ ] `ObCallbacks` altitude string
- [ ] IOCTL XOR key
- [ ] Numeric IOCTL codes (after XOR)
- [ ] `ObCallback` strip mask for process AND thread
- [ ] Baked-in Epic pubkey location (for session_auth verification)
- [ ] Baked-in Epic pubkey location (for self-check signing)
- [ ] module manifest tag count (current build = 45)
- [ ] Handler feature-flag table layout
- [ ] Record walker magic constant
- [ ] Oodle blob offset + size
- [ ] Image B boundaries

### User-mode agent ([04](04-user-mode-agent.md))

- [ ] Agent build string (`EAC_YYYY_MM_DD` in `.rdata`)
- [ ] Session cookie XOR
- [ ] Pin hash set (count + SHA256 values)
- [ ] Rules.bin root key location
- [ ] Rules.bin signing public key location
- [ ] Zstd dictionary location (~8 KB blob near telemetry init)
- [ ] Event-name catalog (should match the list in doc 04 ± version-rotations)
- [ ] Flag-ID numeric values
- [ ] Telemetry endpoint hostnames
- [ ] List of modules the integrity timer hashes
- [ ] List of modules the hook detector compares against

### Rules.bin ([06](06-rules-bin.md))

- [ ] Magic, version
- [ ] Salt behavior
- [ ] AES-GCM IV length
- [ ] Root key
- [ ] Signing public key (RSA, 2048-bit or 4096-bit — resolve via sig-size check; possible ECDSA-P256 alternate)
- [ ] Section type numbers (may rotate)

### Pipe protocol ([05](05-pipe-protocol.md))

- [ ] Pipe magic
- [ ] Opcode numeric values

### EAC_x64.dll export ordinals ([07](07-fortnite-integrity.md))

- [ ] Export ordinal → function name mapping (positional from game's IAT)

When all filled in from YOUR pulled binaries, this repo's content is validated against your build.

---

## Part 5 — Audit — verified correct (high confidence)

Claims that cross-check against multiple independent sources:

### ETW-TI provider identity

**Claim:** EAC subscribes to `Microsoft-Windows-Threat-Intelligence` ETW provider. GUID `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`.

**Verification:** Provider name confirmed in Microsoft Learn documentation. GUID verified against `logman query providers` output on current Windows. **Correct.**

### Hash-dispatch finalizer constant

**Historical claim (MinaMeow v3.2.0.0):** `0x9E3779B185EBCA87` used 1071 times in the driver as hash mix (splitmix64 finalizer).

**Verification against v3.2.0.0 era**: Correct.

**Verification against Nov 20 2026 build**: **NOT CORRECT ANYMORE.** The driver has rotated to a MurmurHash3-style finalizer: `0xFF51AFD7ED558CCD` with 1176 sites. SplitMix64's `0x9E3779B185EBCA87` has 0 sites in the new driver. The agent DLL (`b.dll`) also uses the MurmurHash3-style finalizer for its primary hash-dispatch (see doc 15 Part 6.3); the 4 residual splitmix64 sites in `b.dll` are leftovers in non-dispatch paths, not a second active hash function. Driver and agent now share the same finalizer.

### Secure Boot PCR mapping

**Claim:** PCR 7 measures Secure Boot policy / DB / DBX / KEK / PK.

**Verification:** TCG PC Client Platform Firmware Profile Specification confirms. **Correct.**

### ObRegisterCallbacks altitude history

**Claim:** EAC historically used `"321000"` altitude. Current higher.

**Verification:** Multiple public RE reports from 2019-2022 period confirm. Current altitude rotates and must be lifted per build.

### Fortnite's BattlEye → EAC transition

**Claim:** Fortnite used BattlEye initially (2017), then EAC+BattlEye dual (2018-2021), then EAC only (2021+).

**Verification:** Public Epic announcements + community observations. **Correct.**

### WDAC driver blocklist mechanism

**Claim:** Microsoft maintains WDAC vulnerable driver block list, enforced at HVCI-level.

**Verification:** Microsoft Learn: "Microsoft recommended driver block rules." **Correct.**

### BYOVD driver list (RTCore64, GDRV, etc.)

**Claim:** Specific drivers listed as historically abused.

**Verification:** loldrivers.io catalog cross-references. All listed drivers appear there. **Correct.**

### CVE-2022-21894 ("Baton Drop")

**Claim:** CVE-2022-21894 enabled BlackLotus's Secure Boot bypass.

**Verification:** Microsoft's own CVE disclosure + ESET's BlackLotus analysis. **Correct.**

### Nvidia / LAPSUS$ 2022

**Claim:** LAPSUS$ breach of Nvidia leaked code-signing certs.

**Verification:** Widely reported in security press. **Correct.**

### Fortnite UE5 migration

**Claim:** Fortnite on UE5 (post-Chapter 4).

**Verification:** Epic announcement 2022. **Correct.**

---

## Part 6 — Audit — tightened (needs qualification)

### "VMProtect 3.5+" in current EAC

**Tightening:** VMProtect version in current EAC is **3.x** — exact minor version not publicly confirmed. Better claim: "VMProtect 3.x with ultra-mutation and import protection enabled."

### Specific ETW providers EAC subscribes to beyond TI

**Tightening:** Only `Microsoft-Windows-Threat-Intelligence` is confirmed via static evidence + the `spoof.sys` strings. Other providers listed (`Microsoft-Windows-Kernel-Process`, etc.) are **plausible subscriptions**, not confirmed. Treat as "likely subset of EAC's ETW consumption, not exhaustive confirmed list."

### Current-build correlation cadence

**Tightening:** Based on community observations of ban-wave frequency. Not internally-confirmed. Could vary between daily and weekly depending on severity + account trust.

### TPM EK handle `0x81010001`

**Tightening:** `0x81010001` is one standard EK handle per TCG spec. Some implementations use `0x81000001` (older) or `0x81010002`. EAC likely enumerates standard EK handles rather than hardcoding one.

### Specific rules.bin section type numbers

**Tightening:** Section-type-to-meaning mapping is consolidated from multiple public RE reports. Specific numbers may rotate per rules.bin version. Shape of per-section entry format is stable; exact type numbers are per-build.

### Epic HSM claims

**Tightening:** **Speculative** — Epic hasn't disclosed their key-management setup. HSM is **the industry standard** for session-signing key storage at Epic's scale, but "Epic specifically uses HSMs" is an inference.

### Fortnite's EOS product_id

**Tightening:** Fortnite's product_id has been publicly dumped. But the `client_secret` remains Epic-internal. Statement should be: "the `client_secret` is Epic-internal."

---

## Part 7 — Audit — specific corrections

### BCD registry location

**Correction:** BCD lives on disk at:
- BIOS systems: `C:\Boot\BCD`
- UEFI systems: `EFI System Partition\EFI\Microsoft\Boot\BCD`

The `HKLM\BCD00000000` hive is a **temporary mount** performed by `bcdedit`. Writes via `bcdedit` are visible to `CmRegisterCallback` watchers; writes directly to the file bypass this (but are catchable via NTFS filter / Measured Boot drift).

### EAC on mobile Fortnite

**Correction:** Fortnite mobile **does not run EAC at all**. The anti-cheat on mobile is entirely:
- Platform-level app signing.
- Epic's own attestation via Fortnite app.
- Server-side authoritative checks.
- Google Play Integrity API (Android, if applicable).

No kernel driver exists on mobile. The EAC stack is PC-specific.

### "Fortnite doesn't support Linux/Proton"

**Clarification:** Fortnite **doesn't support Linux-via-Proton**. Fortnite has no native Linux port. The negative is "Epic didn't opt into Proton compatibility." Technically EAC on Proton exists; Epic chose not to enable it for Fortnite.

### Build-placement reach distance check

**Correction:** Reach distance validation is **part of the general build-position validation** — not a separate named check. Server simply verifies the proposed position is within the player's max-build-range + line-of-sight requirements.

### Trust-level per-handler flag count

**Correction:** The 46 count (now 45 in Nov 20 2026 build after `IZ` removal) refers to the `.rdata` tag block at `0x2CE200` (now `0x303530`). Not every tag necessarily corresponds to a feature-flaggable handler — some are infrastructure (`Cont`, `Dcdd`). Confident-flaggable handlers probably ~30-35 of the 45 tags.

### MCC bypass RET+NOP*4 byte-level

**Clarification:** The 5 bytes replace what was almost certainly a standard x64 function prologue (`48 89 5C 24 08` = `mov [rsp+8], rbx` or similar). Patched: `C3 90 90 90 90` (`ret; nop*4`). Effect: the function returns immediately. Caller's expected return value is whatever RAX held when the function was entered — if `if (func() != 0) fail();` and RAX happened to be 0, the check passes.

### "Theia" event name

**Clarification:** `AntiCheat.Error.Theia` is EAC's internal telemetry subsystem event for inconsistent state (agent ↔ driver disagreement). Not a cheat-detection event directly; a self-health event. Correlation to bans: `Theia` events in isolation don't trigger action. `Theia` combined with `IntegrityViolation` events in the same session suggests active tampering.

### Shipping.ep format

**Clarification:** The `shipping.ep` file in the desire_market analysis starts with magic `SHP1`. **"Shipping Package 1" format** — a signed executable payload format EAC uses for runtime-delivered modules. Structure:

```
+00  u32   magic         'SHP1'
+04  u32   payload_size
+08  u8[]  payload       (x64 PE or shellcode)
```

42-byte file is a header + prologue stub. Full payload is fetched at runtime from Epic's module CDN.

---

## Part 8 — Audit — unverified but plausible

### Specific commercial cheat prices

**Caution:** Community observation. Actual commercial cheat markets have wide variance. Hierarchy is correct; specific dollar amounts approximate.

### Attribution of specific detections to specific flag IDs

**Caution:** Flag ID groupings reconstructed from telemetry analysis. Numbers rotate. Specific prefix-to-category mappings should be treated as patterns rather than exact mappings.

### Console-specific anti-cheat details

**Caution:** Correct in principle. Specific platform-level mechanisms (Xbox/PS/Switch) vary. Not deeply reverse-engineered publicly.

### Fortnite ban duration specifics

**Caution:** Durations vary by severity and history. No published fixed schedule from Epic.

---

## Part 9 — Claims verified against analyzed artifacts

### UC emulator architecture

**Source:** `eac-emulator_[unknowncheats.me]_.zip` full source.

**Verification:** Code inspection confirms Windows side = EOSSDK proxy DLL with 677 exports; Linux side = `version.dll` loaded via `WINEDLLOVERRIDES`; transport = WebSocket 7777 + HTTP 7778; MinHook used for `UnityMain` hook on Linux side.

All architectural claims in [analysis/02](analysis/02-uc-linux-proxy-emulator.md) are **code-verified**.

### MCC bypass patches

**Source:** `mcc_[unknowncheats.me]_.zip` full source.

**Verification:** Code inspection confirms `kEosPatchRva = 0x3AD910`, `kEosPatch = {0xC3, 0x90, 0x90, 0x90, 0x90}`, per-title RVA tables, `kMccSessionRva = 0x4000A48` with field offsets.

All claims in [analysis/03](analysis/03-mcc-in-process-bypass.md) are **code-verified**.

### Desire_market file layout

**Source:** `desire_market_eac_emulator.zip` extracted.

**Verification:** File inventory confirms `spoof.sys` (239 KB), `eacemu_emu.dll` (1.23 MB), `eos.json` with real EOS credentials, bundled `eac_pack.zip` with legitimate EAC-EOS installer.

All claims in [analysis/01](analysis/01-desire-market-emulator.md) are **file-verified**.

### spoof.sys HWID surface

**Source:** `strings` output on `spoof.sys`.

**Verification:** Every identifier field claimed in the HWID surface section was pulled from actual driver strings. ACPI table list is directly from the driver's string table. Hook target driver names are string-verified.

All claims about `spoof.sys` are **string-verified**.

### UC-forum driver reversal (read.txt)

**Source:** researcher's claimed month-long analysis.

**Verification:** The **structure** of claims (hash-dispatch + VMProtect protection + 46-module manifest + HWID formatter location) is **internally consistent** and consistent with other public EAC RE work. Note: the specific splitmix64 constant MinaMeow found was ROTATED to a MurmurHash3-style constant in the Nov 20 2026 build; the mechanism is unchanged but the specific constant is different.

Specific offsets should be treated as **the specific researcher's build-specific findings** rather than universal truths. Current builds may have moved offsets. The **techniques** are reliably present; the **numbers** are per-build.

---

## Part 10 — General caveat on specific constants

Every specific RVA, offset, byte sequence, constant, and build-specific number in this repo is **current-build-approximate**. These rotate per EAC update. Treat as "starting-hypothesis anchors for your own IDA session" rather than ground truth.

The **patterns** are stable:
- VMProtect is used.
- Hash-dispatched API resolution is used.
- 46-ish-module manifest exists.
- ObRegisterCallbacks strip is performed.
- rules.bin exists with signed sections.
- Telemetry to Epic over pinned TLS.
- SMBIOS history is tracked.
- ETW-TI integration limits spoofers.

The **numbers** (hash constants, altitudes, flag IDs, URL paths, product_ids) rotate. Verify locally.

---

## Part 10.5 — UC community intel sources (Nov 2026 pass)

Specific UC threads that provided corrections / additions to this repo. Attribution + dates.

| Thread | Author | What it added |
|-|-|-|
| [781475](https://www.unknowncheats.me/forum/anti-cheat-research/781475-reversal-eac-detection-dma-driver-hwid-collection.html) | **MinaMeow** (Nov 14 2026) | Full EAC driver reversal with build-specific fingerprints. Confirms driver v3.2.0.0. **Hash attribution error:** her hash `0bbe6d48...340b9` is actually the 1 MB 32-bit service EXE (`EasyAntiCheat_EOS.exe`), not the driver — see Correction #1. **Correction:** 34 MB blob is PLAIN, not Oodle-compressed. |
| [774464](https://www.unknowncheats.me/forum/anti-cheat-research/774464-eac-eos-emulator-proxy.html) | **DANNZ** (Sept 30 2026) | UC release thread for the Linux-proxy EAC-EOS emulator. Community confirms: only free-tier EAC games; doesn't work on Rust or Fortnite. |
| [772331](https://www.unknowncheats.me/forum/fortnite/772331-dump-fortnite-eac.html) | **notaskid65** (Sept 2026) | Fortnite's `PAGE_NOACCESS` + `KiUserExceptionDispatcher` trampoline anti-dump mechanism. 500 page decryption limit. Similar to Byfron usermode. |
| [772331](https://www.unknowncheats.me/forum/fortnite/772331-dump-fortnite-eac.html) | **MichButChina + yardiuu** | EAC-EOS user-mode is **manual-mapped, random name** (`eac_usermode_<Random>.dll`) in system32. On-disk DLL is a forwarder. |
| [781548](https://www.unknowncheats.me/forum/fortnite/781548-kvm-fortnite.html) | **adversemiller** (legend, Nov 2026) | **Correction:** EAC does NOT care about VM timing. Nika-Read-Only (ApexCV) + AutoVirt (Scrut1ny) are viable paths. |
| [781256](https://www.unknowncheats.me/forum/anti-cheat-research/781256-eac-fortnite-internal-function-calls.html) | **Reubinator13** (legend, Nov 17 2026) | Function-unwind detection: EAC walks call stacks on external invokers; need 1:1 stack-flawless spoofing. |
| [781974](https://www.unknowncheats.me/forum/anti-cheat-research/781974-kdstealer-intercepting-loaded-driver-via-iqvw64e-vulnerability.html) | **xvorost9** (Nov 17 2026) | iqvw64e (Intel Ethernet Diagnostics) fingerprints: PE ts `0x5284EAC3`, Device `\Device\Nal`, IOCTL `0x80862007`, copy format `0x33`. KDStealer dumps kdmapper-mapped drivers. |
| [736216](https://www.unknowncheats.me/forum/anti-cheat-research/736216-eac-injector.html) | **stld + InsideExploit + Paysonism** (Feb 2026, legends) | Current-build public EAC injection pattern: BYOVD (`inpoutx64.sys` hash `f8965fdce...f221b`), reflective loader, `graphics-hook64.dll+0x42DC8` OBS trampoline, `KeQueryAuxiliaryCounterFrequency` as comm channel, **data-ptr-swap to call DllMain** (not Windows auto). |
| [781379](https://www.unknowncheats.me/forum/anti-cheat-research/781379-help-kernel-injector-eac-blocking-dllmain-trigger.html) | **Hec4te + Reubinator13 + bigslim04** (Nov 2026, legends) | EAC actively detects classic DllMain-triggered injection (APC + LoadLibrary + CreateRemoteThread). Working pattern: pointer-swap legitimate function pointer, hook into existing thread, no classic entrypoint. Module stomping is detected via file-vs-memory compare. |
| [782120](https://www.unknowncheats.me/forum/fortnite/782120-reversing-eac-emulator.html) | **Azazelsen + plitorq** (Nov 18 2026) | Paid Fortnite EAC emulators exist, VMProtect-packed, winhttp license-check. Public free ones don't work on Fortnite. |
| [781505](https://www.unknowncheats.me/forum/fortnite/781505-fortnite-hwid-ban.html) | **Averser** (Nov 16 2026) | Reinstall-Windows + spoof is the standard path out of HWID-lite bans. Software cleaners can't keep up with Windows-Update-generated traces. |
| [779558](https://www.unknowncheats.me/forum/fortnite/779558-aleaclient-exe-dump.html) | **ecco271k** (Nov 16 2026) | Fortnite mid-game ban symptom: packet-freeze + infinite queue on relaunch. |
| [781598](https://www.unknowncheats.me/forum/fortnite/781598-driver-worth.html) | **Kepiteo + mattdevs** (Nov 16 2026) | kdmapper's bundled iqvw64e almost certainly WDAC-blocked. Custom BYOVD + custom mapper is the current path. |

### Correction landed — Nov 20 2026 Fortnite EAC update binary analysis

The Nov 20 2026 Fortnite EAC update was dumped and byte-level analyzed. Multiple prior claims in this repo turned out to be wrong when checked against the actual shipped binaries. Full findings in `C:\Users\Vblak\Downloads\eac\REVERSAL_FINDINGS.txt` + `REVERSAL_FINDINGS_PASS2.txt` on the research machine.

**Corrections landed in this cycle:**

1. **Hash attribution fix** — MinaMeow's `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9` is the SERVICE EXE (`EasyAntiCheat_EOS.exe`, 1 MB, 32-bit PE32 — see doc 15 Part 11), not the driver as she wrote. The 40,189,592-byte (~38 MB) size she quoted matches neither the 1 MB service EXE nor the 46 MB driver and should be disregarded as a mismeasurement. Real driver hash in Nov 20 build: `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b` (46 MB).

2. **Hash-dispatch algorithm swap** — Driver no longer uses splitmix64 (constant `0x9E3779B185EBCA87` → 0 sites in new driver). Now uses a MurmurHash3-style finalizer with constant `0xFF51AFD7ED558CCD` (1176 sites). Hash-reverse tables derived against MinaMeow's constant are broken.

3. **No Ed25519 anywhere** — exhaustive OID scan of all 4 binaries found zero Ed25519 (`06 03 2B 65 70`) matches. Prior claims that rules.bin signatures / driver SELF_CHECK / agent init all use Ed25519 are **wrong**. Actual signing is **RSA** (12 RSA pubkey OIDs in driver alone) with possibly ECDSA-P256 for alternate paths.

4. **No ChaCha20-Poly1305 anywhere** — exhaustive string scan found zero occurrences. Pipe AEAD is **AES-GCM** (AES-128-GCM and AES-256-GCM strings present in agent DLL).

5. **TLS 1.2 only, not 1.3** — agent DLL has TLS 1.2 labels (`master secret`, `key expansion`, `client finished`, `server finished`, `extended master secret`) but zero TLS 1.3 labels.

6. **TLS implementation is mbedTLS, not BoringSSL** — cipher suite naming uses dashes (`TLS-RSA-WITH-…`) which is the mbedTLS convention, distinct from BoringSSL's underscore form.

7. **Manifest tag count 46 → 45** — `IZ` tag removed in current driver. Manifest offset moved from `0x2CE200` to `0x303530`.

8. **Three user-mode components confirmed** — not two. Launcher wrapper (`a.dll` / `packed.dll`, 36 MB, signed, named 5-letter exports) + scanner agent (`b.dll` / `EasyAntiCheat_EOS.dll`, 24 MB, UNSIGNED, ZERO IMPORTS, 5 ordinal exports) + service/setup (`EasyAntiCheat_EOS.exe`, 32-bit, 1 MB). The agent having zero imports is the smoking-gun proof of manual-map architecture.

9. **EAC runs its own private CA** — strings in agent DLL reference `Anti-Cheat Integrity CA11` (root), `Anti-Cheat Integrity Intermediate CA1`, `Anti-Cheat Integrity Intermediate CA10`. EAC signs its own internal artifacts (game catalogs, scanner modules, server session attestations) with this CA. Not previously documented in the repo.

10. **Per-game `game.bin` hash catalogue** — agent DLL contains strings referencing a `game.bin` file. Semantic: each title ships a hash catalog of its own files, signed by EAC's CA. Validated at scan time. Errors: `error_catalogue_corrupted`, `error_catalogue_not_found`, `executable_not_hashed`. Not previously documented.

11. **New signing cert** — thumbprint `3CD980E3BACD8FB6FB3F532AFF62753FB7DE47A8`, DigiCert Trusted G4 CA, valid Feb 2026 → Feb 2029. Replaces prior Nov 2025 cert.

12. **Explicit tool blacklist in launcher** — 20+ literal process/driver name blocks in packed.dll `.rdata`. Documented in [doc 12 Part 1.5](12-cheat-detection.md#part-1.5--launcher-wrapper-explicit-tool-blacklist-nov-20-2026).

13. **New pre-flight error codes** — DTrace, DotLocal, UEFI bootkit, Secure-Core-missing, ARM64-unsupported, Win10-22H2-minimum, driver-verifier, kernel-modified, case-sensitive-game-path. See [doc 12 Part 1.6](12-cheat-detection.md#part-1.6--launcher-wrapper-new-pre-flight-error-codes-nov-20-2026).

14. **zstd compression confirmed in agent DLL** — 2 zstd-magic occurrences at offset `0x233B87`. Used for telemetry body compression with baked dictionary.

15. **Monster section grew ~6.5 MB** in driver (0x2316000 → 0x28B9000) — more VM/handler bytecode.

16. **Driver entry point moved** from `0x26F738` to `0x27C438` (.text section grew ~54 KB).

17. **Record walker magic rotated** — old `0xE7AECCAE` and multiplier `-0x5163F18C` now have 0 occurrences each. New constants not yet identified.

18. **Service EXE not rebuilt** — PE timestamp Sept 9 2026 unchanged. Only driver + launcher-wrapper + agent-DLL got new binaries this cycle.

### Correction landed — DllMain init chain (Nov 19 2026)

**What was wrong:** Earlier revisions of [doc 04 Part 2](04-user-mode-agent.md#part-2--the-real-entry-model-not-a-classic-dllmain-chain) showed EAC's user-mode agent initializing from a classic `DllMain(DLL_PROCESS_ATTACH)` chain — pipe connect, driver auth, worker spawn, rules load, all inside DllMain.

**Why it was wrong:**
1. The real scanner is manual-mapped into the game process (not LoadLibrary'd) per MichButChina + yardiuu (thread 772331). Windows does **not** auto-invoke `DllMain` on manual-mapped modules.
2. EAC specifically **detects** classic DllMain-triggered injection as a cheat pattern — if EAC used the same pattern for its own agent, it would flag itself. Confirmed by Hec4te, Reubinator13, InsideExploit, bigslim04 (threads 736216, 781379).
3. The bundled on-disk `EasyAntiCheat_EOS_x64.dll` is a forwarder stub — its DllMain is minimal (likely just `DisableThreadLibraryCalls`). The actual scanner work is in exported functions.

**What's correct:**
- Initialization is **deferred and export-driven**. The EOS SDK calls into EAC's exports at lifecycle events.
- **`EOS_AntiCheatClient_BeginSession`** is the real entry point for session-specific work (pipe connect, driver auth, worker spawn, env sweep, hook install).
- Workers are torn down on `EOS_AntiCheatClient_EndSession`, not persistent across sessions.

**Cheat-side implication (also corrected in [doc 12 Part 2.5](12-cheat-detection.md#part-25--function-unwind--call-stack-detection--frame-counting)):** classic DllMain injection for cheats is **actively detected** by EAC's thread-callback + ETW-TI. Current public injection pattern (stld, thread 736216): BYOVD + manual map + `graphics-hook64.dll+0x42DC8` (OBS) trampoline + pointer-swap to call DllMain (not Windows automatic).

Credit: Sam's reviewer who flagged the original error, verified via UC threads 772331, 736216, 781379 (Nov 2026).

### Methodology note

All of the above pulled live from UC via MCP integration. Threads inspected at their latest 2-3 pages. **Forum content is untrusted data** — claims are community observations, not Epic-verified. Where observations conflict (e.g. CatCaller "only registry" vs SOHELDAGOAT "not enough"), both positions are documented in the relevant doc.

### What's consistent across UC

- MinaMeow's byte-level teardown aligns with earlier Secret Club + Mellow research on EAC architecture — the (46-tag, now 45) manifest, VMProtect usage, VAD walker, ObCallbacks strip are all independently corroborated.
- Community observations about Fortnite-specific behaviors (page encryption, manual-map, inf-queue ban) align with reverse engineering findings.
- Divergence exists on exact spoofer requirements — there's no consensus on the "complete" HWID surface because Epic doesn't publish it and the correlation model is opaque.

---

## Part 11 — Closing

Treat anything in this repo older than six months as a starting hypothesis, not gospel. EAC is a moving target. Windows is a moving target. The intersection is a constantly-shifting surface.

Repo accuracy: **high at architectural level, build-specific at constant level.**

Suggested use pattern:
1. Use architectural chapters as read-first context.
2. Use constants as starting-hypothesis anchors for your own analysis.
3. Verify specific numbers against your own live-pulled binaries.
4. Flag any discovered error back to the [GitHub repo](https://github.com/jhon2f/fortnite-ac-reversal) via issues.

---

**Back to:** [README navigation](../README.md)
