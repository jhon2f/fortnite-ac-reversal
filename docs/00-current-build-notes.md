# 00 — Current-build notes + Fortnite EAC history

Changelog from historical EAC (2018 Fortnite integration) to what's shipping on current Fortnite builds (**late-2026 / Nov 20 2026 build**). Read this before the architecture docs so you know which details are new.

Includes Fortnite-specific EAC history (BattlEye → dual-stack → EAC-only → EAC-EOS).

---

## Nov 20 2026 build fingerprint

| Artifact | Size | SHA256 | PE timestamp |
|-|-|-|-|
| `EasyAntiCheat_EOS.sys` (kernel driver) | 46,171,808 | `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b` | 2026-11-17 05:36:29 |
| `EasyAntiCheat_EOS.dll` (real scanner, `b.dll`, **UNSIGNED**, zero imports, 5 unnamed ordinals — manual-map target) | 24,245,760 | `c4d06ee450c2770588416228a5692265c68e9ae7cb199b19c19c8af8784b5dc0` | 2026-11-17 13:34:50 |
| `EasyAntiCheat.packed (1).dll` (launcher wrapper, `a.dll`) | 36,403,128 | `28b0756d2be21386ae826511deafec906976cf7e10db6e34856ad3b863ecd6e7` | 2026-11-17 13:40:14 |
| `EasyAntiCheat_EOS.exe` (service/setup, 32-bit) | 1,041,336 | `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9` | 2026-09-09 14:20:48 |

Signing cert (sys + exe + packed-dll):
- Thumbprint: `3CD980E3BACD8FB6FB3F532AFF62753FB7DE47A8`
- Issued by: DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1
- Valid: 2026-02-01 → 2029-02-01
- Subject: `CN=Epic Games Inc., O=Epic Games Inc., L=Cary, S=North Carolina, C=US`

> **CORRECTION**: Earlier revisions of this repo attributed hash `0bbe6d48...340b9` to "the driver v3.2.0.0" (per MinaMeow). That hash is actually the **service EXE** (1 MB, 32-bit PE32), not the driver. MinaMeow mislabeled her own file. The real driver (now 46 MB in current build) has hash `3eabcfe9...5d2b`.
>
> **CORRECTION (supersedes doc 01)**: Doc 01 §95-98 (citing UC thread 772331) describes the bundled `EasyAntiCheat_EOS.dll` as a "forwarder/loader stub" with the real scanner dropped at runtime to `C:\Windows\System32\eac_usermode_<Random>.dll`. That was the **prior architecture**. In the Nov 20 2026 build, byte evidence shows the bundled 24 MB DLL (zero imports, 5 unnamed ordinals) **is itself the manual-map target** — it is the real scanner, not a stub. Doc 00 is authoritative here; doc 01's claim is historical.

---

## Part 1 — Fortnite's anti-cheat history

| Period | Anti-cheat | Notes |
|-|-|-|
| 2017 (launch — early BR) | **BattlEye** | Original Fortnite AC |
| 2017-2018 | BattlEye + EAC experiments | Epic began testing EAC integration before acquiring EAC |
| 2018 (October) | **Epic acquires Easy Anti-Cheat Oy** | Finnish company founded 2006; Epic now owned both the game and the AC |
| 2018-2021 | **BattlEye + EAC dual stack** | Both ACs ran simultaneously; cheat devs had to defeat both |
| 2021 | **EAC only** (BattlEye dropped) | Epic consolidation move |
| 2022+ | EAC migrating Classic → EOS variant | `EasyAntiCheat_EOS.*` stack |
| 2023+ | VMProtect 3.x, bundled hook baselines | (prior revisions listed "Ed25519 signatures" here as a transient historical entry; the Nov 20 2026 byte-scan found zero Ed25519 OIDs — see Crypto correction below. Current signatures are RSA / ECDSA-P256.) |
| 2024+ | ETW-TI subscription, `env_worker` drift detection | |
| 2024+ | TPM attestation via `EacQuoteKey` | Hardware-rooted trust |
| 2025+ | `PsSetCreateProcessNotifyRoutineEx2` with veto | Win11 23H2+ only |
| 2025+ | AES-256-GCM rules.bin | Up from AES-128-CBC |
| 2025+ | Daily correlation cadence | Down from weekly ban waves |

The dual-stack period (2018-2021) was unusual — both ACs ran in parallel. Each caught different cheat categories. **Fortnite private-server emulators specifically target the pre-2021 dual-stack configurations or earlier where defeat conditions differ.**

---

## Part 2 — Current-build headline changes

### Kernel driver

- **Expanded BYOVD matching.** `DRIVER_LIST` used to return name + hash. Now also returns image size, signer cert thumbprint, and the Microsoft WDAC vulnerable-driver block-list state. Renaming your vulnerable driver buys you nothing.
- **`PsSetCreateProcessNotifyRoutineEx2` on win11 23H2+.** The newer kernel surface lets EAC veto process creation before it starts rather than just observe it.
- **ObRegisterCallbacks altitude moved.** Up from the old `"321000"` string into a higher band to avoid collisions with newer gamer-focused AV products.

### Crypto (CORRECTED Nov 20 2026)

Previous revisions of this doc claimed Ed25519 signatures and ChaCha20-Poly1305 for the pipe. **Byte-scan of the Nov 20 2026 build shows neither is present anywhere.** No Ed25519 OID, no ChaCha20 strings, no Poly1305 strings in any of the 4 binaries.

Actual crypto surface in current build:

- **Signatures**: RSA (12 RSA public-key OIDs embedded in driver; 24 RSA references in service). ECDSA with secp256r1 or brainpool curves via NCrypt (`CALG_ECDSA` in service). SHA256 / SHA384 hashes. No Ed25519.
- **Symmetric encryption**: AES-128/256 in CBC or GCM mode (`AES-128-CBC`, `AES-128-GCM`, `AES-256-CBC`, `AES-256-GCM` all present in agent DLL). Pipe encryption is almost certainly AES-GCM, not ChaCha20-Poly1305.
- **TLS**: TLS 1.2 ONLY. Agent DLL contains TLS 1.2 labels ("master secret", "key expansion", "client finished", "server finished", "extended master secret"). No TLS 1.3 labels anywhere.
- **TLS curves supported**: secp256r1, secp384r1, secp521r1, secp256k1, secp224r1, secp192r1, brainpoolP256r1, brainpoolP384r1, brainpoolP512r1.
- **Compression**: zstd confirmed in agent DLL (2 magic-byte occurrences). Oodle statically linked in launcher wrapper (full codec set: Kraken, Selkie, Mermaid, Leviathan, Hydra, BitKnit, LZB16, LZBLW, LZHLW, LZNA, LZNIB).
- **Hashing** (for internal integrity / dispatch): see hash-algorithm section below.

### Hash-dispatch algorithm CHANGED

Previous builds (MinaMeow v3.2.0.0) used splitmix64 finalizer constant `0x9E3779B185EBCA87` — 1071 sites in driver.

**New driver (Nov 17 2026, v3.3+) uses a MurmurHash3-style finalizer constant**:

```
0xFF51AFD7ED558CCD — 1176 sites in driver .text
```

SplitMix64's `0x9E3779B185EBCA87` has **0** occurrences in the new driver. The hash-dispatch algorithm itself was rotated. Hash-reverse tables derived against MinaMeow's constants will no longer work — new tables must be built against `0xFF51AFD7ED558CCD`.

MurmurHash3's second finalizer constant `0xC4CEB9FE1A85EC53` is NOT present — EAC uses a custom finalizer with just the first multiplier. "SplitMix-variant with MurmurHash3's first multiplier" is the characterization.

Agent DLL (`b.dll`) still has 4 sites of the old splitmix64 constant — different hash functions per module.

Record walker magic rotated too: old `0xE7AECCAE` and multiplier `-0x5163F18C` both have 0 occurrences. New magic not yet identified.

### Scanners

- **Dual frame-capture path.** DXGI OutputDuplication plus Win32 `Graphics.Capture` on win11.
- **Integrity hash set expanded.** Current builds hash `ntdll.dll`, `kernelbase.dll`, `win32u.dll`, and `dxgi`/`d3d11` stubs on top of the game's modules.
- **Hook-detector baselines moved on-DLL.** From `\KnownDlls` (tamperable) to bundled known-good pages shipping with the agent.
- **New `env_worker` thread.** Runs on ~30s cadence doing an environmental-consistency pass — pulls SMBIOS, MAC, disk serials, machine GUID, compares against session-init snapshots, flags drift. **Spoof-detector hedge.**
- **ETW-TI integration.** Driver subscribes to the `Microsoft-Windows-Threat-Intelligence` ETW provider for kernel-asserted suspicious events.

### Telemetry

- **All transport consolidated to `api.epicgames.dev`.** Legacy `service.easyanticheat.net` endpoints resolve but return 410.
- **~~AEAD on the pipe (ChaCha20-Poly1305)~~** — CORRECTED Nov 20 2026: no ChaCha20 or Poly1305 present in any binary. Pipe is almost certainly AES-GCM (both AES-128-GCM and AES-256-GCM present in agent DLL strings).
- **Compression with a baked dictionary.** Telemetry body is zstd — confirmed by zstd magic bytes (0x28B52FFD) at agent DLL offset 0x233B87.
- **New flag family `0x1Cxx` — environmental fingerprint anomalies.**
- **Daily correlation cadence.** Ban waves still exist but shortened from weekly to daily. High-severity flag chains trigger near-realtime bans.

### Nov 20 2026 build — launcher wrapper (packed.dll) NEW pre-flight blocks

The launcher wrapper (`EasyAntiCheat.packed (1).dll`, 36 MB) performs pre-flight environment checks before game launch. New error keys in this build (not present in prior builds):

- `error_dtrace_enabled` — Windows Dynamic Tracing (DTrace) must be off
- `error_dotlocal` — DotLocal DLL redirection must not be present (anti-hijack)
- `error_patched_boot_loader` — UEFI boot loader (bootmgr/winload) integrity — detects BlackLotus-class bootkits
- `error_missing_secure_core_feature` — Windows 11 Secure-Core feature required on compatible hardware
- `error_unsupported_arm64` — ARM64 Windows explicitly not supported
- `error_win10_22h2_required` — minimum OS raised to Windows 10 22H2
- `error_unrecognized_blacklisted_driver` — generic unrecognized driver category
- `error_kernel_modified` — PatchGuard-equivalent kernel integrity check
- `error_driver_verifier_enabled` — Driver Verifier running → block
- `error_case_sensitive_game_path` — per-directory case-sensitivity (NTFS modern feature) blocks

### Nov 20 2026 build — NEW tool/driver blacklist (plaintext in packed.dll)

Explicit named-tool blocks that fire in pre-flight. Every entry is a literal byte-string match:

**Anti-cheat conflicts** (refuses to run alongside):
- BattlEye, ACE-BASE (Chinese AC), EchoAC (Chinese AC), MyhProt2

**Cheat / cheat-dev tools:**
- Cheat Engine, Xenos Injector, HideToolz, Global Hack, Iuebesks

**Reverse-engineering / debug tools:**
- WinDbg, LiveKD, PCHunter64, PowerTool X64, WIN64AST (Chinese RE suite), Windows Kernel Explorer, BlEM, CAIs, WinD64, TermDD

**System / BYOVD-source tools:**
- CPU-Z (BYOVD source — cpuz141.sys / cpuz149.sys), WinIO (BYOVD), RWDrv (BYOVD), WinPmem (memory forensics driver), WinDivert (packet filter driver)

**Streaming / overlays:**
- Moonlight Engine (NVIDIA GameStream FOSS clone)

**Exploit variant fingerprints:**
- "SMEP Bypass (B)", "SMEP Bypass (C)" — specific SMEP bypass code variants detected by name

### Nov 20 2026 build — New EAC concepts (missing from prior docs)

**EAC's own private PKI — "Anti-Cheat Integrity CA"**

Agent DLL contains strings for an internal CA chain:
- `Anti-Cheat Integrity CA11` (root)
- `Anti-Cheat Integrity Intermediate CA1`
- `Anti-Cheat Integrity Intermediate CA10`

EAC runs its own CA independent of Microsoft WDAC. Used for signing internal artifacts (game catalogs, pushed scanner modules, server-session attestations). Error string `"EAC index certificate revoked"` confirms EAC maintains its own cert revocation.

**Per-game `game.bin` hash catalog**

Agent DLL contains strings referencing a `game.bin` file. Semantic: per-game hash catalog shipping with each title, signed by EAC's Anti-Cheat Integrity CA. Lists expected hashes for game files. Scanner validates every game file against it at launch. Errors:
- `game_error.error_catalogue_corrupted`
- `game_error.error_catalogue_not_found`
- `game_error.executable_not_hashed`
- `"Unknown game file"`
- `"Untrusted system file"`

### Nov 20 2026 build — kernel driver structural deltas vs v3.2.0.0

- `.text` grew ~54 KB (0x26F764 → 0x27C464)
- Entry point RVA moved (0x26F738 → 0x27C438)
- Monster section (VM/handler blob) grew ~6.5 MB (0x2316000 → 0x28B9000)
- Manifest tag block offset moved (0x2CE200 → 0x303530)
- Manifest tag count 46 → 45 (`IZ` tag removed)
- `.pdata` grew by ~3056 bytes → more `RUNTIME_FUNCTION` entries (more functions in driver)

### Remote scanner loading

- **`REMOTE_MODULE_LOAD` pipe opcode.** The launcher can push signed auxiliary scanner DLLs to the agent at runtime, pulled from `modules-cdn.eac-prod.on.epicgames.com`. Epic deploys new detections without shipping a new EAC version.

### Fortnite-side

- **UE5-current integration.** Classic `IOnlineAntiCheatCommon` and `IAntiCheatModularFeature` interfaces, same binding pattern.
- **Shipping exe signature-check on EAC init callback.** Current builds verify not just that EAC's init returned success but also that the init callback carried a signature (RSA or ECDSA — see Crypto correction above; no Ed25519 present) over session state that only the real EAC can produce. This is what breaks the simple-stub emulation approach on live Fortnite.

---

## Part 3 — What's unchanged

For completeness, because people assume lots of things changed that didn't:

- **Callback APIs.** `PsSetCreateProcessNotifyRoutineEx` (or Ex2), `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallbackEx`. Same surface, same semantics.
- **Handle strip mechanism.** Same `ObRegisterCallbacks` pre-op pattern, same strip mask.
- **VAD walker approach.** Still the gold standard for catching manually-mapped modules.
- **Caller authentication model.** User-mode agent still has to present a signed session blob to the driver at CREATE time.
- **VMProtect 3.x as primary obfuscator.** Ultra-mutation + import protection enabled.
- **No BSOD policy.** The driver still doesn't crash legit users on self-hash mismatch — it flags and reports, backend decides.

---

## Part 4 — What's gone

- **BattlEye.** Dropped around 2021.
- **Legacy `easyanticheat.net` transport.** DNS still resolves, HTTP 410 on new sessions.
- **AES-128-CBC rules.bin.** Replaced by AES-256-GCM.
- **RSA-PSS rules.bin signature.** Replaced — current signature is RSA (12 RSA pubkey OIDs in driver at 0x2C035B6) or ECDSA-P256 (1 secp256r1 OID at 0x303F8E). Earlier revisions of this doc claimed Ed25519; the Nov 20 2026 byte-scan found zero Ed25519 OIDs (`06 03 2B 65 70`) anywhere — see the Crypto (CORRECTED Nov 20 2026) section.
- **Trusting `\KnownDlls` for hook-detector baselines.** Bundled baselines now.

---

## Part 5 — Milestone cheat events (what triggered which EAC changes)

> **AUTHORITATIVE — read first.** Doc 07 Part 21 contains a partial duplicate of this timeline (missing the 2022 LAPSUS$ entry). This doc 00 version is the canonical one; doc 07's copy must defer to this list and should be treated as a cross-reference only. Updates land here first.

Specific events that triggered observable EAC changes:

### 2019 — Fortnite Winter Cheat Wave

- Massive hypervisor cheat deployment during the holiday season.
- Epic's response: emergency patch adding anti-VM timing checks in mid-December.
- Set the precedent for "major cheat events trigger mid-season EAC updates."

### 2020 — World Cup qualifier scandal

- Multiple accused cheaters in FNCS qualifiers.
- Epic rolled back prize distributions.
- Established the payout-hold policy still in use.

### 2021 — RTCore64.sys crackdown

- Microsoft added RTCore64 to WDAC block list.
- Many Fortnite cheats relied on it.
- Precipitated the move toward manual-mapped drivers + hypervisor cheats.

### 2022 — LAPSUS$ Nvidia breach

- Nvidia code-signing certs leaked.
- Several cheats briefly signed with leaked certs.
- Microsoft revoked within weeks.
- Reinforced the WDAC-at-load-time enforcement pattern.

### 2023 — BlackLotus era

- First publicly-disclosed UEFI bootkit bypass of Secure Boot (via CVE-2022-21894).
- Elite cheat vendors adopted bootkit persistence.
- EAC response: TPM attestation + Measured Boot PCR drift detection.

### 2024 — Project Reboot DMCA wave

- Epic went after Project Reboot derivatives aggressively.
- Multiple repos taken down.
- Private-server operators moved to pseudonymous hosting.

### 2025 — DMA proliferation

- Chinese FPGA DMA cards became $200 commodity.
- Fortnite ban wave specifically targeting DMA players.
- EAC added PCI configuration space enumeration + IOMMU state reporting.

---

## Part 6 — Version-triage quick tips

To figure out which EAC build you're staring at before you start reversing:

- **`SplashScreen.png` in the bundle folder** often changes shape when EAC hits a version boundary. Not reliable alone but useful for rough dating.
- **Agent build string in telemetry packets** (`EAC_2026_MM_DD` pattern). Lift from a pipe capture.
- **Signer cert thumbprint on `.sys` + `.dll`.** `signtool verify /pa /v`. Thumbprints and sign dates narrow down the window.
- **IOCTL dispatcher size.** Current-build driver dispatcher is bigger than historical (new IOCTLs added).
- **Imports tab in IDA on the `.sys`.** Exactly one import (`FLTMGR.SYS!FltRegisterFilter`) → current (everything else is name-resolved at runtime; see doc 02 §27, §64). 50+ imports → pre-2019.
- **Current rules.bin file size + magic** (`EACR` header + GCM structure + RSA or ECDSA-P256 sig at end = current-build; no Ed25519 — see Crypto correction).

---

## Part 7 — What might come next

Reasonable predictions based on trajectory (2026-2028):

- **Deeper TPM 2.0 integration** — attestation beyond just EK readout, into PCR-based policy enforcement.
- **Confidential compute** interactions — Intel TDX / AMD SEV-SNP for isolating EAC's own agent from hypervisor cheats.
- **CET integration** — using Control-flow Enforcement Technology against ROP-style cheats.
- **DRTM (Dynamic Root of Trust)** adoption — Windows' Secure Launch becomes EAC's baseline measurement.
- **Vulkan / explicit API hooks** — DXGI frame capture may extend to Vulkan swap chains.
- **AI/ML on the client side** — possible, with lightweight inference running locally to flag in-session anomalies pre-correlation.
- **Longer and more opaque correlation windows** — moving from daily to continuous correlation with Bayesian inference.

None guaranteed; all plausible based on 2026 trends.

---

## Part 8 — Build-triage signals (quick-reference)

| Signal | Location |
|-|-|
| EAC agent build string | Pipe `HELLO` message; also `.rdata` of `EasyAntiCheat_x64.dll` as UTF-8 `"EAC_YYYY_MM_DD"` |
| EAC driver build string | `.rdata` of `EasyAntiCheat.sys`, UTF-16 |
| Fortnite build version | `FortniteGame\Content\Build.version` (text file) OR `.rdata` of shipping exe |
| Fortnite UE engine version | UE5 build string in shipping exe's version info |
| EOS SDK version | `FileVersion` resource of `EOSSDK-Win64-Shipping.dll` |
| Driver signing cert thumbprint | `signtool verify /pa /v` on the `.sys` |
| Driver sign date | `signtool verify /pa /v` timestamp signature |
| Rules.bin build-id | First 8 bytes after the `'EACR'` magic + version field |

Match 3+ of these to pin down the exact build context.

---

**Next:** [01 — On-disk inventory](01-on-disk-inventory.md)
