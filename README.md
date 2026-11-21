# fortnite-ac-reversal

Deep reverse-engineering notes on Fortnite's full anti-cheat stack: Easy Anti-Cheat (classic + EOS variant), Fortnite's own integrity layer, HWID / fingerprint surface, trust-score mechanics, ETW-TI hazards, real-world emulator architectures, and an EAC emulation PoC.

Current-build era: **late-2026** (EAC agent `EAC_2026_*`, EAC driver v3.3+ Feb 2026 sign, Fortnite UE5).

**Refreshed Nov 19 2026** with UC community intel — see [doc 14 Part 10.5](docs/14-workflow-and-checklist.md#part-105--uc-community-intel-sources-nov-2026-pass) for source thread attribution.

> **Read before trusting any specific constant:** this is a map of the *architecture*. Offsets inside `EPROCESS`, altitude strings, XOR keys, AES salts, numeric IOCTL codes, pin hashes, and flag IDs rotate every few builds. Always re-derive constants against your own pulled binaries.

---

## What this repo lets you do

Everything below is unlocked by the material in these docs + the three PoCs. Each bullet is one concrete capability.

### EMULATION
- Build a drop-in replacement for the bundled EasyAntiCheat_EOS.dll (`b.dll` — 5 unnamed ordinals at RVAs 0x4FEA3 / 0x22DE30 / 0x30A0E0 / 0x4FCE2 / 0x2F2760)
- Build a drop-in replacement for `a.dll` (launcher wrapper, 5 named exports `a,b,c,d,e`, heavy export `d` at RVA 0x2DDB2)
- Stand up an EAC-shaped Windows service (`EasyAntiCheat_EOSSys`) that passes local verify-installation checks
- Expose a pipe server on `\\.\pipe\EasyAntiCheat_EOS` that handshakes correctly with a game process
- Create the 3 named events (`EventDriver`, `EventGame`, `EventModule`) + 64 KB shared-memory mapping EAC's IPC expects
- Seed the 23 `ErrRpt_*` registry values under `HKLM\Software\EasyAntiCheat_EOS` to look like a prior clean session
- Stub the TPM attestation registry surface (`QuoteKeyStatus`, `QuoteKeyStatusCode`, `EacQuoteKey`, `PcpTpmPersistentKeyBlob`, `AttestationKey`)
- Implement all 6 setup-CLI subcommands (`install`, `uninstall`, `repair`, `verify-and-install`, `verify-installation`, `qa-factory-reset`)
- Emulate `\Device\EasyAntiCheat_EOS` driver IOCTL surface (SESSION_AUTH, READ_MEM, GET_VAD, ENUM_HANDLES, DRIVER_LIST, CALLBACK_DUMP, SELF_CHECK)
- Fake the EventLog subscription surface so the service appears to monitor tamper evidence
- Emulate the telemetry upload channels (`sdkevents` + `eteventstream`) over mock HTTP endpoints
- Mock the EOS SDK Platform/AntiCheat Client interfaces (`EOS_Platform_GetAntiCheatClientInterface`, `BeginSession`, `EndSession`, `PollStatus`)
- Implement the `AddNotify*` callback registration surface (return `EOS_NotificationId` not `EOS_EResult`)
- Register stub callbacks for `OnClientIntegrityViolated` + `OnMessageToServer` + `OnPeerActionRequired`
- Fake the Anti-Cheat Integrity CA11 PKI trust store at `EasyAntiCheat/Certificates/` so cert verification passes
- Emulate the launcher wrapper's full pre-flight sequence (DTrace, DotLocal, UEFI boot config, Secure-Core, ARM64, Win10 22H2, kernel-mods, driver verifier, case-sensitive path)
- Produce a working `game.bin` stub that satisfies "executable_hashed" + "catalogue_present" checks locally
- Chain all 3 PoCs together (service + launcher wrapper + agent) into a complete on-host EAC-shaped stack
- Build a Linux-side EOS/EAC proxy that bridges a Windows game session (per UC-community pattern in docs/analysis/02)
- Build a self-provisioned EOS backend that signs its own session tokens for offline/private-server play
- Build a runtime RVA-patch bypass (per docs/analysis/03 MCC pattern) that neuters integrity callbacks in-process
- Mimic the full `EAC_LAUNCHERDIR` env var + Localization + Certificates directory shape expected by a real game

### BYPASS
- Patch the launcher's self-integrity hash check so you can run a modified agent DLL
- Launch `FortniteClient-Win64-Shipping.exe` directly (not `*_EAC.exe`) to skip the EAC launcher outright for research
- Inject via data-pointer-swap on an existing function table / callback pointer instead of `CreateRemoteThread`
- Hook into a legit running thread via pointer swap to avoid `PsSetCreateThreadNotifyRoutine`
- Invoke a manual-mapped module's init path via data-pointer swap instead of the Windows loader
- Build a cheat with no DllMain-style entrypoint (survives EAC's loader-callback detection)
- Patch the agent's SPKI pin check (memcmp → `mov al, 1; ret`) to MITM EAC TLS traffic
- Patch EAC's static assertions on HVCI / Memory Integrity / DSE state (bypass "DSE disabled" refusals)
- Bypass the launcher's blacklisted-driver check by renaming/altering the vulnerable driver's hash before load
- Bypass `error_driver_verifier_enabled` by unloading Driver Verifier before launch
- Bypass `error_dtrace_enabled` by disabling DTrace in BCD
- Bypass `error_dotlocal` by removing `.local` redirection files from game directory
- Bypass `error_patched_boot_loader` by restoring vanilla BOOTMGR / winload.efi
- Hook `NtCreateUserProcess` to filter EAC's child-process creation and interpose a monitored binary
- Call `ZwOpenProcess` without `OBJ_KERNEL_HANDLE` to acquire a useful handle to the protected game process from a BYOVD-loaded driver
- Allocate RWX in the game via `ZwAllocateVirtualMemory(MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)` from kernel
- Use `KeQueryAuxiliaryCounterFrequency` as a kernel→UM comms side-channel
- Use OBS's `graphics-hook64.dll` at offset 0x42DC8 as a signed trampoline for injection
- Use `inpoutx64.sys` (verified hash present in BYOVD catalog) as a loadable kernel R/W primitive
- Abuse the TempleOS driver (or any legacy WHQL-signed quirk) for arbitrary kernel execute
- Build a kernel-mode cheat that runs below EAC by mapping before EAC's driver initializes
- Skip EAC's session signature verification at game-side by patching the EOS signature-verify callsite
- Defeat Fortnite's own page-encryption anti-dump by hooking `KiUserExceptionDispatcher` before it trampolines decrypt
- Exceed Fortnite's 500-page decryption limit by patching the limit counter after first exception
- Run the agent on an older EAC version that skips newer scans (via `verify-installation` lying about version)
- Exploit UC community-documented published vulns (CVE-2020-XXXX drive-by patterns documented in doc 12)
- Build a client that passes the `b.dll` ordinal-1 init without executing the real scanner body

### CHEAT DEVELOPMENT
- Build a kernel-driver cheat using the full BYOVD catalog (RTCore64, GDRV, DBUTIL_2_3, GIO, inpoutx64, etc.)
- Build a hypervisor-level cheat with EPT page splitting (type-1/type-2 architecture per doc 12 Part 3)
- Build an SMM cheat that runs below ring 0 using documented SMM comm-buffer techniques
- Build a UEFI bootkit cheat (BlackLotus / CosmicStrand architecture reference per doc 12 Part 4)
- Build a DMA/PCILeech hardware cheat (Screamer tier + MemProcFS integration per doc 12 Part 5)
- Build a kmbox-style input injector via arduino/raspi USB HID emulation
- Build a GPU-executed cheat with compute-shader readback (NVIDIA / AMD paths per doc 12 Part 6)
- Build a user-mode internal cheat (manual-mapped, no DllMain, pointer-swap entry)
- Build a user-mode external cheat with DMA-free remote-read through shared-memory oracles
- Build a call-stack-spoofing cheat that evades EAC's return-address walker
- Build a hooking engine that avoids EAC's bundled known-good page baseline (manual relocations, not inline patches)
- Build an aimbot/triggerbot driver that reads game state via VAD walk instead of OpenProcess
- Build an ESP that renders via DirectX overlay hook (Fortnite's overlay detection surface documented)
- Build a radar hack that reads replay buffers for server-authoritative position leak
- Build an input-replay macro cheat that evades Fortnite's input anomaly scanner
- Build a cheat-as-a-service backend that signs loaders with an EV cert to pass BYOVD checks
- Target each named flag family in doc 04 to understand what triggers detection vs scanning noise
- Instrument every scanner in doc 04 Part 3 to understand its scan period + detection surface
- Build a cheat that stays below the daily correlation cadence by throttling its memory access rate
- Build a cheat that schedules all memory R/W during cutscenes / lobby to evade env_worker windows
- Pin-check-bypass via patched `g_pinSet` (per doc 04 Part 8) to allow self-signed TLS MITM
- Use the exploit-variant fingerprints ("SMEP Bypass (B)", "SMEP Bypass (C)") as detection-avoidance anchors

### SPOOFING
- Spoof CPUID vendor / family / model / stepping / brand (full per doc 11 Part 1)
- Spoof SMBIOS vendor / product name / serial number / UUID at all 4 collection paths
- Spoof disk serial via `IOCTL_STORAGE_QUERY_PROPERTY` hook + `ATA PASS-THROUGH` diversion
- Spoof MAC address via all 4 EAC collection paths (NDIS, ARP, ExUuidCreate seed, PCIe Config Space DSN)
- Spoof EDID (monitor identifier) via `D3DKMT_SETMONITORCUSTOMHDRSUPPORT` hook
- Spoof TPM Endorsement Key via Platform Crypto Provider interposition
- Spoof PCIe Device Serial Number via config-space write (BYOVD-dependent on vendor)
- Spoof ACPI tables (all 34 that real spoof.sys patches — SLIC, MSDM, SLIT, BERT, HEST, ERST, FPDT, NHLT, XSDT, RSDT, DSDT, etc.)
- Spoof firmware BIOS vendor / version / release date via SMBIOS Type 0 patching
- Spoof RAM SPD (DIMM part number / serial) via memory controller hooks
- Spoof GPU device ID + vendor ID + subsystem ID via WDDM filter driver
- Spoof Windows `MachineGuid` + `InstallDate` + `InstallTime` registry values
- Spoof `MachineAccountSid` + `MachineSecret` LSA secret via DPAPI tampering
- Spoof system boot time + first-install time across all tracked registry locations
- Spoof the Windows Experience Index baseline so hardware changes don't trip env_worker
- Build a complete HWID spoofer per the architecture requirements in doc 11 Part 4 (loader + filter driver + ETW-TI awareness)
- Understand the ETW-TI constraint (`shm PATCH_PTE refused`) that forces spoofers to avoid certain kernel memory writes
- Understand why TPM clear works for ban-wave evasion but cert re-issuance won't
- Use the WDAC Microsoft Vulnerable-Driver block-list to pick drivers EAC's own `DRIVER_LIST` IOCTL doesn't flag
- Track the BYOVD catalog + per-driver detection state (per doc 11 Part 3)
- Spoof network adapter instance-id / guid-registry (not just MAC) to defeat multi-point correlation
- Spoof ACPI DSDT hex-pattern anomalies that mark VMs (VMware / VirtualBox / Hyper-V / KVM signatures)
- Spoof GPU driver install time + VRAM size + feature-level flags
- Reset WER (Windows Error Reporting) UUID + Click-ID state
- Spoof per-NIC `PermanentAddress` vs `CurrentAddress` so both read identical and clean
- Choose the per-field spoofing weight (doc 11 Part 2) to maximize evasion / minimize detection risk per hour

### CLEANING / FORENSICS
- Enumerate every on-disk artifact EAC + Windows leaves (full per doc 10)
- Clean Prefetch (`C:\Windows\Prefetch\*.pf`) selectively or wholesale
- Clean Amcache.hve (`C:\Windows\appcompat\Programs\Amcache.hve`) InventoryApplicationFile entries
- Clean Shimcache (`AppCompatCache` registry blob) of EAC + game executions
- Clean BAM (`SYSTEM\CurrentControlSet\Services\bam\State\UserSettings`) per-SID activity
- Clean MUICache of DLL / EXE load records
- Clean SRUM `SRUDB.dat` (energy + network + app usage telemetry)
- Clean USN change journal (`fsutil usn deletejournal`)
- Clean VSS shadow copies that preserve pre-cheat state
- Clean WER crash dumps + reports under `C:\ProgramData\Microsoft\Windows\WER\`
- Clean Windows Timeline + ActivitiesCache.db
- Clean Shellbags / ShellNoRoam MRU
- Clean Thumbcache / IconCache
- Clean UserAssist + RecentApps + FeatureUsage registry
- Clean DPAPI master keys that bind cheat-era state to user profile
- Clean LSA secrets + cached credentials used for correlation
- Clean DriverStore (`C:\Windows\System32\DriverStore\FileRepository\`) of BYOVD remnants
- Clean NTFS low-level artifacts ($LogFile, $MFT entries, $UsnJrnl, $RmMetadata)
- Clean kernel memory dumps + minidumps + hibernation file remnants
- Understand why cleaning doesn't beat HWID bans (hardware signal vs software signal)
- Clean EAC-specific traces (service pipe handle records, named event records in Object Manager)
- Clean `EacQuoteKey` TPM-persistent key blob to force re-attestation
- Clean all 23 `ErrRpt_*` registry values to erase session telemetry
- Clean `pbrules.bin` / `game.bin` on-disk caches
- Clean the launcher wrapper's crash-feedback URL state
- Produce a reproducible cleaner script covering every artifact type in doc 10
- Investigate a banned machine forensically from these artifacts (the inverse use)
- Build a time-skew detector that identifies inconsistent timestamps left by cleaners

### DETECTION / DEFENDER
- Understand every scanner in EAC so defenders can mirror its surfaces (doc 04)
- Identify every IOCTL the driver exposes + what each returns (doc 02)
- Detect cheats that use the same manual-map architecture EAC itself uses (apply EAC's own detection rules upward)
- Detect call-stack spoofing via the same return-address walker EAC employs
- Detect ETW-TI tampering (patched provider GUIDs, suppressed notifications)
- Detect VMProtect-packed modules via characteristic entropy + import patterns
- Detect `PsSetCreateProcessNotifyRoutineEx2` pre-creation veto bypass attempts
- Detect kernel modifications via EAC's own `DRIVER_LIST` + WDAC cross-check
- Detect ObCallbacks tampering via altitude enumeration
- Build a trusted-launch verifier that mirrors the launcher wrapper's 10 pre-flight checks
- Build a defender-side TPM attestation verifier using the same `EacQuoteKey` pattern
- Detect spoofers by cross-correlating 4 MAC collection paths (any mismatch = tamper)
- Detect spoofers via `MachineGuid` ↔ `InstallDate` ↔ SMBIOS `UUID` consistency check
- Detect SMBIOS filler strings ("To be filled by O.E.M.", "System Manufacturer", etc.) as spoofer tells
- Detect vulnerable drivers via WDAC Vulnerable-Driver block-list + signer thumbprint
- Detect UEFI bootkits via Secure-Boot measured-log + TPM PCR values
- Detect DMA cheats via `IOMMU_RESOURCE_INVALIDATE` / IOMMU remap tables
- Detect kmbox devices via USB HID descriptor anomalies + timing fingerprints
- Detect GPU-executed cheats via GPU command-buffer monitoring (DXGI / NVAPI)
- Audit a user's on-disk state for cheat-era traces using the doc 10 artifact list
- Correlate `AntiCheat.Error.IntegrityViolation` telemetry events for ban-review workflows
- Build a tamper-evident telemetry pipeline mirroring EAC's `AntiCheat.*` event taxonomy
- Harden a game against the same cheats EAC targets by integrating the detection surface at the engine level
- Detect `ExUuidCreate` hooks (common spoofer technique for MAC injection into UUIDs)
- Detect `BgfxCopyContext` / overlay-renderer injection techniques
- Build a Fortnite-specific match-fraud detector using the server-authoritative movement/weapon/build checks in doc 07

### REVERSE ENGINEERING
- Reverse any VMProtect 3.x-packed binary using documented static + dynamic techniques (doc 08)
- Devirtualize VMProtect regions with NoVmp (covers ~70-85% of handlers per public RE)
- Hand-lift residual VMProtect handlers using unicorn-engine + VTIL
- Dump a manual-mapped module from a live process via memory enumeration + PE reconstruction
- Rebuild a stripped IAT using Scylla after a memory dump
- Walk the PEB loader-order list to enumerate manually-mapped modules EAC uses
- Reverse hash-dispatch patterns using the MurmurHash3 finalizer constant `0xFF51AFD7ED558CCD`
- Build a hash-reverse table for API resolution against current-build EAC
- Identify the 12 RSA public-key OID occurrences in the driver (first at 0x2C035B6)
- Identify the secp256r1 ECDSA OID at driver offset 0x303F8E
- Identify zstd compression magic (`0x28B52FFD`) in the agent at offset 0x233B87
- Parse the PE export table of any EAC DLL to extract ordinal + RVA mapping
- Analyze VMProtect's "cage" + flattened dispatcher pattern (doc 02 + doc 08)
- Reverse the module manifest format (45 tags in current build, offset 0x303530)
- Understand the "monster section" (+6.5 MB in current driver — VM handler bytecode)
- Reverse the pipe frame format `{len, seq, opcode, flags, crc32, body}` from observed traffic
- Reverse rules.bin section types (0x01 modules, 0x02 paths, 0x03 patterns, 0x10 processes, etc.)
- Reverse the TPM attestation flow via `rtbs.dll` + `TpmCoreProvisioning.dll` imports
- Reverse the EventLog subscription XPath template used by the service
- Reverse the 23-value `ErrRpt_*` registry schema
- Understand the 3-component user-mode layout (`a.dll` launcher wrapper + `b.dll` scanner + service EXE)
- Understand why `b.dll` has zero static imports (manual-map architecture proof)
- Understand why `b.dll` has 5 unnamed ordinals (name-less entry points)
- Use ETW-TI without triggering EAC's provider-tamper scan
- Trace the full boot-to-session flow end-to-end (doc 15 Part 2)
- Parse PE .rdata section strings systematically (UTF-16LE wide strings + ASCII)
- Extract all RSA public keys from a driver binary via OID scan
- Identify a file's crypto surface via mode-string survey (AES-128-CBC / AES-128-GCM / etc.)
- Identify the TLS implementation via cipher-suite naming convention (mbedTLS = dashes, BoringSSL = underscores)
- Understand the "cage" obfuscation technique used by VMProtect 3.x
- Day-by-day reversal plan + tooling stack (doc 14)
- Audit prior public RE claims against byte evidence (doc 14's correction cycle)
- Attribute UC community threads to specific findings (full source attribution in doc 14 Part 10.5)
- Build your own byte-scan tooling using the patterns documented across docs 02/04/15

### PROTOCOL / CRYPTO
- Parse the pipe frame format end-to-end (header + optional AES-GCM body)
- Construct a valid HELLO + WELCOME + CONFIG handshake sequence
- Craft a telemetry frame with correct CRC32 over the payload
- Decrypt a `pbrules.bin` file given the embedded root key + Epic RSA pubkey
- Verify the RSA signature on a `pbrules.bin` or `game.bin` using one of the 12 RSA pubkeys in the driver
- Implement HKDF-SHA256 key derivation with EAC's `info` string pattern
- Implement AES-GCM AEAD for pipe body encryption (128 or 256-bit)
- Implement the TLS 1.2 stack EAC uses with mbedTLS conventions
- Implement the EAC private PKI chain validation (CA11 root + Intermediate CA1 + CA10)
- Produce a mock TPM quote using Platform Crypto Provider
- Serialize the full `AntiCheat.*` event body format for telemetry replay
- Reverse the REMOTE_MODULE_LOAD opcode flow (server pushes signed modules at runtime)
- Serialize + sign a session attestation blob using RSA (not Ed25519 — corrected Nov 2026)
- Compute the SPKI pin set that EAC pins against (bundled fingerprints baked into the agent)
- Decode the `game.bin` per-game hash catalog format
- Implement a `CONFIG`-frame `enabled_modules` bitmap mapping
- Implement the agent's init-cookie exchange protocol with the driver (XOR'd IOCTL)
- Verify Authenticode signatures on EAC binaries using the exact DigiCert G4 chain
- Serialize crash-report blobs in the same shape the service uploads to `sdkevents`
- Reverse the `env_worker` fingerprint change-detection protocol (30s cadence)
- Implement a full EOS SDK-compatible AntiCheat Client transport layer
- Decode `AntiCheat.Info.SandboxProcess` + `AntiCheat.Error.IntegrityViolation` event bodies
- Implement the service's EventLog XPath subscription template programmatically
- Build a tool that re-signs arbitrary `pbrules.bin` for test purposes (research only — Epic's real key not reachable)

### RESEARCH / INFRASTRUCTURE
- Build a Fortnite private server (prior art: Project Reboot, Reload-FN, Project Era) — architecture reference in doc 13
- Reverse Fortnite's backend endpoint catalog (15+ endpoints documented in doc 07 Part 18)
- Mock the EOS SDK backend for offline-focused reversing (arbitrary platform URL via platform options)
- Build a UEFN Verse sandbox analyzer (what the sandbox allows vs forbids, per doc 07)
- Reverse UE5 integration surfaces (server-authoritative movement, weapon fire, building placement)
- Understand replay integrity (demo-file signing + tampering surfaces)
- Understand FNCS tournament integrity (competitive-grade additional checks)
- Understand cross-play trust model (PlayStation / Xbox / Switch / mobile delta)
- Understand mobile anti-cheat (Play Integrity API classic/standard tiers, iOS alternative)
- Understand cosmetic verification (anti-piracy pattern for V-Bucks / cosmetic entitlements)
- Research the three analyzed emulator architectures (desire_market full-emu, UC Linux-proxy, MCC in-process) — docs/analysis
- Build a HWID-rotation lab (TPM clear + MachineGuid rotation + SMBIOS swap per boot)
- Build a telemetry capture rig that logs every `AntiCheat.*` event for research
- Build a detection-rate measurement harness across cheat variants
- Build a correlation-lag measurement harness (how long from cheat run to ban)
- Build a per-build diff rig that auto-generates change summaries like doc 00
- Track the Nov 20 2026 build fingerprint (hashes, PE timestamps, section sizes) as baseline for future diffs
- Build a UC-thread-to-finding attribution index (template in doc 14 Part 10.5)
- Build a cheat-wave timeline (2019 Winter / 2020 World Cup / 2021 RTCore64 / 2022 LAPSUS / 2023 BlackLotus / 2024 Reboot / 2025 DMA) for cheat-market research
- Build a BYOVD-tracking dashboard integrating WDAC block-list + EAC `DRIVER_LIST` output
- Research the account-trust-signal model (doc 07 Part 15-16) for fraud-detection research
- Research the match-level fraud surface (collusion / win-trading / stat-padding / smurf detection)
- Build a per-season rotation tracker (EAC rotates keys / constants per Fortnite chapter)

### TOOLING
- Extend `poc/eac-emu-stub/` with real ordinal matching against your target build
- Extend `poc/eac-service-emu/` with proper DACLs, real pipe framing, event signaling
- Extend `poc/eac-launcher-wrapper/` with real pre-flight stubs (DTrace/DotLocal/etc detection)
- Build a Scylla-based IAT reconstruction script keyed to EAC's import patterns
- Build a MurmurHash3 reverse-lookup table generator for current-build API resolution
- Build a `pbrules.bin` dumper/parser given a captured file
- Build a `game.bin` dumper/parser given a captured file
- Build a trace-cleaner implementing the doc 10 artifact list
- Build a HWID spoofer implementing the doc 11 field matrix
- Build an EAC telemetry proxy that logs all `AntiCheat.*` events to disk
- Build a Fortnite private-server stub (prior art + docs/13)
- Build a BYOVD loader that integrates WDAC block-list check + signer thumbprint whitelist
- Build a VMProtect devirtualizer wrapper that integrates NoVmp + unicorn fallback
- Build an ordinal-table lifter for current-build `b.dll` (dumpbin + custom parse)
- Build a byte-scan toolkit using the documented OID / magic / constant patterns
- Build an ETW-TI awareness harness that demonstrates provider tampering detection
- Build a correlation-cadence measurement tool (daily vs weekly ban waves)
- Build a per-build change-diff tool that auto-produces changelog entries like doc 00 Part 2
- Build a per-scanner feature-flag enumerator against the agent DLL
- Build a session-state replay tool to compare pre/post EAC session telemetry
- Build an automated UC-thread monitor that ingests new RE findings
- Build a correction-cycle template (like doc 14 Part 10.5) for tracking repo corrections per build


---

## Nov 20 2026 EAC update — what changed

Fortnite's Easy Anti-Cheat shipped a major update on Nov 17 2026 (~13 hours before the Nov 20 repo refresh). The byte-verified delta across the 4 shipped binaries (driver + agent + launcher wrapper + service EXE):

### + What's new (added in the Nov 20 2026 build)

- New launcher pre-flight error codes: `error_dtrace_enabled`, `error_dotlocal`, `error_patched_boot_loader`
- New error codes continued: `error_missing_secure_core_feature`, `error_unsupported_arm64`, `error_win10_22h2_required`
- New error codes continued: `error_unrecognized_blacklisted_driver`, `error_kernel_modified`, `error_driver_verifier_enabled`, `error_case_sensitive_game_path`
- New literal tool blacklist in packed.dll: BattlEye, ACE-BASE, EchoAC, MyhProt2 (AC conflicts)
- New tool blacklist: Cheat Engine, Xenos Injector, HideToolz, Global Hack, Iuebesks
- New tool blacklist: WinDbg, LiveKD, PCHunter64, PowerTool X64, WIN64AST, Windows Kernel Explorer, BlEM, CAIs, WinD64, TermDD
- New tool blacklist: CPU-Z, WinIO, RWDrv, WinPmem, WinDivert, Moonlight Engine
- New named exploit-variant fingerprints: `"SMEP Bypass (B)"`, `"SMEP Bypass (C)"`
- New EAC private PKI discovered: `Anti-Cheat Integrity CA11` root, `Intermediate CA1`, `Intermediate CA10`
- New `game.bin` per-game hash catalog concept with errors `error_catalogue_corrupted`/`error_catalogue_not_found`/`executable_not_hashed`
- New flag family `0x1Cxx` for environmental-fingerprint anomalies
- New signing cert thumbprint `3CD980E3BACD8FB6FB3F532AFF62753FB7DE47A8` (DigiCert G4, valid 2026-02-01→2029-02-01)
- New `REMOTE_MODULE_LOAD` pipe opcode pulling signed scanner modules from `modules-cdn.eac-prod.on.epicgames.com`
- New `PsSetCreateProcessNotifyRoutineEx2` pre-creation veto path on Win11 23H2+

### ~ What changed (behavior/implementation rotated)

- Hash-dispatch finalizer rotated: splitmix64 `0x9E3779B185EBCA87` (1071 sites) → MurmurHash3-style `0xFF51AFD7ED558CCD` (1176 sites)
- Driver grew 40,189,592 → 46,171,808 bytes; `.text` grew ~54 KB (`0x26F764`→`0x27C464`)
- Entry point moved `0x26F738` → `0x27C438`; monster section grew ~6.5 MB (`0x2316000`→`0x28B9000`)
- Module manifest offset moved `0x2CE200` → `0x303530`; tag count dropped 46 → 45 (`IZ` tag removed)
- `.pdata` grew by ~3056 bytes (more `RUNTIME_FUNCTION` entries = more functions compiled in)
- `ObRegisterCallbacks` altitude moved up from legacy `"321000"` to avoid colliding with newer AV products
- `DRIVER_LIST` IOCTL now returns image size + signer thumbprint + WDAC block-list state, not just name+hash
- Hook-detector baselines moved from tamperable `\KnownDlls` to bundled known-good pages shipped in the agent
- All telemetry transport consolidated to `api.epicgames.dev`; legacy `service.easyanticheat.net` now returns HTTP 410
- Ban-wave correlation cadence shortened from weekly to daily, with near-realtime bans on high-severity chains
- Record walker magic constant rotated off `0xE7AECCAE` / multiplier `-0x5163F18C` (both now 0 sites; new values unidentified)

### − What was wrong before (corrections to prior docs that are now fixed)

- MinaMeow's hash `0bbe6d48...340b9` was mislabeled "driver v3.2.0.0" — it's actually `EasyAntiCheat_EOS.exe` (service), not the driver
- Prior docs claimed Ed25519 everywhere (rules.bin sig, driver SELF_CHECK, agent init) — zero Ed25519 OID (`06 03 2B 65 70`) hits in any binary
- Actual signing is RSA: 12 RSA pubkey OID matches (`06 09 2A 86 48 86 F7 0D 01 01 01`) in driver `.rdata`, first at `0x2C035B6`
- Prior docs claimed ChaCha20-Poly1305 pipe AEAD — zero "ChaCha"/"Poly1305"/"XChaCha" strings in any of the 4 binaries; actual is AES-GCM
- Prior docs claimed TLS 1.3 support — only TLS 1.2 labels found (`master secret`, `key expansion`, etc.); TLS 1.3 labels are 0 occurrences
- Prior docs claimed BoringSSL — cipher-suite naming (`TLS-RSA-WITH-...` dashes) is the mbedTLS convention, not BoringSSL's underscore form
- Prior docs described the 34 MB driver blob as Oodle-compressed — it's plain, uncompressed VM/handler bytecode (Oodle present but unused on it)
- Prior docs described a classic `DllMain`-driven init chain for the agent — wrong; it's manual-mapped, `DllMain` never auto-fires
- Real init is export-driven via `EOS_AntiCheatClient_BeginSession`, not `DllMain(DLL_PROCESS_ATTACH)`
- Prior docs described only two user-mode components — confirmed three: launcher wrapper (`a.dll`), scanner agent (`b.dll`), service EXE
- Ntf-tag casing corrected to `NtFB`/`NtFf`/`NtFL` (capital F) — MinaMeow's post had a lowercase transcription typo

### = What was byte-verified this round (findings confirmed by direct bytes)

- Driver: SHA256 `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b`, 46,171,808 bytes, PE ts 2026-11-17 05:36:29 UTC
- Agent DLL `b.dll`: SHA256 `c4d06ee450c2770588416228a5692265c68e9ae7cb199b19c19c8af8784b5dc0`, 24,245,760 bytes, unsigned, zero imports
- Launcher `a.dll`: SHA256 `28b0756d2be21386ae826511deafec906976cf7e10db6e34856ad3b863ecd6e7`, 36,403,128 bytes
- Service EXE: SHA256 `0bbe6d48f45fc155f1c1d029df8de67f221b7329010164eda2dd06d7978340b9`, 1,041,336 bytes, 32-bit PE32, PE ts 2026-09-09 (unrebuilt this cycle)
- `b.dll` exports: 5 ordinals, 0 names — RVAs `0x4FEA3`, `0x22DE30`, `0x30A0E0`, `0x4FCE2`, `0x2F2760`
- `a.dll` exports: 5 named (`a,b,c,d,e`) — RVAs `0xC7837`, `0xC7892`, `0xC78C1`, `0x2DDB2` (heavy), `0xC78F3`
- zstd magic `0x28B52FFD` confirmed at agent DLL offset `0x233B87`, 2 occurrences
- 1 secp256r1 OID (`06 08 2A 86 48 CE 3D 03 01 07`) confirmed at driver offset `0x303F8E`
- Driver import table has exactly ONE import — `FLTMGR.SYS!FltRegisterFilter`, zero xrefs, never called
- Agent DLL zero static imports confirmed via PE import-table inspection — manual-map architecture proof
- Agent DLL retains 4 sites of the old splitmix64 constant `0x9E3779B185EBCA87` — different hash function per module
- AES mode strings counted in agent DLL: `AES-128-CBC` (6), `AES-128-GCM` (3), `AES-256-CBC` (6), `AES-256-GCM` (3)
- Signing cert thumbprint `3CD980E3BACD8FB6FB3F532AFF62753FB7DE47A8` confirmed identical across `.sys`, `.exe`, and packed `.dll`

---

## Contents

**Fortnite anti-cheat covered end-to-end in 15 core docs + analysis of 3 real emulators.** Each doc is a comprehensive reference for its category — nothing split across scattered files.

### Core docs

| | Doc | What's in it |
|-|-|-|
| 00 | [Current-build notes + Fortnite EAC history](docs/00-current-build-notes.md) | What's new vs historical. Fortnite's BattlEye → dual-stack → EAC-only timeline. Milestone cheat events that triggered hardening. **Read first.** |
| 01 | [On-disk inventory](docs/01-on-disk-inventory.md) | Every file EAC + Fortnite ship, every path. |
| 02 | [Kernel driver](docs/02-kernel-driver.md) | `EasyAntiCheat_EOS.sys` complete teardown. Raw offsets, splitmix64 hash dispatch, the cage, flattened dispatcher, 45-module manifest (down from 46), ETW-TI subscription, VAD walker, ObCallbacks strip. **Everything kernel-side.** |
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
