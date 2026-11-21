# Analysis 01 — desire_market full EAC-EOS emulator

Full-emulator approach shipping its own EOS product + HWID spoof driver + fake `FortniteLauncher.exe`. Analyzed from the `desire_market_eac_emulator.zip` archive.

**Not a Fortnite bypass.** A toolkit for provisioning your own EAC-protected product using Epic's official infrastructure, with bundled cheat-protection (HWID spoof driver) to protect your own test games from external memory readers.

---

## File manifest

| File | Size | Role |
|-|-|-|
| `start_protected_game.exe` | 3.99 MB | The protected-game launcher binary |
| `FortniteLauncher.exe` | 240 KB | **Fake FortniteLauncher** (small — real is bigger) |
| `EOSSDK-Win64-Shipping.dll` | 19.5 MB | Real EOS SDK bundle, not stubbed |
| `eacemu_emu.dll` | 1.23 MB | The emulator's user-mode agent |
| `eacemu_game.exe` | 6.9 MB | Test game executable |
| `spoof.sys` | 239 KB | **HWID spoof kernel driver** |
| `eos.json` | 468 B | EOS credentials (real) |
| `shipping.ep` | 42 B | Encrypted session blob (magic `SHP1`) |
| `eac_pack.zip` | 796 KB | Real EAC files (installer + settings + certs + localization) to deploy |

---

## eos.json — real EOS credentials

```json
{
  "product_name": "eacemu",
  "product_version": "1.0.0",
  "product_id": "49cfd1d86d7e48c89912d2eda7f0b59a",
  "sandbox_id": "389dd1abe82249ecaeed050b0d4b1a46",
  "deployment_id": "e01426dbd3fd4703a48a6c29c90c3dde",
  "client_id": "xyza7891a3fgfxTlNDJuQBjdJT43Mx1I",
  "client_secret": "969HzLYH8MMooC2bk+SmxvFEeVDshJT2T7twH1evECI",
  "server_client_id": "xyza7891tlrtamRbnOSNoM2rsUqgNGlU",
  "server_client_secret": "CiYGWiMPETkg1MhCscPU4pc2od7Th/+0mHv6rJCuw/Q"
}
```

### What this means

These are **real EOS credentials for a product called `eacemu`.** They were obtained by registering a product on the Epic Online Services developer portal. Epic doesn't vet what product names mean — "eacemu" is a dev name, and the sandbox is a regular dev sandbox with EAC enabled.

The `product_id`, `sandbox_id`, `deployment_id` form the identity triplet EOS uses to scope sessions. `client_id` + `client_secret` authenticate a client connecting to EOS. `server_client_id` + `server_client_secret` authenticate a game server reporting to EOS.

### What this enables

The emulator can mint **real EAC sessions** against Epic's backend — but **scoped to the `eacemu` product**, not Fortnite. Fortnite's `product_id` is Epic's, their `client_secret` is Epic's, and nobody outside Epic has it.

So: **the architecture is legitimate EAC + EOS integration. The "emulation" is of a Fortnite-like launcher chain, not of EAC itself.**

---

## Bundled EAC pack

`eac_pack.zip` contains a complete classic EAC-EOS installation tree:

```
EasyAntiCheat/
├── EasyAntiCheat_EOS_Setup.exe    985 KB
├── Settings.json
├── SplashScreen.png
├── Certificates/   (pinned certs)
├── Licenses/       (Apache 2.0 etc)
└── Localization/   (18 locale files)
```

This is **the real EAC-EOS installer**, which the emulator deploys into its game directory. The installer registers EAC as a service, drops the driver, sets up the service config — same as any EAC-protected game would.

The emulator then launches the game via `start_protected_game.exe`, which is a copy of Epic's standard "launch under EAC protection" wrapper. EAC spawns, injects into `eacemu_game.exe`, authenticates against the `eacemu` product's EOS infrastructure, and starts protecting.

---

## `spoof.sys` — bundled HWID spoof driver

Strings analysis reveals the full HWID spoof surface:

### Spoofed fields

**Windows identity:**
- `MachineGuid`
- `MachineSid`
- `SqmMachineId`

**SMBIOS:**
- `SmbiosBiosSerial`
- `SmbiosBoardSerial`
- `SmbiosChassisSerial`
- `SmbiosChassisAssetTag`
- `SmbiosSystemSerial`
- `SmbiosSystemUuid`
- `SmbiosProcessorId`
- `SmbiosProcessorName`

**Storage:**
- `DiskSerials`
- `DiskModelPrimary`
- `VolumeSerials`
- `RamSpdSerials`

**Network:**
- `NicMacAddresses`
- `MACAddress`

**Audio:**
- `AudioEndpointGuids`
- `AudioEndpointGuidPrimary`
- `AudioDeviceNames`

**Display:**
- `MonitorName`
- `MonitorSerial`
- `Adapters1`
- `HardwareInformation.AdapterString`

**Boot / firmware:**
- `BootCurrent`, `BootNext`, `BootOrder`, `BootOptionSupport`
- `SecureBoot`
- `WBCLColdboot`, `WBCLDrtmColdboot`
- `WindowsBootSession`
- `AcpiRegistryPatched`, `AcpiTablesPatched`
- `BootEfiActiveSec`

**ACPI tables spoofed** (strings verbatim from the driver):

```
DSDT SSDT FACP APIC DMAR IVRS HPET WAET MCFG BGRT TPM2 TCPA
SLIC MSDM SRAT SLIT BERT HEST ERST FPDT NHLT XSDT RSDT
OEM1 OEM2 OEM3 OEM4 DBG2 DBGP WSMT IORT LPIT
```

### Hooked driver stack

```
\Driver\Disk
\Driver\storahci
\Driver\stornvme
\Driver\storport
\Driver\USBHUB      \Driver\USBHUB3
\Driver\BTHPORT     \Driver\BTHUSB
\Driver\hidusb
\Driver\SMBUS       \Driver\AMDSMBUS      \Driver\amd_smbus
\Driver\i801        \Driver\smbctrl
\Driver\IntelTA
\FileSystem\Ntfs    \FileSystem\refs
```

### Spoofed PCI classes

```
{4d36e967-e325-11ce-bfc1-08002be10318}   Disk drives
{4d36e968-e325-11ce-bfc1-08002be10318}   Display adapters
{4d36e96e-e325-11ce-bfc1-08002be10318}   USB controllers
{4d36e97b-e325-11ce-bfc1-08002be10318}   SCSI and RAID controllers
```

### Configuration toggles

```
EnableFsctlSpoof
EnableSmbusSpoof
EnableAudioSpoof
```

Each a registry/config flag turning on a specific spoof subsystem.

### IPC

**Shared memory object: `\BaseNamedObjects\EacEmuShm`**

User-mode agent writes requests to a shared-memory block. The driver reads them, performs the requested operation, writes results back. Classic kernel ↔ user IPC pattern.

**Filter instance: `\Instances\XHWIDSpoofer Instance`**

The filter driver's registered instance name. Standard minifilter registration.

### Hardcoded fake values

Specific cached strings in the driver — fake hardware the spoofer can pretend to be:

- `Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz`
- `Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz`
- `Intel(R) Core(TM) i9-12900K CPU @ 3.20GHz`
- `NVIDIA GeForce RTX 3060 Ti`
- `NVIDIA GeForce RTX 3070 Ti`
- `(Realtek(R) Audio)`
- `(NVIDIA High Definition Audio)`
- `(USB Audio Device)`
- `(High Definition Audio Device)`
- `Digital Audio (HDMI)`
- `HDAUDIO`

Combined with ACPI spoofing, these form a complete "plausible system" — specific CPU/GPU/audio/chipset combinations that match real-world hardware.

### ETW-TI awareness

Critical strings:

```
shm PATCH_PTE refused (EAC TI ProtectVm)
shm ALLOC refused (EAC TI AllocVm)
```

**The driver explicitly detects EAC's TI subscription and refuses user-mode-requested operations (PATCH_PTE, ALLOC) that would trigger TI events.** See [11 — HWID spoofing § ETW-TI and kernel hazards](../11-hwid-spoofing.md) for the full context.

Operationally: **the spoofer is aware of EAC's observability and tries to not generate events EAC would see.** This is the state-of-the-art.

---

## `shipping.ep` — session blob

42 bytes, magic `SHP1`. First bytes:

```
53 48 50 31 fc 7c 14 0c 20 00 48 83 ec 28 e8 0b
00 00 00 48 83 c4 28 e9 7a fe ff ff cc cc 48 89
5c 24 18 55 48 8b ec 48 83 ec
```

After the `SHP1` magic, the bytes `48 83 EC 28 ...` are **x64 function prologue instructions** (`sub rsp, 28h`). This looks like an **embedded-executable format** — a small signed blob containing executable code the launcher runs after verification. Probably the EAC init-callback that produces the Ed25519 signature (see [13 — EAC emulation](../13-eac-emulation.md)).

42 bytes is small. Likely a header + first-page fragment of a larger blob fetched at runtime from Epic.

---

## How the launch chain works

1. **User runs `start_protected_game.exe`** — the standard EAC-EOS launcher wrapper.
2. **Launcher reads `eos.json`** — identifies the `eacemu` product and gets credentials.
3. **Launcher triggers `EasyAntiCheat_EOS_Setup.exe`** from the `eac_pack.zip` if EAC isn't installed — installs the service, driver.
4. **EAC service starts.** Driver loads.
5. **`spoof.sys` loads** — either alongside EAC via auto-run service config, or pre-boot via boot driver. Starts spoofing HWID.
6. **`FortniteLauncher.exe` (fake) runs** — issues a signed session token for the "game" (actually `eacemu_game.exe`).
7. **Launcher spawns `eacemu_game.exe`** via EAC's standard protected-launch path.
8. **`eacemu_emu.dll` gets injected** by EAC into the game process (or loaded via `DLLOVERRIDES` as a side-loaded module).
9. **The emulator DLL + real `EOSSDK-Win64-Shipping.dll`** talk to Epic's backend using the `eacemu` product's credentials.
10. **EAC authenticates against `eacemu`'s product**, protects the game session, reports telemetry to Epic under the `eacemu` product ID.

**End state:** a "protected game" running under EAC, on Epic's infrastructure, scoped to the dev's own product, with HWID spoofed against external cheat tools.

---

## What this does NOT do

- **Does not play Fortnite.** The `eacemu` product is not Fortnite. The real Fortnite product_id + sandbox_id + client_secret are Epic-internal.
- **Does not bypass Fortnite's server-side correlation.** Fortnite's backend only accepts sessions from Epic's own products.
- **Does not disable EAC.** EAC runs normally — it's protecting the emulator's own game against cheaters.

---

## What this reveals about EAC architecture

Three insights:

1. **EAC is sold as a service through EOS.** Any developer can provision a protected product with their own EOS credentials.
2. **The protection model is per-product.** Each product has its own sandbox, its own keys, its own trust state in Epic's backend. No cross-product trust.
3. **The spoof driver is a separate concern from the emulator.** HWID spoofing is about protecting *your own* product against external cheaters who'd read your game's memory. It's not about bypassing EAC's own checks.

The emulator ships as a package because dev-provisioned EAC-protected products need both: real EOS integration (via official credentials) **and** some anti-cheat on top of what EAC gives you (because EAC's default protection doesn't cover memory reading from kernel, which commercial cheats do).

---

## Fortnite relevance

**Zero direct relevance.** You can't use any of this to play Fortnite.

**Indirect learning:**

- The HWID spoof surface in `spoof.sys` is the complete current-build surface (see [11 — HWID spoofing](../11-hwid-spoofing.md) and [11 — HWID spoofing § ETW-TI hazards](../11-hwid-spoofing.md)).
- The ACPI table list + boot variable list tells you exactly what a durable spoofer must handle.
- The ETW-TI constraint ("shm PATCH_PTE refused") is confirmed in the wild.
- The hooked driver list is a map of where the storage / network / display / USB / SMBUS / audio stacks hang together for spoofing purposes.

---

**Next:** [02 — UC Linux-proxy emulator](02-uc-linux-proxy-emulator.md)
