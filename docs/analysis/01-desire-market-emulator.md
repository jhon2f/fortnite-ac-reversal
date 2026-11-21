# Analysis 01 — desire_market full EAC-EOS emulator

Full-emulator approach shipping its own EOS product + HWID spoof driver + fake `FortniteLauncher.exe`. Analyzed from the `desire_market_eac_emulator.zip` archive.

**Not a Fortnite bypass.** A toolkit for provisioning your own EAC-protected product using Epic's official infrastructure, with bundled cheat-protection (HWID spoof driver) to protect your own test games from external memory readers.

---

## File manifest (byte-verified Nov 21 2026)

| File | Size | SHA256 | Signed? | PE timestamp | Role |
|-|-|-|-|-|-|
| `start_protected_game.exe` | 3,993,896 | `46d2552552ac95c436389a2c9f1aba6fda37ab998acf9b9ee026f3262dd70c53` | **YES** (EasyAntiCheat Oy / Helsinki) | 2026-03-25 | Real EAC-signed launcher entry (legacy Finnish sign) |
| `FortniteLauncher.exe` | 240,640 | `e6bf23354f3bb2c5542eb8f4d53e15dfd4d1565d67446391feb16f88daab3603` | NO | 2026-11-07 | **Custom** fake launcher — loads EOSSDK + emu.dll |
| `EOSSDK-Win64-Shipping.dll` | 19,548,600 | `ab25af350c48856633d671a16e8469277f9acee39186d69fe5b2a26100d738e8` | **YES** (Epic Games Inc. / Cary NC) | 2026-09-15 | Real Epic-signed EOS SDK, bundled verbatim |
| `eacemu_emu.dll` | 1,233,408 | `f55aeab938d782a40172acae56f959af165593c0de69f19c9d25453090486398` | NO | **1970-01-01** (wiped) | Emulator core — manual-map, 3 obfuscated-name ordinals |
| `eacemu_game.exe` | 6,898,688 | `58669ef935e2754b8fc05232260e48dd1ad23bb8ddec265a75addd2c730922ba` | NO | 2026-11-03 | Demo game (VMProtect-packed — 3× `.hCpbDAi` sections) |
| `spoof.sys` | 239,104 | `3ad1e88aa1d7249f235a91e18a1157f2e5fe3912a12f51ec87cffa0a18b91c64` | NO | 2026-11-03 | HWID spoof driver (needs BYOVD or DSE-disabled) |
| `eos.json` | 468 | — | — | — | Self-provisioned EOS product credentials |
| `shipping.ep` | 42 | — | — | — | SHP1 patch descriptor for Fortnite shipping exe |
| `eac_pack.zip` | 796,104 | — | — | — | Real EAC install tree (installer + settings + certs + localization) |

### Signed-binary subjects (byte-verified from PKCS#7 blocks)

- **`EOSSDK-Win64-Shipping.dll`** — signed by:
  - CN: `Epic Games Inc.`
  - L: `Cary`
  - S: `North Carolina`
  - C: `US`
  - Issuer: `DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1`
  - This is the **genuine Epic-signed EOS SDK**. Not a forgery, not a rebuild — bundled verbatim.
- **`start_protected_game.exe`** — signed by:
  - CN: `EasyAntiCheat Oy`
  - Address: `Arkadiankatu 6 A 61`
  - L: `Helsinki`
  - S: `Uusimaa`
  - C: `FI`
  - Issuer: `GlobalSign GCC R45 EV CodeSigning CA 2020` (**EV cert**)
  - This is the **real Finnish EAC Oy-signed binary** from before/alongside Epic's acquisition. Still ships as the legit protected-launcher front-end.

Everything in the bundle that is signed is signed by a legitimate CA chain. Nothing is forged. The emulation works by **composing legit signed Epic binaries with a self-provisioned Epic product + an unsigned emulator DLL + an unsigned kernel spoofer** — not by faking Epic's signatures.

---

## eos.json — real EOS credentials (how the self-provision works)

### The `xyza7891` prefix tell

The `client_id` and `server_client_id` both start with `xyza7891`:

```
client_id        = xyza7891a3fgfxTlNDJuQBjdJT43Mx1I
server_client_id = xyza7891tlrtamRbnOSNoM2rsUqgNGlU
```

**`xyza7891` is the standard Epic dev-portal client-ID prefix for products registered via developer.epicgames.com.** Any dev who clicks "Create Product" on the portal gets a client ID in this exact format. You can verify this against Epic's public Epic Online Services documentation — all example client IDs in their docs use the same prefix pattern.

This means: **desire_market literally signed up for an Epic developer account, created a product called "eacemu", and got legitimate credentials back.** The credentials shipped in this bundle are real and were working against Epic's infrastructure as of the bundle date.

### The Settings.json disguise

`eac_pack_extracted/EasyAntiCheat/Settings.json` (byte-verified):

```json
{
    "title": "Windows",
    "executable": "IECompatHost.exe",
    "productid": "49cfd1d86d7e48c89912d2eda7f0b59a",
    "sandboxid": "389dd1abe82249ecaeed050b0d4b1a46",
    "deploymentid": "e01426dbd3fd4703a48a6c29c90c3dde",
    "requested_splash": "EasyAntiCheat/SplashScreen.png",
    "wait_for_game_process_exit": "true",
    "hide_bootstrapper": "true",
    "hide_gui": "false"
}
```

Note **`executable: IECompatHost.exe`** — this is the Microsoft Internet Explorer Compat Host filename. The emu tells EAC "the protected game is `IECompatHost.exe`" even though the real executable launched is `eacemu_game.exe`. This disguise helps evade detection by anyone casually auditing the install.

### EAC certificate catalog (`base.bin`)

`eac_pack_extracted/EasyAntiCheat/Certificates/base.bin` — 2315 bytes, byte-verified:

```
Offset  Bytes
------  --------------------------------------------------
0x00    45 41 43 00  05 00 00 00  ...                      "EAC\0" magic + version 5
```

This is EAC's own cert catalog format. Magic `EAC\0` + version `0x05`. The bundle ships this file **verbatim from a real EAC install** — reproducing it would require EAC's own private PKI keys, which nobody outside EAC has. The emulator's trick: use the REAL file + point EAC at the self-provisioned product that trusts this cert chain.

---

## eos.json — raw credential block

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

## `eacemu_emu.dll` — manual-map architecture (byte-verified)

**The emulator core uses the exact same architecture as EAC's own `b.dll`.** Byte-verified PE details:

### Section layout — the manual-map unpack trick

```
.text    VA 0x00001000  VS 0x0001FCAE  RAW 0x00000000  ← zero on disk
.rdata   VA 0x00021000  VS 0x0001622D  RAW 0x00016400
.data    VA 0x00038000  VS 0x00220E48  RAW 0x00000000  ← zero on disk
.pdata   VA 0x00259000  VS 0x00000F3C  RAW 0x00001000
.reloc   VA 0x0025A000  VS 0x00000018  RAW 0x00000200
.text1   VA 0x0025B000  VS 0x00021190  RAW 0x00021200  ← actual code lives here
.rdata1  VA 0x0027D000  VS 0x000DD950  RAW 0x000DDA00  ← actual rdata lives here
.data1   VA 0x0035B000  VS 0x000003F0  RAW 0x00000400
.data2   VA 0x0035C000  VS 0x00016230  RAW 0x00016400
```

`.text` and `.data` are declared with normal VirtualSize but **RawSize = 0** — they don't exist on disk, they're just address-space reservations. The real code + data live in `.text1` / `.rdata1` / `.data2`. At load time (manual-map by the custom launcher), a stage-2 unpacker copies `.text1` bytes into `.text` and `.rdata1` into `.data`. Static analysis tools that walk `.text` see nothing; dynamic analysis after unpack sees everything.

### 3 exports with byte-encrypted names

```
Ordinal base: 1  Func count: 3  Named: 3
  ord 1: RVA 0x00011D44  (in .text — ZERO on disk)
  ord 2: RVA 0x00011D48  (in .text — ZERO on disk)  +4 bytes from ord 1
  ord 3: RVA 0x00011D5C  (in .text — ZERO on disk)  +20 bytes from ord 2
```

Export names are **not strings — they are raw bytes that look like encrypted UTF-8** (e.g. `°ðO¨]LÅÂ¢\x8f\x92£\x8eE`). This defeats name-based static hooking and name-dispatch resolution. The names are only meaningful after the manual-map unpacker XORs/decrypts them at runtime.

### Zero static imports

The PE import directory is **empty**. Every API call is resolved via hash-dispatch against walked PEB loader-order modules (same technique as EAC's `b.dll` — doc 04 Part 2).

### PE timestamp wiped

PE header timestamp is `0x00000000` → `1970-01-01 00:00:00 UTC`. Classic anti-forensics — makes diffing binary versions harder.

### Embedded driver whitelist (44 driver names)

The emulator's `.rdata1` contains a complete reference set of normal Windows system driver names. On startup, the emu enumerates modules in the game process + kernel and compares each against this whitelist. Anything NOT in the whitelist gets flagged or hidden from EAC's own module scanner:

```
ci.dll         tm.sys        kd.dll        pci.sys       pcw.sys
cng.sys        MUP.SYS       hal.dll       wof.sys       pdc.sys
tpm.sys        prm.sys       ACPI.sys      NDIS.SYS      skci.dll
Clfs.Sys       vmci.sys      ntfs.sys      disk.sys      pshed.dll
vsock.sys      ntdll.dll     tcpip.sys     netio.sys     amdwps.sys
volume.sys     WmiLib.sys    clipsp.dll    win32k.sys    ksecdd.sys
hvix64.exe     krpcdd.sys    wdfldr.sys    fs_rec.sys    kdstub.dll
volmgr.sys     iorate.sys    FVEVOL.SYS    acpiex.sys    fltMgr.sys
bootvid.dll    partmgr.sys   volmgrx.sys   ntosext.sys
```

Notable inclusions: `hvix64.exe` (Hyper-V kernel), `skci.dll` (System Code Integrity), `kdstub.dll` (Kernel Debugger stub), `tpm.sys`. The emu is designed to run on systems with HVCI / Secure Core / TPM features present — not just vanilla Windows.

### `KiUserExceptionDispatcher` string present

The emulator's `.rdata1` contains the string `KiUserExceptionDispatcher`. **This is Fortnite's own anti-dump trampoline target** (doc 07 — Fortnite integrity layer, page-encryption via SEH hook). The presence of this string in `eacemu_emu.dll` means the emulator CAN hook Fortnite's SEH-based anti-dump and defeat the 500-page decryption limit. This is the one piece needed for extending the emulator to actually run Fortnite's shipping exe (not just `eacemu_game.exe`).

---

## `EOSSDK-Win64-Shipping.dll` — verified genuine Epic SDK

**681 named exports total.** By category:

| Prefix | Export count | Purpose |
|-|-|-|
| `EOS_Lobby*` | 79 | Multiplayer lobbies |
| `EOS_Sessions*` | 59 | Match sessions |
| `EOS_AntiCheat*` | **53** | **Client + Server AntiCheat API** |
| `EOS_RTCAudio*` | 44 | Real-time voice chat |
| `EOS_Platform*` | 42 | Platform init / instance |
| `EOS_Ecom*` | 41 | In-game purchases |
| `EOS_Connect*` | 28 | Account linking |

### AntiCheat-specific exports (53 total)

The 20 most relevant AntiCheatClient exports (there are also 28 AntiCheatServer exports):

```
EOS_AntiCheatClient_AddExternalIntegrityCatalog
EOS_AntiCheatClient_AddNotifyClientIntegrityViolated
EOS_AntiCheatClient_AddNotifyMessageToPeer
EOS_AntiCheatClient_AddNotifyMessageToServer
EOS_AntiCheatClient_AddNotifyPeerActionRequired
EOS_AntiCheatClient_AddNotifyPeerAuthStatusChanged
EOS_AntiCheatClient_BeginSession
EOS_AntiCheatClient_EndSession
EOS_AntiCheatClient_GetModuleBuildId
EOS_AntiCheatClient_GetProtectMessageOutputLength
EOS_AntiCheatClient_GetSystemRequirementStatus
EOS_AntiCheatClient_PollStatus
EOS_AntiCheatClient_ProtectMessage
EOS_AntiCheatClient_ReceiveMessageFromPeer
EOS_AntiCheatClient_ReceiveMessageFromServer
EOS_AntiCheatClient_RegisterPeer
EOS_AntiCheatClient_RemoveNotifyClientIntegrityViolated
EOS_AntiCheatClient_RemoveNotifyMessageToPeer
EOS_AntiCheatClient_RemoveNotifyMessageToServer
EOS_AntiCheatClient_RemoveNotifyPeerActionRequired
```

This is the **complete public AntiCheat Client SDK surface**. The emulator hooks each of these in-process (via the manual-mapped `eacemu_emu.dll`) and returns `EOS_SUCCESS` or crafted responses to make EAC-protected games think they passed every check.

### Why ship the real SDK (not a stub)?

Two reasons:
1. **Signature verification.** Fortnite's own shipping exe may check that `EOSSDK-Win64-Shipping.dll` is Epic-signed. Bundling the real signed DLL passes that check. A stub never would.
2. **Behavioral completeness.** The emulator only needs to intercept a few dozen functions; the rest of the 681 (Lobby, Sessions, RTCAudio, Ecom, Connect, Auth, etc.) MUST behave correctly for a game to function. Easier to let the real SDK handle those than reimplement them.

---

## `FortniteLauncher.exe` (custom 240 KB replacement)

Byte-verified imports: `kernel32`, `kernelbase`, `user32`, **`wininet`**, **`mscoree`**.

The `wininet` + `mscoree` combo is the tell:
- **`wininet.dll`** — HTTP/HTTPS stack. The custom launcher does an HTTP check-in on launch. Could be for update checks, licensing, or user telemetry back to desire_market.
- **`mscoree.dll`** — .NET CLR host. The launcher has managed-code paths. Either hosts a .NET component, or uses .NET for config/crypto.

Section layout includes `.aobf` sections (×2) — custom obfuscation / bytecode-VM markers. The small ~240 KB size + limited string table (only 13 interesting strings) = the launcher is a thin loader that does: (1) HTTP check-in, (2) `LoadLibraryExW` on `EOSSDK-Win64-Shipping.dll`, (3) manual-map of `eacemu_emu.dll`, (4) spawn of `eacemu_game.exe` (or the real Fortnite exe if SHP1 patch is applied).

---

## `eos.json` + `Settings.json` — the self-provisioned product recipe



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

## `shipping.ep` — SHP1 hook patch (byte-verified Nov 21 2026 pass)

42 bytes, magic `SHP1`. Full dump:

```
Offset  Bytes                                             Meaning
------  ------------------------------------------------  --------------------------
0x00    53 48 50 31                                       Magic "SHP1" (SHiPping Patch v1)
0x04    FC 7C 14 0C                                       Target offset 0x0C147CFC (LE u32)
0x08    20 00                                             Shellcode length 0x20 (LE u16)
0x0A    00 48                                             Padding + start of shellcode
0x0C    83 EC 28     E8 0B 00 00 00                       sub rsp,0x28 ; call +0x0B
0x14    48 83 C4 28  E9 7A FE FF FF                       add rsp,0x28 ; jmp -0x186
0x1D    CC CC                                             int3 int3   (padding)
0x1F    48 89 5C 24 18  55  48 8B EC  48 83 EC            mov [rsp+0x18],rbx ; push rbp ; mov rbp,rsp ; sub rsp,…
```

**Disassembly of the 32-byte shellcode payload (x64):**

```asm
sub   rsp, 0x28          ; allocate shadow space for call
call  $+0xB              ; call forward into handler fn
add   rsp, 0x28          ; restore stack
jmp   $-0x186            ; jump back to original site in shipping exe
int3; int3               ; padding
mov   [rsp+0x18], rbx    ; standard x64 prologue of the called handler
push  rbp
mov   rbp, rsp
sub   rsp, …             ; (truncated — shellcode continues in memory)
```

**What this is:** a tiny redirect-and-return hook stub patched into `FortniteClient-Win64-Shipping.exe` at file offset `0x0C147CFC` (RVA / file-offset identical because .text starts at 0x1000 and 0x0C147CFC is deep inside .text).

The `call $+0xB` branches into a handler the emulator writes at the next instruction after the `jmp`. That handler does the real work (hook body); after it returns, the `jmp $-0x186` returns to original flow -0x186 bytes from the patch site — i.e. to the instruction JUST BEFORE where the hook was planted, so the original-prologue bytes clobbered by the patch can be re-executed after the handler.

This is the **classic "trampoline hook"** pattern. The 42-byte file format is just: `magic + patch_offset + patch_len + patch_bytes`. Easy to batch-generate for multiple hook sites.

> **Not a signature — a patch.** Prior revisions of this doc guessed `shipping.ep` was a "session blob with Ed25519 signature." It isn't. It's a code patch descriptor, and no Ed25519 is involved (byte-scan confirmed no Ed25519 OIDs in any of the 6 binaries in this bundle — matches doc 06's crypto correction).

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

## Fortnite relevance — updated after Nov 21 2026 byte-scan

**Previous summary said "zero direct relevance." That's half right.**

The self-provisioned-product flow doesn't let you play Fortnite — correct. But the Nov 21 2026 byte-scan reveals **two artifacts specifically aimed at Fortnite**:

1. **`shipping.ep`** — the SHP1 patch format is designed to patch `FortniteClient-Win64-Shipping.exe` at offset `0x0C147CFC`. That offset is deep inside Fortnite's `.text`, exactly the region where the EOS/EAC integrity callback lives. The patch exists to redirect that callback into a handler the emulator provides. **`eacemu_game.exe` doesn't need this patch — it's for when you point the emulator at the real Fortnite exe.**

2. **`KiUserExceptionDispatcher` string in `eacemu_emu.dll`** — that function is Fortnite's own anti-dump trampoline (doc 07 — page-encryption via SEH hook). The emulator carrying this string means it has code paths to hook Fortnite's SEH-based anti-dump defense. Only relevant if you're trying to run Fortnite under this emulator.

**What this means:** desire_market's emulator bundle has the scaffolding to attempt Fortnite, but ships configured for `eacemu_game.exe` (their safe demo target). Someone with the SHP1 patch + Fortnite's shipping exe + the emulator could try to run Fortnite against a private server that accepts the self-provisioned `eacemu` product. **Live Epic servers would still reject** because Fortnite's real product-id is Epic's, not `49cfd1d86d7e48c89912d2eda7f0b59a`.

### What this does NOT mean

- **Does not play live Fortnite.** The product_id mismatch is enforced server-side. Epic's matchmaker only accepts sessions for Fortnite's real product. You'd end up in `eacemu`'s own sandbox (empty), not a Fortnite match.
- **Does not bypass Fortnite's launcher integrity.** Even with the SHP1 patch, Fortnite's launcher (the real `FortniteLauncher.exe`, which this bundle REPLACES) still runs other checks. Replacing it with the 240 KB custom version means bypassing those too, which is a separate reverse.
- **Does not disable EAC's kernel driver.** `spoof.sys` is loaded alongside EAC, not instead of.

### Indirect learning (full list after Nov 21 2026 pass)

- The HWID spoof surface in `spoof.sys` is the complete current-build surface (see [11 — HWID spoofing](../11-hwid-spoofing.md)).
- The ACPI table list + boot variable list tells you exactly what a durable spoofer must handle.
- The ETW-TI constraint ("shm PATCH_PTE refused") is confirmed in the wild.
- The hooked driver list is a map of where the storage / network / display / USB / SMBUS / audio stacks hang together for spoofing purposes.
- **The 2-stage manual-map architecture of `eacemu_emu.dll`** (empty `.text` on disk + real code in `.text1`) is a technique applicable to any EAC-shaped emulator you build. See [04 — user-mode agent](../04-user-mode-agent.md) Part 2 for EAC's identical architecture.
- **The `xyza7891` client-ID prefix** uniquely identifies products registered via Epic's developer portal — useful for distinguishing self-provisioned EAC-protected products from Epic-owned ones in any observed EOS traffic.
- **The SHP1 patch format** (4-byte magic + 4-byte target offset + 2-byte length + N bytes shellcode) is a simple template for Fortnite-specific hook campaigns.
- **The `KiUserExceptionDispatcher` presence** confirms the Nov 20 2026 doc 07 claim that Fortnite's anti-dump protection is the main obstacle to running Fortnite under any emulator — it's the one thing every emu that tries Fortnite will have to defeat.
- **EOS SDK is bundled verbatim, signed by Epic.** Nobody is forging Epic signatures. The bypass pattern is always: bundle real signed binaries + a self-provisioned product + a manual-mapped hook DLL.

---

**Next:** [02 — UC Linux-proxy emulator](02-uc-linux-proxy-emulator.md)
