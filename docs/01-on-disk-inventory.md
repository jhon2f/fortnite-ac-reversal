# 01 — On-disk inventory

Everything that ships, where to find it, and how to pull it safely.

Default Fortnite install root (Epic Games Launcher default):

```
C:\Program Files\Epic Games\Fortnite\
```

Substitute your own if different. Paths below assume this root.

---

## Classic EAC bundle

Path: `FortniteGame\Binaries\Win64\EasyAntiCheat\`

| File | What it is |
|-|-|
| `EasyAntiCheat.exe` | Launcher / service-bridge. Starts the service, opens the pipe, spawns the game. |
| `EasyAntiCheat_launcher.exe` | Alternate launcher used by newer paths. |
| `EasyAntiCheat_x64.dll` | User-mode agent injected into the game. The big one — most of EAC's intelligence lives here. |
| `EasyAntiCheat.sys` | Kernel driver. Signed by Epic / Easy Anti-Cheat Oy, WHQL cross-signed. |
| `Settings.json` | Per-title config (partially base64'd in some fields). |
| `pbrules.bin` | Encrypted rules blob — current name. (Historical: `rules.bin`.) |
| `SplashScreen.png` | Version marker. Shape changes at build boundaries. |
| `Certificates\` | Pinned certs bundle + signer intermediates. |
| `easyanticheat_<locale>.txt` | Localized error strings. Great xref anchor for error-code reversing. |

---

## EAC-EOS bundle

Path: `FortniteGame\Binaries\Win64\EasyAntiCheat_EOS\`

| File | What it is |
|-|-|
| `EasyAntiCheat_EOS.exe` | EOS launcher variant. |
| `EasyAntiCheat_EOS_x64.dll` | EOS user-mode agent. |
| `EasyAntiCheat_EOS.sys` | EOS kernel driver. ~46 MB in the Nov 20 2026 build (SHA256 `3eabcfe97e8a2bde0b3db1ab1645c66c8183f053588699d3409d93d2235c5d2b`). Historically smaller than the classic driver; current build is substantially larger. |
| `Certificates\` | Pinned certs (shared with EOS SDK's set). |
| `SplashScreen.png` | Version marker. |

See [09 — EOS variant delta](09-eos-variant.md) for what's actually different.

---

## Game binaries

Path: `FortniteGame\Binaries\Win64\`

| File | What it is |
|-|-|
| `FortniteClient-Win64-Shipping.exe` | Plain UE5 client. Still exists; doesn't go through the EAC launcher. |
| `FortniteClient-Win64-Shipping_EAC.exe` | EAC-protected launcher wrapper. This is what runs by default. |
| `FortniteClient-Win64-Shipping_EAC_EOS.exe` | EOS variant launcher wrapper. |
| `FortniteLauncher.exe` | Pre-launcher. Issues session tokens, spawns the EAC wrapper. |

The shipping EXE is ~200+ MB. The RPC boundary between EAC and the game, server-authoritative check logic, UE5 anti-cheat integration — all lives here.

---

## System-wide EAC install

The EAC installer puts a shared copy outside the Fortnite tree:

```
C:\Program Files (x86)\EasyAntiCheat\
C:\Program Files (x86)\Common Files\EasyAntiCheat\
```

The shared install exists so multiple EAC-protected games can reuse one driver. Service config is in the registry:

```
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat
```

Service is `SERVICE_DEMAND_START` — nothing loads it until a protected game needs it.

---

## Runtime-dropped — the real user-mode scanner (current build)

**Not in the bundled files above.** On current-build EAC-EOS, the real user-mode scanner module is **dropped at runtime** to `system32` with a randomized name:

```
C:\Windows\System32\eac_usermode_<Random>.dll
```

Attributes:
- Dropped by the EAC service during init.
- **Manual-mapped** into the game process (not `LoadLibrary`'d).
- No LDR entry in the game process.
- Name rotates per install / per session.
- The on-disk `EasyAntiCheat_EOS_x64.dll` in the Fortnite bundle is a **forwarder/loader stub**, not the real scanner.

**Implication for research:** capturing the real agent requires either process-memory dump (per [04 user-mode agent](04-user-mode-agent.md)) or racing to copy the `system32` drop before EAC wipes it. The bundled DLL is a thin wrapper; the useful reversing target is the dropped random-name DLL. Source: UC thread 772331 (MichButChina + yardiuu, Sept 2026).

---

## Historical — BattlEye (old Fortnite builds only)

Path: `FortniteGame\Binaries\Win64\BattlEye\`

- `BEService.exe`, `BEClient_x64.dll`, `BEDaisy.sys`, `BEServer.dll`
- `Config\`, `Logs\`

Not shipping anymore. Only relevant if you're auditing a pre-2022 ban wave.

---

## Pulling files safely

Three rules.

**1. Stop the service first** so you don't race EAC's self-update:

```powershell
sc stop EasyAntiCheat
```

Then copy.

**2. Hash everything before you touch it.**

```powershell
Get-ChildItem *.dll,*.sys,*.exe,*.bin | ForEach-Object { 
    "$($_.Name)  $((Get-FileHash $_.FullName -Algorithm SHA256).Hash)"
} | Out-File hashes.txt
```

Or with `certutil`:

```powershell
for %f in (*.dll *.sys *.exe *.bin) do @(
    certutil -hashfile "%f" SHA256 | findstr /v ":" >> hashes.txt && echo %f >> hashes.txt
)
```

**3. Keep two copies.** One you reverse. One you never touch. If EAC's service wakes up (or if you forget and launch Fortnite), the service will overwrite your working copies silently. The clean copy is your safety net.

---

## Sigcheck for version metadata

For each binary, grab the full metadata trail — signer, signing date, product version, file description:

```powershell
sigcheck -a -h EasyAntiCheat_x64.dll
```

Sign dates narrow the version window. Thumbprints identify which signing cert generation produced this build (Epic rotates intermediates occasionally).

---

## What to pull from the running system

Beyond on-disk files, three sources worth capturing at session start:

1. **Full registry dump of `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat` and `…\EasyAntiCheat_EOS`.** `ImagePath`, `Start`, `Type`, `FailureActions`.

2. **Loaded driver list at a point in time:**

   ```powershell
   driverquery /v /fo csv > drivers.csv
   ```

   Useful to document the "what drivers were present during the session" baseline.

3. **Live network capture during launch → match → quit.** Wireshark + SSLKEYLOGFILE (works for your own browser; EAC pins its own cert so you need to patch the pin per [08 — protection stack](08-protection-stack.md) before mitmproxy can MITM EAC's traffic).

---

## Runtime-only fetches (module CDN)

EAC downloads auxiliary scanner modules at runtime via `REMOTE_MODULE_LOAD` pipe opcodes. These never appear in the installer. Capture them two ways:

- **Pipe tap.** Dump pipe frames from inside the game process; see [05 — pipe protocol](05-pipe-protocol.md).
- **CDN tap.** Fiddler/mitmproxy on `modules-cdn.eac-prod.on.epicgames.com` after patching EAC's pin check.

Both routes get you the signed module bytes; the pipe is lower effort if you're already inside the agent.

---

**Next:** [02 — Kernel driver](02-kernel-driver.md)
