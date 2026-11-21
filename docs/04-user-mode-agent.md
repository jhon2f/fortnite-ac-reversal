# 04 — User-mode agent (`EasyAntiCheat_x64.dll` / `EasyAntiCheat_EOS_x64.dll`)

Where most of EAC's intelligence lives. If your reversing time budget isn't weighted ≥70% here, you're budgeting wrong.

- The driver is maybe 8-10 KLOC of kernel C.
- The agent, unpacked, is probably 60-90 KLOC of user-mode C++, 30-40% of it inside VMProtect handlers you have to devirtualize before any of it reads meaningfully.

This doc covers: getting the agent readable, the **export-driven init model** (not a classic DllMain chain — that's a corrected misconception, see Part 2), every worker thread, every scanner, telemetry endpoints with exact URLs + event catalog, the trust-score model + per-handler feature flags, pin check mechanics, severity + flag-ID taxonomy. **Everything the agent does from load to unload.**

---

## Part 1 — Getting the agent into a readable state

### Where the agent actually lives

**Important:** On current-build EAC-EOS, the on-disk `EasyAntiCheat_EOS_x64.dll` is **not the true user-mode agent**. Per MichButChina and yardiuu (UC thread 772331):

- EAC drops its real user-mode module as a randomly-named DLL into `system32`.
- Name pattern: `eac_usermode_<Random>.dll`.
- This dropped DLL **is manual-mapped** by the EAC service, not loaded via `LoadLibrary`.
- No LDR entry in the game process for the real agent.
- The on-disk `EasyAntiCheat_EOS_x64.dll` is a thin forwarder / loader that bootstraps the real module.

**Implication for reversing:** dumping the real agent requires either:
- Dumping the manual-mapped memory region from the game process after EAC init.
- Capturing the `system32`-dropped random-name DLL before it gets wiped.
- Snooping on EAC's service as it manual-maps into the game.

The traditional "grab `EasyAntiCheat_EOS_x64.dll` off disk" workflow gives you the loader stub, not the full scanner implementation.

### Workflow (updated for manual-mapped layout)

The on-disk DLL is VMProtect-packed with import protection. The in-memory manual-mapped module is also VMProtect-packed but has its IAT resolved. Workflow:

1. **Dump from memory** after full init inside the game. Target the manual-mapped region, not the LDR-loaded forwarder.
2. **Scylla** the dump to rebuild the IAT from resolved pointers.
3. **NoVmp** the VMP regions.
4. **Hand-lift residual handlers** with unicorn-engine + VTIL.
5. **Label subsystems.**

Plan on a week minimum if you haven't done VMProtect devirt before. NoVmp covers 70-85% of handlers across most EAC builds; the rest you fingerprint one at a time.

Full protection-stack details in [08 — protection stack](08-protection-stack.md).

---

## Part 2 — The REAL entry model (not a classic DllMain chain)

### CORRECTION (Nov 2026)

Earlier revisions of this doc showed a classic `DllMain → init chain → spawn workers` pattern. **That's wrong architecturally.** EAC's user-mode agent does NOT initialize from `DllMain`. Verified via UC thread 772331 (MichButChina, yardiuu — manual-map disclosure) + thread 781379 (Hec4te, Reubinator13 — EAC's specific detection of classic DllMain-triggered injection) + the UC emulator source code (uc_emulator analysis in [analysis/02](analysis/02-uc-linux-proxy-emulator.md), which deliberately mimics EAC's real export-driven pattern).

### The actual layered structure

Two distinct user-mode components:

```
C:\Program Files\Epic Games\Fortnite\...\EasyAntiCheat\
    EasyAntiCheat_EOS_x64.dll         <- bundled on disk
                                         Thin FORWARDER STUB
                                         DllMain is minimal
                                         Does NOT contain the scanner logic
                                         Called by EOS SDK / game IAT

C:\Windows\System32\
    eac_usermode_<Random>.dll         <- dropped at runtime by EAC service
                                         Random name per install / session
                                         MANUAL-MAPPED into the game process
                                         No LDR entry
                                         DllMain is NOT auto-invoked by Windows
                                         This is the real scanner
```

### Why there's no classic DllMain-based init chain

**Windows does not automatically call `DllMain` on manual-mapped modules.** `LoadLibrary` calls `DllMain`. Manual mapping (`VirtualAllocEx` + `WriteProcessMemory` + relocate + fix IAT) skips it unless the mapper explicitly jumps to it.

And EAC specifically avoids having the mapper jump to `DllMain` of the scanner, because:

1. **A new thread calling DllMain is visible.** EAC's own `PsSetCreateThreadNotifyRoutine` catches thread creation into a protected process — if EAC used `CreateRemoteThread` to call its own scanner's DllMain, it would flag against its own rules.
2. **EAC specifically detects classic DllMain-triggered injection patterns in CHEAT loaders** (see "Cheat-side mirror" below). Using the same pattern for its own agent would be inconsistent.
3. **Export-driven initialization is cleaner** — the EOS SDK calls specific EAC exports at known lifecycle points (session begin, poll status, end session). Init tied to those lifecycle calls matches what the game actually needs.

### Where initialization actually happens

Init is **deferred and export-driven**. The EOS SDK (`EOSSDK-Win64-Shipping.dll`) calls into EAC's exports on lifecycle events:

| EOS SDK call | What EAC does |
|-|-|
| `EOS_Initialize` | Pre-session: no pipe, no driver call. Just set up internal state tables inside the agent. |
| `EOS_Platform_Create` | Still pre-session. Reserve platform handle. |
| `EOS_Platform_GetAntiCheatClientInterface` | Returns the AntiCheat client handle. Still pre-session. |
| **`EOS_AntiCheatClient_BeginSession`** | **This is where real work happens**: parse session token, connect pipe to launcher, driver session auth via IOCTL, spawn worker threads, environment sweep, install game hooks. |
| `EOS_AntiCheatClient_PollStatus` | Periodic game-driven poll — reports pending state transitions. |
| `EOS_AntiCheatClient_ReceiveMessageFromServer` | Server → client AC packet; agent dispatches to scanner logic. |
| `EOS_AntiCheatClient_AddNotifyMessageToServer` | Game registers a callback for outbound AC messages. |
| `EOS_AntiCheatClient_AddNotifyClientIntegrityViolated` | Game registers a callback for integrity-violation notifications. |
| `EOS_AntiCheatClient_EndSession` | Tears down pipe, stops workers, drops driver auth. |

**Pseudocode of the actual `BeginSession` handler** (what the earlier incorrect DllMain section was trying to describe):

```c
EOS_EResult
EAC_AntiCheatClient_BeginSession(EOS_HAntiCheatClient h,
                                 const EOS_AntiCheatClient_BeginSessionOptions* opts)
{
    if (!parse_session_token_from_opts(opts))
        return EOS_InvalidParameters;

    verify_own_integrity_first_tick();        // self-check
    pipe_connect();                            // to EasyAntiCheat_EOS.exe
    pipe_hello();
    driver_session_auth();                     // IOCTL_EAC_SESSION_AUTH
    // Note: rules.bin is typically loaded/decrypted by the SERVICE, not here.
    //       The service pushes parsed rules to the scanner via the pipe.
    environment_sweep_once();                  // anti-vm, anti-debug,
                                               // initial module probe,
                                               // SMBIOS fingerprint cache
    spawn_worker_threads();                    // scan/pipe/telemetry/integrity/input/capture/env
    install_game_hooks();                      // EOS SDK ordinal-call integration

    return EOS_Success;
}
```

### What the bundled on-disk DLL's DllMain actually does

Minimal. Typical pattern for an EOS-API-compatible stub:

```c
BOOL WINAPI DllMain(HINSTANCE h, DWORD why, LPVOID rsv)
{
    if (why == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);          // reduce DLL_THREAD_* noise
        // That's essentially it. Maybe some TLS slot init.
        // No pipe, no driver auth, no workers.
    }
    return TRUE;
}
```

This matches the pattern observed in the publicly-analyzed UC emulator source ([analysis/02](analysis/02-uc-linux-proxy-emulator.md)) which is explicitly designed as a drop-in replacement for the bundled `EasyAntiCheat_EOS_x64.dll` — its own `DllMain` is minimal, and it implements the EOS exports that do the real work.

### Cheat-side mirror — why classic DllMain-based injection fails on current EAC

This is directly confirmed as a current-build detection. Per multiple UC legends:

**Hec4te** (legend, trust 87 — thread 781379):
> You need to find unusual structures to replace and execute with, all the methods that are known publicly EAC has a way to counter them or flag them, this includes some methods from mitre.org too.

**Reubinator13** (legend — thread 781379):
> pointer swap some function to call ur entrypoint, or ideally, dont even have an entrypoint, just pointerswap to your main thread and run from a hook. btw everything you doing is detected.

**InsideExploit** (legend, trust 84 — thread 736216):
> face injector 1:1 rewritten but with data ptr swap to call dllmain lmao
> someone could take face injector and it would work on eac. all you gotta change is the way you call DllMain, nothing else.

**bigslim04** (legend — thread 781379):
> Thread hijacking, dont module stomp they can easily check.

### The specific detection path for classic DllMain injection

1. Classic injector: `CreateRemoteThread(LoadLibraryA, path)` or `QueueUserAPC(LoadLibraryA, thread, path)`.
2. `LoadLibraryA` eventually calls `DllMain(DLL_PROCESS_ATTACH)` from a new / hijacked thread.
3. EAC observes the new thread via `PsSetCreateThreadNotifyRoutine` → thread start address is outside any whitelisted module → **flag hard** (per [02 kernel driver](02-kernel-driver.md)).
4. EAC's `ETW-TI` subscription also fires on the APC injection event if APC-based.
5. Game process gets closed by EAC's response (not a kernel kill; EAC's agent initiates graceful termination via the pipe → launcher kills).

### What works instead (current-build)

Per the legends in thread 781379:
- **Pointer-swap a legitimate function pointer** (vtable entry, callback pointer, virtual function dispatch) to redirect to your code.
- **Hook into an existing legit thread** via pointer swap — avoid creating any new thread.
- **No DllMain-style entrypoint** — your cheat runs from inside the hooked function's natural execution path.

### The specific current-public injection pattern (per stld, thread 736216)

Full technical breakdown of a working current-build injector:

| Component | Detail |
|-|-|
| BYOVD base | `inpoutx64.sys` hash `f8965fdce668692c3785afa3559159f9a18287bc0d53abb21902895a8ecf221b` — straight-up `memmove` user-input IOCTL |
| Mapper | Custom reflective loader shellcode |
| Comms channel | `KeQueryAuxiliaryCounterFrequency` abused as pointer-swap comm |
| Process open | `ZwOpenProcess` without `OBJ_KERNEL_HANDLE` flag |
| Memory alloc | `ZwAllocateVirtualMemory(MEM_COMMIT \| MEM_RESERVE, PAGE_EXECUTE_READWRITE)` |
| Staging trampoline | **`graphics-hook64.dll + 0x42DC8`** (OBS's graphics hook module — used as a legit-signed landing pad) |
| DllMain invocation | Data-pointer swap to redirect a legit function pointer to call DllMain (not the Windows automatic call) |

**OBS staging note:** `graphics-hook64.dll` is OBS Studio's graphics capture module, legitimately loaded into any process OBS is capturing. Current-public injectors require the user to have OBS running with capture active, then use a known offset inside the OBS hook DLL as their trampoline landing. stld (thread 736216) flags this as "over-engineered yet primitive" — it works but EAC's blacklist updates catch it fast.

### Implication for reversers

If you're trying to reverse the real EAC scanner:
1. **Don't look at `EasyAntiCheat_EOS_x64.dll`'s DllMain** for the scanner logic — it's not there.
2. **Dump the manual-mapped region** inside a live Fortnite game process.
3. **Trace the EOS exports** the game calls — that's where the real init happens.
4. **`EOS_AntiCheatClient_BeginSession`** is the critical function to analyze — it's the gateway to the scanner's real work.

---

## Part 3 — Worker threads (spawned at BeginSession, NOT at DllMain)

Workers spawn inside `EOS_AntiCheatClient_BeginSession` (see Part 2). They are not present before the game explicitly asks for an AC session.

| Thread | Cadence | Job |
|-|-|-|
| `scan_worker` | ~2s | Rotates module / window / thread / hook scans. |
| `pipe_worker` | blocking | Read incoming launcher messages, dispatch. |
| `telemetry_worker` | batched | Compress + encrypt + TLS to backend. |
| `integrity_worker` | ~2s (jittered) | Self + game module + system-DLL hashes. |
| `input_worker` | continuous | Mouse/keyboard hooks, distributional stats. |
| `capture_worker` | server-gated | DXGI OutputDuplication + Win32 `Graphics.Capture`. |
| `env_worker` | ~30s | Environmental drift check (SMBIOS, MAC, disk serial, machine GUID). |

**Workers are torn down on `EOS_AntiCheatClient_EndSession`** — not left running across session boundaries. Each new session gets a fresh worker set.

---

## Part 4 — Pipe client

Wraps named-pipe I/O. After `HELLO` the payloads are **AES-GCM** under a session ephemeral key the launcher sends in `WELCOME`.

**CORRECTION (Nov 20 2026 build analysis)**: earlier revisions of this doc claimed the pipe used ChaCha20-Poly1305. Byte-scan of all 4 current binaries found **zero** occurrences of "ChaCha", "Poly1305", "XChaCha", or any related string. The agent DLL contains AES mode strings: `AES-128-CBC` (6), `AES-128-GCM` (3), `AES-256-CBC` (6), `AES-256-GCM` (3). Pipe AEAD is almost certainly AES-GCM (128 or 256 bit), not ChaCha20-Poly1305.

See [05 pipe protocol](05-pipe-protocol.md) for frame format and opcode list.

---

## Part 5 — Driver client

Thin wrapper over `DeviceIoControl` with the XOR quirk from the kernel side:

```c
NTSTATUS drv_call(ULONG code, void* in, ULONG inl, void* out, ULONG outl)
{
    ULONG real = code ^ g_sessionCookie;
    DWORD got = 0;
    if (!DeviceIoControl(g_drv, real, in, inl, out, outl, &got, NULL))
        return GetLastError() | 0xC0000000;
    return 0;
}
```

Per-IOCTL wrappers sit above this. The `g_sessionCookie` XOR is the user-mode side of the kernel's `ioctlXorKey`; they're derived from the same session negotiation at auth time.

---

## Part 6 — Rules engine

Loads `pbrules.bin` at init, decrypts, parses sections. See [06 rules.bin](06-rules-bin.md) for the file format.

Runtime matching lives behind functions roughly shaped like:

```c
BOOL eac_rules_match_module(const wchar_t* path, const uchar hash[32]);
BOOL eac_rules_match_process(const wchar_t* exe);
BOOL eac_rules_match_window(const wchar_t* className);
BOOL eac_rules_match_driver(const UCHAR hash[32]);
BOOL eac_rules_match_signer(const UCHAR certThumb[32]);  // current
BOOL eac_rules_match_smbios(int kind, const char* value); // current
```

Each dispatches into the appropriate rule section, iterates entries, checks match-mode (hash / path-suffix / pattern / signer / SMBIOS-field), returns the severity tag.

---

## Part 7 — Scanners

The part most writeups are hazy on because there are a lot of them.

### 7.1 — Module scanner

Runs on timer, also fires on every image-load notification piped from the driver.

- Calls `GET_MODULES` for the game process. Walks LDR. Matches each entry against rules.bin module sections. Hash match → high severity. Path-suffix or pattern → medium.
- Calls `GET_VAD`. Builds a set of every executable VAD region. For each, checks whether an LDR entry covers that range. If not and the region is executable, flag.
  - `VadImageMap` without LDR → "unlinked image."
  - `VadPrivate` with executable protection → "shellcode region."
- **Transient-executable detector (current-build):** two VAD snapshots two seconds apart. Any region that was R/W in the first and R/X in the second (flipped while we weren't looking) is flagged.
- **Entropy check:** walk executable VADs, compute Shannon entropy on a 64KB sample. Real x86 code sits around 6.0-6.5 bits/byte. Packed or encrypted code runs 7.5+. Over threshold → flag.

### 7.2 — Window scanner

The overlay / ESP detector.

- `EnumWindows` callback grabs classname and title for every top-level window.
- Matches against rules.bin window sections. Known cheat UI classes flagged on sight.
- **Transparent-topmost windows over the game's client rect get flagged** even if the class isn't known — the pattern itself is suspicious.
- Legit overlays (Discord, NVIDIA, Steam) have their properties on an internal baked-in whitelist.
- **Current-build addition:** windows with no owner but rendering via d3d11/d3d12 directly get flagged.

### 7.3 — Thread scanner

- `NtQuerySystemInformation(SystemProcessInformation)`, filter to own pid, iterate threads.
- Classify start addresses the same way the driver's thread callback does.
- User-mode cross-check in case the driver's callback path got subverted.

### 7.4 — Hook detector

Periodically loads a clean copy of important system DLLs and diffs `.text` pages against in-memory.

Modules checked (current build):

```
ntdll.dll, kernel32.dll, kernelbase.dll, user32.dll, win32u.dll,
d3d11.dll, d3d12.dll, dxgi.dll, gdi32.dll, gdi32full.dll
```

Historical approach was to load the "clean copy" from `\KnownDlls`. Current builds bundle their own known-good baselines (section hashes + raw bytes for the first ~16 KB of `.text` of each module). The change is in response to cheats modifying the `\KnownDlls` section objects before the agent could consult them.

**Export-pointer check (current).** Several key exports (`NtOpenProcess`, `NtReadVirtualMemory`, `LdrLoadDll`, `NtCreateFile`, …) are resolved at agent init and cached. Periodically re-resolved; mismatch flags "export rebound."

### 7.5 — DXGI frame capture

Gated by server-side config.

- Reference `d3d11` device, `OutputDuplication` object on monitor 0.
- Every N seconds, composited frame captured.
- **Current-build also uses `Graphics.Capture` API on win11** — desktop duplication misses some overlay compositions.
- Frames are JPEG-compressed (or AVIF on current, smaller payload). Shipped via telemetry.
- Backend runs vision models looking for aim circles, bounding boxes, crosshair overlays that the window scanner would never see.

### 7.6 — Input anomaly detector

- Hooks `WH_MOUSE_LL` + RawInput.
- Tracks dX/dY per tick, sub-pixel step distributions, device ID consistency, time-to-shot latencies after a snap.
- Agent doesn't make ban decisions — bins data, ships summaries. Backend ML models score the distributions.
- **Current-build addition:** tracks the kernel-level mouse driver chain. Walks `\Driver\MouseClass`'s device stack. Cheats using kmbox-like hardware or custom mouse drivers show an unusual driver chain. Rolls up into the "mouse-driver block list" section of rules.bin.

### 7.7 — Integrity timer

- Self `.text` + each game module's `.text` + **current-build expansion to system DLLs** (`ntdll`, `kernelbase`, `win32u`).
- Expected hashes baked into rules.bin or delivered in session init.
- Mismatch → max severity.
- Interval is short (every 2s) and **jittered** within a window to defeat scheduling by cheats that hook briefly between ticks.

### 7.8 — Environmental drift worker (`env_worker`)

Current-build addition. Runs on ~30s cadence doing SMBIOS + MAC + disk serial + machine GUID re-reads. Compares against session-init cached values. Any drift flags.

This is the spoof-detector hedge — a spoofer that only patches reads at init time but later system calls read the real values gets caught.

---

## Part 7.5 — Three-component user-mode layout (Nov 20 2026 build confirmed)

Byte-level analysis of the Nov 20 2026 Fortnite EAC update confirmed the user-mode is **three distinct components**, not two as earlier revisions suggested:

| Component | File | Role | Signed? | Imports |
|-|-|-|-|-|
| Launcher wrapper (`a.dll`) | `EasyAntiCheat.packed (1).dll` (36 MB) | Pre-flight checks + service control + game spawn + agent injection. Contains all user-facing error strings + tool blacklist. | YES (Epic) | KERNEL32 (24) + ADVAPI32 (7, SCM only) |
| Scanner agent (`b.dll`) | `EasyAntiCheat_EOS.dll` (24 MB) | The real manual-mapped scanner. Dropped to `C:\Windows\System32\eac_usermode_<Random>.dll`, mapped into game process. Contains CA chain refs + game.bin catalog logic. | **NO** | **ZERO imports** |
| Service / setup | `EasyAntiCheat_EOS.exe` (1 MB, 32-bit) | Installs service, performs TPM attestation (tbs.dll), telemetry to Epic via libcurl. PDB `EasyAntiCheat_EOS_Setup.pdb`. Service display name `EasyAntiCheat_EOSSys`. | YES (Epic) | 9 DLLs incl `tbs.dll` (TPM) |

The agent DLL (`b.dll`) having **zero static imports** is conclusive evidence of the manual-map architecture — Windows loader can't satisfy a DLL with no IAT entries via `LoadLibrary`. The exports are 5 ordinal-only entries (no names).

The launcher wrapper exports 5 named single-letter functions: `a, b, c, d, e`.

## Part 7.6 — TLS is TLS 1.2 ONLY (Nov 20 2026 build)

Byte-scan of agent DLL confirms:

TLS 1.2 labels present:
- `master secret`
- `key expansion`
- `client finished`
- `server finished`
- `extended master secret` (RFC 7627)

TLS 1.3 labels ABSENT:
- `tls13`, `derived`, `exporter`, `traffic` — all 0 occurrences

Conclusion: EAC agent speaks **TLS 1.2 only**. No TLS 1.3 support.

### TLS curves supported (per mbedTLS name list in agent DLL)

```
secp256r1, secp384r1, secp521r1, secp256k1, secp224r1, secp192r1,
brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
```

### Cipher suites supported (mbedTLS-naming convention)

```
TLS-RSA-WITH-AES-128-CBC-SHA / SHA256 / GCM-SHA256
TLS-RSA-WITH-AES-256-CBC-SHA / SHA256 / GCM-SHA384
TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA / SHA256 / GCM-SHA256
TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384 / GCM-SHA384
TLS-DHE-RSA-WITH-AES-128-CBC-SHA / SHA256 / GCM-SHA256
TLS-DHE-RSA-WITH-AES-256-CBC-SHA / SHA256 / GCM-SHA384
```

NO ChaCha20-Poly1305 suite in agent. TLS implementation is **mbedTLS** (based on the `TLS-RSA-WITH-…` naming convention which is distinct from BoringSSL/OpenSSL `TLS_RSA_WITH_…` format). Prior repo revisions claimed BoringSSL — correction.

### Compression

zstd confirmed in agent DLL — 2 occurrences of zstd magic `0x28B52FFD` at offset `0x233B87`. Used for telemetry body compression (with the shared ~8KB baked dictionary).

## Part 8 — TLS transport + pin check

Statically-linked TLS stack. Current builds use a BoringSSL fork. Trusts a small set of certificate SPKI hashes hardcoded in the DLL.

```c
int eac_tls_verify_cert(cert_chain)
{
    compute SPKI SHA256 of leaf → spkiHash;
    for (int i = 0; i < EAC_PIN_COUNT; i++)
        if (!memcmp(spkiHash, g_pinHashes[i], 32)) return 1;
    return 0;
}
```

**To mitm for research:** find the pin function (string xref "pin" or by cross-ref from TLS handshake code), patch `memcmp` → `mov al, 1; ret`. Install your CA, mitmproxy sees cleartext.

### Alternative — the Kaspersky SSL MITM trick

The service does cert pinning so a normal mitmproxy gets ignored. But: Kaspersky's "SSL protection" package installs its own CA as trusted on the machine. Use it:

1. Install Kaspersky with SSL protection enabled (or extract the CA from an existing install).
2. Export Kaspersky's CA cert + private key.
3. Use that CA as the signing CA for mitmproxy.
4. The service accepts certs signed by that CA (because it's in the trust store Kaspersky put it in).
5. mitmproxy sees cleartext.

---

## Part 9 — Backend endpoints (exact URLs)

### Primary

```
POST https://api.epicgames.dev/telemetry/data/datarouter/api/v1/public/data
  ?AppVersion=1.0.0
  &AppEnvironment=Production
  &UploadType=sdkevents
  &AppID=EOSSDK.AntiCheatExt.Service
  &SessionId=<...>
```

### Secondary / legacy

```
POST https://datarouter.ol.epicgames.com/datarouter/api/v1/public/data
  ?AppVersion=1.0.0
  &AppEnvironment=Production
  &UploadType=eteventstream
  &AppID=easyanticheat
  &SessionId=<...>
```

### Module CDN

```
GET https://modules-cdn.eac-prod.on.epicgames.com/<module>
```

Dynamic auxiliary scanner modules fetched at runtime. See [05 pipe protocol REMOTE_MODULE_LOAD](05-pipe-protocol.md).

### Headers

| Header | Value |
|-|-|
| `Content-Type` | `application/json` |
| `User-Agent` | `Easy Anti-Cheat EOS/1.0.0` |
| `Service` | `1.5.9` |

### Transport

HTTPS. libcurl + schannel + Negotiate strings. Proxy resolution via `WinHttpOpen` / `WinHttpGetIEProxyConfigForCurrentUser` / `WinHttpGetProxyForUrl`.

---

## Part 10 — Telemetry body format

Not a generic JSON serializer. Built by concatenating fixed string fragments in a specific order:

```
{"Events":[
{"EventName":"<...>","Source":"<...>","BuildTime":"<...>",
 "ProductId":"<fortnite product_id>","SandboxId":"<...>",
 "DeploymentId":"<...>","OSName":"<...>","OSVer":"<...>",
 "BuildId":<numeric>}
```

### Field sources

- `ProductId` = the EOS `ProductId` of the game (Fortnite's product ID is Epic-internal; `client_secret` is what matters).
- `OSName` / `OSVer` / `BuildId` = Windows `CurrentVersion` registry keys.
- `SandboxId` / `DeploymentId` = per-title EOS identifiers.

### Compression (current)

Current builds use zstd compression with a shared dictionary baked into the agent DLL (~8 KB blob referenced near telemetry init).

```
header:
  u16 version
  u16 flags
  u32 bodyLen
  u8  msgType
  u8  severity
  u16 reserved

body: zstd-dict(Fields)
  u16 tag
  u16 len
  u8  value[len]
```

---

## Part 11 — Event catalog

Every event name the service may emit. **Reading this catalog is the fastest way to understand what EAC actually flags.**

```
AntiCheat.Generic.TestValue

AntiCheat.Error.Bugcheck
AntiCheat.Error.BugcheckDetailed
AntiCheat.Error.GameTrust                    <- correlates to bans
AntiCheat.Error.GameApplicationError
AntiCheat.Error.IntegrityViolation           <- correlates to bans
AntiCheat.Error.GameHardError
AntiCheat.Error.Launch
AntiCheat.Error.ValidateError                <- correlates to bans
AntiCheat.Error.ServiceUpdateFailed
AntiCheat.Error.GameException
AntiCheat.Error.NetworkProtocol
AntiCheat.Error.Theia                        <- internal state inconsistency
AntiCheat.Error.Undefined

AntiCheat.Warning.ChunkFailure
AntiCheat.Warning.GameTerminationAbnormal
AntiCheat.Warning.AbnormalShutdown
AntiCheat.Warning.BadOSVersion

AntiCheat.Info.DriverInitResult
AntiCheat.Info.DriverInitTime
AntiCheat.Info.DriverUnloadDuration
AntiCheat.Info.SandboxInfo
AntiCheat.Info.SandboxEventInfoFile
AntiCheat.Info.SandboxProcess
```

### Field groupings

- **`GameTrust` / `IntegrityViolation` / `ValidateError`** → enforcement-correlated events. These are the ones you want to see *absent* from your traffic.
- **`Theia`** → internal state inconsistency (driver ↔ agent disagreement). Not a cheat-detection event directly; a self-health event. Correlated with other error-family events it drives correlation.
- **`DriverInitResult` / `DriverInitTime` / `DriverUnloadDuration`** → routine telemetry, baseline-expected.
- **`BadOSVersion` / `ChunkFailure`** → environment anomalies.
- **`SandboxInfo` / `SandboxProcess`** → per-session environment facts.

---

## Part 12 — Current-build telemetry tag list

| Tag | Content |
|-|-|
| `0x0001` | Session id (16 byte GUID) |
| `0x0002` | Timestamp u64 ms since epoch |
| `0x0010` | Flag id u32 |
| `0x0011` | Severity u8 |
| `0x0012` | Flag-specific data |
| `0x0020` | Module info (path + hash + base + size + authenticode signer thumbprint) |
| `0x0021` | VAD info (base + size + protection + type + backing file path) |
| `0x0022` | Thread info (tid + start_addr + state) |
| `0x0030` | CPUID dump (leaves 1, 7, `0x8000000{1,2,3,4}`, `0x40000000`) |
| `0x0040` | Window info (hwnd + class + title + rect + style flags + `has_d3d_swapchain`) |
| `0x0050` | Driver info (name + hash + size + signer + WDAC blocklist state) |
| `0x0060` | Screenshot bytes (image format tag + compressed payload) |
| `0x0070` | Input stats block |
| `0x0080` | Environmental fingerprint (SMBIOS + disk hash + MAC hashes + GPU LUID + machine GUID + TPM EK hash + Windows product id) |
| `0x0090` | Driver chain for mouse/keyboard (ordered names + hashes) |
| `0x00A0` | Kernel callback dump (addr + owning driver hash) |

---

## Part 13 — Severity

| Level | Meaning |
|-|-|
| 0 | Info |
| 1 | Warning |
| 2 | Suspicious |
| 3 | Fatal (flagged for ban) |

### Ban timing reality

Getting a fatal flag does not mean instant ban. Flag gets logged server-side, correlated across sessions. Current-build correlation cadence is daily (used to be weekly), with hard-correlated flag chains triggering near-realtime bans within hours.

Still: "my cheat worked for a week before I got banned" is a normal story.

---

## Part 14 — Flag-ID groupings

| Prefix | Family |
|-|-|
| `0x10xx` | Module / VAD / shellcode / injection |
| `0x11xx` | Thread family |
| `0x12xx` | Handle / API access |
| `0x13xx` | Window / overlay |
| `0x14xx` | Hook / integrity |
| `0x15xx` | Driver / signing |
| `0x16xx` | Process / parent |
| `0x17xx` | Debugger |
| `0x18xx` | VM / hypervisor |
| `0x19xx` | Registry / BCD |
| `0x1Axx` | Input anomaly |
| `0x1Bxx` | Frame-capture overlay |
| `0x1Cxx` | Environmental fingerprint (current-build addition) |
| `0x1Dxx` | Server-pushed auxiliary scanner findings |

---

## Part 15 — Named kernel objects + service-registry state

For observability without touching the kernel, EAC leaves behind:

### Named events

```
Global\EasyAntiCheat_EOSEventDriver
Global\EasyAntiCheat_EOSEventGame
Global\EasyAntiCheat_EOSEventModule
```

Standard Windows named events (`CreateEventW` / `OpenEventW`). Subscribing reveals the driver / game / module heartbeat without any hooking.

### Registry state keys

Under `SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\`:

```
Attestation
ProductsInstalled
ErrRpt_GameCrashExitStatus
ErrRpt_LastUnloadDuration
ErrRpt_GameState
ErrRpt_ServiceState
ErrRpt_GameCrashExitTime
ErrRpt_LastInitTime
ErrRpt_GameCrashCreateTime
ErrRpt_LastInitSandboxId
ErrRpt_LastInitDeploymentId
```

Accessible with any registry viewer. They reflect the service's last session state and error flags. **Useful for ban-trace cleanup (`ErrRpt_*` values survive game-level uninstall).**

---

## Part 16 — Trust-score model (how EAC decides what runs on YOUR machine)

The score itself is server-side. The driver and service **feed** it. The feedback loop is which handlers fire on your next session.

### Three inputs

**1. Certificate trust state of the machine**

Driver walks Windows trust stores + Wintrust policy plumbing. See [02 kernel driver Part 10](02-kernel-driver.md#part-10--the-46-module-manifest-plaintext-tags) for the module manifest.

Operationally:
- Every signed driver on your machine is a data point.
- Signed cheat drivers from 2016 with leaked/revoked certs show up as trust-positive but fingerprint-negative.
- A fresh clean Windows install with only Microsoft + major vendor signers has the highest baseline trust.
- A machine with many third-party / unknown signers has lower baseline trust.

**2. TPM attestation**

EAC captures the TPM endorsement key, requests PCR quotes signed by the AIK (Attestation Identity Key), binds the attestation to the EAC session id. Controlled by registry keys:

```
SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys
EacQuoteKey
AttestationKey
SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation
```

Operationally:
- Quotes are **cryptographically bound to physical TPM state.** A running hypervisor / tampered boot changes the PCR values → different quote → anomaly.
- The HWID isn't "just a text string" anymore when TPM attestation is in play. It's a cryptographic proof of boot state.

**3. Per-handler feature flags (the live-rotation dial)**

The flattened command dispatcher at `0x18C0E6 – 0x18FE5D` ([02 kernel driver Part 2.e](02-kernel-driver.md#2e--flattening--selector--kill-switches-feature-flags)) implements a per-handler feature-flag bit. **The feature-flag byte comes from the request record.** The request record is pushed from server-side to the driver per session. **The backend decides per-session which handlers fire.**

### What this means for "bypassing" EAC

If you bypass one check, you haven't bypassed the system. **The backend just rotates a flag.**

Consider: you build a spoofer that defeats `NtfL` (load-image notify). First session, `NtfL` fires, finds nothing suspicious. The backend's correlation model notices "this machine had many driver loads in previous sessions, but none now — anomaly." Next session, the backend sets a flag turning on `SmBf` (SMBIOS fingerprint) with more granular checks + `WfpC` (WFP callouts) for network-level correlation. You might not even notice because you successfully defeated `NtfL`.

This is why "my cheat works, I tested it" doesn't mean "I'm safe." **What ran on your test session is not what will run on your next session.**

---

## Part 17 — Operational signals

### Normal session baseline

- Low event volume (maybe 5-20 events over a match).
- Mostly `DriverInitResult`, `DriverInitTime`, `SandboxInfo`, `DriverUnloadDuration`.
- No `IntegrityViolation` / `GameTrust` / `ValidateError`.

### Elevated-scan session (you're being correlation-mapped)

- Higher event volume (50-200+ per match).
- Multiple `IntegrityViolation` or `GameTrust` events.
- More granular `SandboxInfo` / `SandboxProcess` events (per-process reporting rather than per-session summaries).
- Higher-detail HWID collection.
- Possibly: domain / IP rotation observed in your outbound DNS logs.

### Pre-ban-wave session

- `IntegrityViolation` or `GameTrust` becomes near-constant.
- Session cuts short or gets disconnected with a soft error.
- Game crashes under what-looks-like-innocent conditions.
- Matchmaking into shadow-ban queue.

### Signal priority

Direct observation from EAC-driver reversal:

> If you see high scan activity plus more / fuller HWID collection, your software might be flagged and they're just mapping out the userbase for a ban wave.

### Timeline

| Phase | Duration | Observable |
|-|-|-|
| Clean baseline | Normal | Few events, no error-family |
| Suspicion phase | Days | `IntegrityViolation` starts appearing |
| Collection phase | Weeks–months (never under 1 week for new drivers) | Scan activity rises, HWID collection broadens |
| Correlation complete | — | Backend has enough data |
| Ban wave | Instant once triggered | Hard ban or HWID ban |

---

## Part 18 — Driver ↔ service frame protocol

Lives at the very beginning of the driver's `.text` (`0x1000 – 0x1200`) and in a couple of RAW gap functions.

### Byte-order split

Envelopes are **little-endian dwords**. Payload values inside are **big-endian**. Watch this — the split cost the original researcher an evening.

### Container init (`0x1020 – 0x1099`)

- Magic dwords: `{1, 2, 1, 0x6C}` — built on the stack at runtime; **you won't find it raw in the file**.
- Min size: `0x50`.
- Data starts at `ctx+0x50`.
- Cap = `size - 0x50`.
- State byte at `+0x40`.
- Flags at `+0x44` (low nibble = op class).
- List head at `+0x48`.

### Push wrapper: `0x1150 – 0x11FA`

### Big-endian value accessors

```
0x53A0  read u8
0x53F0  read u16 BE (rol ax, 8)
0x54A0  write u32 BE (bswap)
0x54F0  read u32 BE (bswap)
```

### Envelope writer (RAW gap, no unwind): `0x24F360 – 0x24F3AF`

```
writes:  [dst+0x00] = type       (1..5, or 0)
         [dst+0x04] = class      (>= 2, or == 2 when type == 0)
         [dst+0x08] = 0x378      (fixed marker, 888)
error:   0x80100004 on invalid args
success: returns 0x100000
```

### Error space

```
Container:    0x80004, 0x80005, 0x80007, 0x80012, 0x80016
Marshalling:  0x90005 (null), 0x90006 (truncation)
```

### Observed pushed message size

`0x17A` bytes.

---

## Part 19 — Anti-debug checks (continuous, not just init)

EAC runs all of these continuously throughout the agent's lifetime.

| Check | Mechanism |
|-|-|
| `PEB.BeingDebugged` | Classic. Still checked. |
| `NtGlobalFlag` | Heap debug flags set → debugger |
| Heap flags | Same idea, different place |
| `ProcessDebugPort` | `NtQueryInformationProcess`; nonzero port → debug |
| `ProcessDebugFlags` | Same; zero → debug |
| `ProcessDebugObjectHandle` | Same; nonzero → debug |
| HWBP | `GetThreadContext` → `Dr0..Dr3` nonzero |
| rdtsc timing | Delta between two nop sequences; too large = being single-stepped |
| Kernel debugger | `NtQuerySystemInformation(SystemKernelDebuggerInformation)` |
| `ThreadHideFromDebugger` consistency | Hidden flag set but debug port still showing → inconsistent debug state |
| `ProcessInstrumentationCallback` | New in current — zero means nobody has the kernel-callback instrumentation hook |

Each check nudges a cumulative suspicion score. No single check is a ban on its own.

---

## Part 20 — Anti-VM checks

| Check | Mechanism |
|-|-|
| CPUID 0x1 ECX bit 31 | Hypervisor-present bit |
| CPUID 0x40000000 brand | `VMwareVMware`, `KVMKVMKVM\0\0\0`, `Microsoft Hv`, `XenVMMXenVMM`, `VBoxVBoxVBox`, `QEMU\0\0\0\0\0\0\0\0`, `TCGTCGTCGTCG`, `bhyve bhyve ` |
| Registry probes | VMware Tools, VBox Guest Additions, Hyper-V Integration Services, Parallels Tools |
| Device probes | `\\.\VBoxMiniRdrDN`, `\\.\pipe\VBoxTrayIPC`, `\\.\vmci`, `\\.\prl_pci` |
| MAC prefix | `00:05:69`, `00:0C:29`, `00:50:56` (VMware); `08:00:27` (VBox); `00:03:FF` (Hyper-V); `00:1C:42` (Parallels) |
| Timing | CPUID cost under virtualization vs native. rdtsc delta across a cpuid, compared against cached native baseline. |
| **APIC ID topology** | Current — real hardware APIC IDs have expected topology; many hypervisors return 0 or linear sequences. Anomalous topology flags. |
| **CPUID leaf 0x16 frequency** | Current — must return nonzero on real modern hardware. Many hypervisors return zeros. |

None fire immediately. Score accumulates. Backend decides.

---

## Part 21 — Correctness checklist

Specific values to pull from your own binaries:

- [ ] Agent build string (`EAC_YYYY_MM_DD` in `.rdata`)
- [ ] Session cookie XOR
- [ ] Pin hash set (count + SHA256 values)
- [ ] Rules.bin root key location
- [ ] Rules.bin signing public key location
- [ ] Zstd dictionary location (~8 KB blob near telemetry init)
- [ ] Event-name catalog (should match the list above ± version-rotations)
- [ ] Flag-ID numeric values
- [ ] Telemetry endpoint hostnames
- [ ] List of modules the integrity timer hashes
- [ ] List of modules the hook detector compares against

When all filled in, this doc plus your constants is a complete agent reversal for YOUR build.

---

**Next:** [05 — Pipe protocol](05-pipe-protocol.md)
