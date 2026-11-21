# 15 — Protocol recreation dossier (deep reversal, Nov 20 2026)

**Read this if you lost every other doc.** This is the "rebuild EAC from zero on the host side" dossier — every subsystem that has to exist for the local stack to run, byte-verified against the Nov 20 2026 Fortnite EAC binaries wherever possible. Where something is reconstructed vs. byte-confirmed is called out explicitly.

What you **can** build from this alone:
- A service that passes as `EasyAntiCheat_EOSSys` locally
- A launcher wrapper replacement with all 5 named exports
- An agent DLL stub with the 5 ordinal entry points at the verified RVAs
- A pipe/mapping/event IPC surface that the real game binary accepts
- The 30 `ErrRpt_*` registry values
- All 6 `EasyAntiCheat_EOS_Setup.exe` CLI subcommands
- The complete TPM provisioning name surface

What you **cannot** build without more (and what the server-side gate catches):
- Valid signatures from EAC's private PKI (`Anti-Cheat Integrity CA11`) — their signing keys are not in the binaries
- EOS backend validation (server-side, not reversible from client binaries)
- Live `pbrules.bin` ciphertext (fetched over TLS from Epic)
- Live `game.bin` catalog signed by EAC's CA
- A valid TPM attestation chain to Microsoft's root (your TPM has its own key)

See Part 10 for the specific points where a server-side emulator is required.

---

## Part 1 — The four on-host principals (byte-verified)

| Role | On-disk name | Internal name | Exports | Loaded by |
|-|-|-|-|-|
| Kernel driver | `EasyAntiCheat_EOS.sys` | — | DriverEntry + Dispatch table | Service via SCM |
| Service (Windows service + setup) | `EasyAntiCheat_EOS.exe` | — | CLI entry (`main`) | Windows SCM / user |
| Agent (user-mode scanner) | `EasyAntiCheat_EOS.dll` (random-named post-install) | **`b.dll`** | 5 ordinals, **0 names** | Game process (manual-mapped) |
| Launcher wrapper | `EasyAntiCheat.packed (1).dll` | **`a.dll`** | 5 ordinals, **5 names: `a,b,c,d,e`** | Pre-flight launcher |

### Byte-verified export tables

**`b.dll` (the agent — real scanner):**
```
Ordinal base: 1  Func count: 5  Named: 0
  ord 1  RVA 0x4FEA3    ← suspected: init / module unpack trampoline
  ord 2  RVA 0x22DE30   ← suspected: BeginSession entry (large RVA, bulk code)
  ord 3  RVA 0x30A0E0   ← suspected: PollStatus / message pump
  ord 4  RVA 0x4FCE2    ← suspected: shutdown / EndSession
  ord 5  RVA 0x2F2760   ← suspected: callback-register path
```

Zero names on exports is the manual-map tell — loaders invoke by ordinal because there are no name hash tables to feed `GetProcAddress`. Combined with zero static imports (see doc 04), this is proof of manual-map architecture.

**`a.dll` (the launcher wrapper):**
```
Ordinal base: 1  Func count: 5  Named: 5
  ord 1 'a'  RVA 0xC7837   small — in secondary cluster
  ord 2 'b'  RVA 0xC7892   small — same cluster (+ 0x5B bytes)
  ord 3 'c'  RVA 0xC78C1   small — same cluster (+ 0x2F bytes)
  ord 4 'd'  RVA 0x2DDB2   ← HEAVY. Different section. The main pre-flight+launch.
  ord 5 'e'  RVA 0xC78F3   small — same cluster (+ 0x32 bytes)
```

The cluster `0xC78xx` suggests `a/b/c/e` are small wrappers (likely version / status / state getters called by the launcher), and `d` (far at `0x2DDB2`) is the heavy lifter — the full pre-flight check pipeline + game process launch. Jumping into `d` is where DTrace/DotLocal/UEFI/SecureCore/ARM64/Win10-22H2/kernel-mods/driver-verifier/blacklisted-driver/case-sensitive-path checks all live.

### Service EXE internals (byte-verified)

- 32-bit PE32 (not PE32+)
- Signed with same cert as sys+packed-dll (thumbprint `3CD980E3BACD8FB6FB3F532AFF62753FB7DE47A8`)
- PE timestamp: 2026-09-09 (**older than sys/dll** — service EXE was not rebuilt in this update; only driver + agent + launcher wrapper changed)
- Dual-role binary: runs as Windows service AND as `EasyAntiCheat_EOS_Setup.exe` CLI tool

---

## Part 2 — Service registry schema (full, byte-verified)

Two root keys. Both discovered as plain UTF-16LE strings in service EXE.

### 2.1 `HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\Attestation`

TPM attestation state lives here. **Note:** This key only holds provisioning state flags — the actual AIK blob lives in the Tpm\PlatformQuoteKeys path below (see doc 10 Part 1).

| Value name | Purpose | Written by |
|-|-|-|
| `QuoteKeyStatus` | Attestation key provisioning state flag (ok/pending/failed) | Service |
| `QuoteKeyStatusCode` | Last error code from TPM provisioning | Service |

The actual AIK blob (named `AttestationKey`) is stored under:
```
HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\AttestationKey
```
as a `PcpTpmPersistentKeyBlob` typed value. This is standard Microsoft Platform Crypto Provider format and is the authoritative location for the key material; the service-local key under `EasyAntiCheat_EOS\Attestation` only carries state flags, not the key itself.

### 2.2 `HKLM\Software\EasyAntiCheat_EOS` (ErrRpt_* — 30 values, full enumeration)

Session telemetry stored locally for crash reconstruction. **Full byte-verified list:**

```
ErrRpt_GameCrashCreateTime
ErrRpt_GameCrashExitStatus
ErrRpt_GameCrashExitTime
ErrRpt_GameCrashInfo01
ErrRpt_GameCrashInfo02      (inferred — gap between 01 and 07; see below)
ErrRpt_GameCrashInfo03
ErrRpt_GameCrashInfo04
ErrRpt_GameCrashInfo05
ErrRpt_GameCrashInfo06
ErrRpt_GameCrashInfo07
ErrRpt_GameCrashInfo08
ErrRpt_GameCrashInfo09
ErrRpt_GameCrashInfo10
ErrRpt_GameCrashInfo11
ErrRpt_GameCrashInfo12
ErrRpt_GameCrashInfo13
ErrRpt_GameCrashInfo14
ErrRpt_GameCrashPID
ErrRpt_GameCrashProductId
ErrRpt_GameState
ErrRpt_LastInitBuildId
ErrRpt_LastInitDeploymentId
ErrRpt_LastInitInfo1
ErrRpt_LastInitInfo2
ErrRpt_LastInitProductId
ErrRpt_LastInitSandboxId
ErrRpt_LastInitTime
ErrRpt_LastProductId
ErrRpt_LastUnloadDuration
ErrRpt_ServiceState
```

> **Byte note**: The service's string table showed values 01, 07-14 as distinct wide strings. Values 02-06 are inferred from the numbering pattern — the service likely also uses them but they didn't surface as string-table entries (either they're built via `wsprintfW("%02d", i)` at runtime, or only populated conditionally).

The `GameCrashInfoNN` slots are sequential 32-bit integers storing register / exception / module-at-fault info captured at crash time. They're the forensic surface the service EXE uploads to Epic alongside crash dumps.

**Build-your-own note:** An emulator must write at minimum `ErrRpt_ServiceState`, `ErrRpt_LastInitTime`, `ErrRpt_LastInitProductId` on each session or the cleaner heuristics in Part 5 will flag abnormality.

---

## Part 3 — IPC surface (full, byte-verified)

### 3.1 Named kernel objects (`Global\` namespace)

| Object name | Type | Signaled by | Waited on by |
|-|-|-|-|
| `Global\EasyAntiCheat_EOSBin` | File-mapping (shared memory) | Agent + Service (bidir) | Both |
| `Global\EasyAntiCheat_EOSEventDriver` | Named event | Driver → UM | Service |
| `Global\EasyAntiCheat_EOSEventGame` | Named event | Service → Game | Agent |
| `Global\EasyAntiCheat_EOSEventModule` | Named event | Agent → Service (module load notifications) | Service |

**Zero-copy architecture (inferred from naming + wait/signal patterns):**
Agent writes a message into `EasyAntiCheat_EOSBin` shared memory, then signals the appropriate named event. Service wakes up, reads from the mapping, processes, writes response back into the mapping, signals the complementary event. This avoids the latency + heap overhead of repeated `WriteFile`/`ReadFile` on the pipe.

The pipe still exists for commands that need stream ordering (session begin/end, config handshake, telemetry batch flushes) — see doc 05.

### 3.2 Pipe name

`\\.\pipe\EOS_EAC_<session>` — standard EAC EOS convention with per-session suffix (authoritative per doc 09; older doc 05 references should be reconciled to this form). Named with full ACL (`SECURITY_ATTRIBUTES` with DACL allowing `SYSTEM` + `AUTHENTICATED_USERS`).

### 3.3 Device object

`\Device\EasyAntiCheat_EOS` — driver-created, opened by service via `NtCreateFile`. Full IOCTL surface is in doc 02.

### 3.4 Shared memory layout (reconstructed — NOT byte-verified)

Reconstructed from prior public RE + the signal patterns. Not confirmed byte-exact against current build.

```c
struct eac_sm_header {
    uint32_t magic;           // probably 'EACS' or similar
    uint32_t version;
    uint32_t agent_offset;    // ring-buffer: agent writes here
    uint32_t agent_size;
    uint32_t service_offset;  // ring-buffer: service writes here
    uint32_t service_size;
    uint64_t agent_seq;       // monotonic sequence number
    uint64_t service_seq;
};
```

Followed by two ring buffers. Verifying this needs runtime analysis — these offsets aren't string-visible.

---

## Part 4 — Service EXE's `EasyAntiCheat_EOS_Setup.exe` CLI (full, byte-verified)

The service EXE is dual-role. Runs as Windows service when started by SCM; runs as installer/maintenance tool when invoked directly from command line.

### 4.1 Command table (byte-verified from help text strings)

```
EasyAntiCheat_EOS_Setup.exe install              <productId>
EasyAntiCheat_EOS_Setup.exe uninstall            <productId>
EasyAntiCheat_EOS_Setup.exe repair
EasyAntiCheat_EOS_Setup.exe verify-and-install   <productId>
EasyAntiCheat_EOS_Setup.exe verify-installation  <productId>
EasyAntiCheat_EOS_Setup.exe qa-factory-reset
```

Example productId from the help text (byte-visible): `95e760e6a6a447c28dc50db3e78d060f` — this is Fortnite's live EOS product ID (32-hex-char lowercase GUID-no-dashes).

### 4.2 Behavior per command (inferred from strings)

| Command | What it does |
|-|-|
| `install <pid>` | Create service, register driver, drop files, write registry baseline for `<pid>` |
| `uninstall <pid>` | Remove service, unregister driver, delete files for `<pid>` |
| `repair` | Re-verify + re-drop any missing/tampered files |
| `verify-and-install <pid>` | If installed+valid: no-op. Otherwise install. Return nonzero if corruption detected. |
| `verify-installation <pid>` | Pure check. Exit 0 if valid, nonzero otherwise. Game launchers check this first. |
| `qa-factory-reset` | **Dev/QA-only.** Wipes all state (registry, files, service). Not a user-facing command but present in production binaries. |

**Build-your-own note:** Any launcher wrapper replacement must at minimum answer `verify-installation <pid>` with exit code 0 — this is the pre-launch probe Fortnite's launcher runs.

### 4.3 Install file drops (inferred — reconstructed from install naming)

From the `EasyAntiCheat_Setup.exe.tmp` string + Windows installer conventions:

```
<game_dir>\EasyAntiCheat\
    EasyAntiCheat_EOS.exe                  (copy of setup)
    EasyAntiCheat_EOS.sys                  (driver, installed via SCM)
    <random_16_hex_chars>.dll              (b.dll — agent, random-named)
    SplashScreen.png                       (optional UI)
    Localization\
        en_us.cfg
        es_es.cfg
        zh_tw.cfg
        ... (additional locales)
    Certificates\
        <anti_cheat_ca_pubkey>.cer
        <intermediate_ca1_pubkey>.cer
        <intermediate_ca10_pubkey>.cer
```

The random-name DLL is dropped to `system32` on service install (confirmed in doc 03 workflow) — NOT to the game directory. The game directory only gets localization + cert store + splash. The real scanner lives in `system32` under a random name, invoked by hash-dispatch not by filename.

---

## Part 5 — EventLog subscription surface (NEW discovery — byte-verified)

Previously undocumented. The service subscribes to Windows EventLog using XPath queries. This is how it detects:
- Secure Boot state changes
- Driver loads (Kernel Event Tracing)
- Code Integrity policy changes
- TPM state transitions
- Audit events related to process creation

### 5.1 Query template (byte-verified)

```xml
<QueryList>
  <Query Path='{0}'>
    <Select>{1}</Select>
  </Query>
</QueryList>
```

Where `{0}` = log channel name, `{1}` = XPath predicate.

### 5.2 Predicate template (byte-verified string fragments)

```
Event/System/TimeCreated[timediff(@SystemTime) <= '<millis>']
  and Event/System/Provider[@Name='<provider_name>']
  and Event/System/Provider[@EventSourceName='<legacy_source>']
  and Event/System/EventID=<numeric_id>
```

### 5.3 Likely monitored channels (inferred — NOT byte-verified)

- `Security` — process creation audit (ID 4688), privileged service calls
- `Microsoft-Windows-CodeIntegrity/Operational` — unsigned driver load (3023, 3024)
- `Microsoft-Windows-TPM-WMI/Operational` — TPM state changes
- `System` — service start/stop, driver load events
- `Microsoft-Windows-WindowsUpdateClient/Operational` — HVCI feature deltas

**Build-your-own note:** An emulator doesn't need to replicate this monitoring. It only needs to appear to the game as if monitoring is present — the game reads session state via EOS SDK, not EventLog directly.

---

## Part 6 — DLL dependency graph (byte-verified)

### 6.1 Service EXE (15 dynamic DLLs, named in `.rdata`)

```
TpmCoreProvisioning.dll     — Platform Crypto Provider provisioning
Wkernel32.dll               — fault-tolerant kernel32 wrapper
Wadvapi32.dll               — fault-tolerant advapi32
Wevtapi.dll                 — fault-tolerant wevtapi (EventLog API)
crypt32.dll                 — certificate operations
dbgeng.dll                  — DebugEngine (symbol resolution for crash reports)
iphlpapi.dll                — network adapter enum (HWID collection #3)
kernel32.dll                — standard
mscoree.dll                 — .NET CLR (service may host managed code for update)
ntdll.dll                   — syscall thunks
ole32.dll                   — COM
rtbs.dll                    — TPM Base Services (TBS) complement
secur32.dll                 — SSPI (for ticket validation)
security.dll                — more SSPI
wintrust.dll                — Authenticode verification
```

**The `W` prefix** (`Wkernel32.dll`, `Wadvapi32.dll`, `Wevtapi.dll`) is the Windows `*Wrap*` fault-tolerant wrapper convention — legacy or 32-bit fallbacks that forward to the modern DLL but with `__try/__except` around every entry. They appear in service EXE because it's 32-bit and loads across multiple Windows versions.

### 6.2 Launcher wrapper (`a.dll`) — statically linked (packed)

Has VMProtect-packed .text. Imports visible after unpack:
```
kernel32.dll       — standard
user32.dll         — UI fallback / messagebox
ntdll.dll          — syscall thunks
advapi32.dll       — SCM, registry
crypt32.dll        — cert verification
wintrust.dll       — Authenticode
ws2_32.dll         — network (for EOS SDK reach)
```

### 6.3 Agent (`b.dll`) — **ZERO static imports** (byte-verified)

This is the manual-map proof. The agent DLL's PE has zero entries in its import table. Everything is resolved at runtime via hash-dispatch (MurmurHash3-style finalizer `0xFF51AFD7ED558CCD` — see doc 02).

The hash-dispatch pattern:
1. Agent is manual-mapped into game process
2. One of its 5 ordinals is invoked (likely ord 1 at RVA 0x4FEA3)
3. That function walks the PEB → loader-order list → each module
4. For each export in each module, compute MurmurHash3 finalizer against the name
5. Match against a hardcoded hash → store resolved function pointer in agent's internal table
6. All subsequent API calls go through that table

**Result:** `GetProcAddress`/`LoadLibrary` are never called. Static analysis tools that only look at import tables see nothing. Runtime hook scanners can still see the resolved function pointers but only AFTER init.

---

## Part 7 — PKI chain (byte-verified, agent + launcher)

The agent and launcher both carry references to EAC's **private** PKI, separate from the DigiCert chain that signs the binaries:

```
Root:         Anti-Cheat Integrity CA11
Intermediate: Anti-Cheat Integrity Intermediate CA1
              Anti-Cheat Integrity Intermediate CA10
Store path:   EasyAntiCheat/Certificates/   (file store, NOT Windows cert store)
```

This private PKI is used for:
- Signing `pbrules.bin` ciphertext (see doc 06)
- Signing `game.bin` per-game hash catalogs (see doc 06)
- Signing EOS SDK internal transport payloads (after TLS termination)

The CA11 designation implies they rotate the root CA periodically (10 prior versions). Each binary release embeds the pubkey trust set valid at that date range. An emulator can read the embedded pubkeys from the binary but cannot sign new content — EAC's private key is not reachable.

---

## Part 8 — Agent's `game_error.*` enum (byte-verified)

Full error code enumeration from agent DLL strings. These are the failure reasons the game surfaces to the player:

```
game_error.error_catalogue_corrupted     ← game.bin tampered / truncated
game_error.error_catalogue_not_found     ← game.bin missing from install
game_error.error_certificate_revoked     ← CA11 PKI cert on revocation list
game_error.error_corrupted_memory        ← heap / stack canary violation in game
game_error.error_corrupted_network       ← pipe/mapping tampered or reset
game_error.error_file_forbidden          ← blacklisted file loaded in process
game_error.error_file_not_found          ← required EAC-managed file missing
game_error.error_file_version            ← file present but version mismatch
game_error.error_module_forbidden        ← blacklisted module in rules.bin matched
game_error.error_service_unavailable     ← EAC service not running or unreachable
game_error.error_system_configuration    ← HVCI off / TPM absent / etc
game_error.error_system_version          ← Win10 < 22H2 or ARM64 etc
game_error.executable_not_hashed         ← game exe not in game.bin catalog
```

And the user-friendly messages (from launcher wrapper):

```
"Forbidden module"
"Forbidden system configuration"
"Forbidden tool"
"Forbidden Windows kernel modification detected"
"Easy Anti-Cheat cannot run if Driver Signature Enforcement has been disabled"
"The driver {0} is loaded without valid signature. Please reboot your system to unload the driver."
"Error validating Easy Anti-Cheat code signing certificate"
"Corrupt Easy Anti-Cheat Hash Catalogue"
"Could not locate game executable entry in the catalogue."
"Easy Anti-Cheat Hash Catalogue not found"
"EAC index certificate revoked"
```

---

## Part 9 — Telemetry/ban-report pipeline (NEW discovery — byte-verified)

The service EXE uploads detections via EOS SDK events. Two upload channels discovered:

### 9.1 SDK events channel

```
nt=Production&UploadType=sdkevents&AppID=EOSSDK.AntiCheatExt.Service&SessionId=<session>
```

### 9.2 Event stream channel

```
?nt=Production&UploadType=eteventstream&AppID=easyanticheat&SessionId=<session>
```

### 9.3 Event names uploaded (byte-verified)

```
AntiCheat.Error.IntegrityViolation       ← violation detected, upload the context
AntiCheat.Error.ServiceUpdateFailed      ← self-update failed
AntiCheat.Error.Bugcheck                 ← kernel bugcheck tied to driver
AntiCheat.Error.BugcheckDetailed         ← crash dump context
AntiCheat.Info.SandboxProcess            ← process ran in sandbox / VM
```

These correlate to the ban pipeline. An `AntiCheat.Error.IntegrityViolation` event with sufficient context causes Epic's server-side correlation to queue the account for ban review. See doc 10 for the ban-wave cadence.

---

## Part 10 — What a working emulator looks like (checklist)

### 10.1 Local stack (recreatable from this doc alone)

| Component | What it must do | Where to look |
|-|-|-|
| Service (Windows service) | Register as `EasyAntiCheat_EOSSys`, create 3 named events + 1 mapping, open pipe server, respond to `BeginSession` with success | Parts 2, 3, 6 |
| Driver stub | Create `\Device\EasyAntiCheat_EOS`, respond to IOCTL_SELF_CHECK + IOCTL_ENUM_MODULES with crafted responses | doc 02 |
| Agent DLL replacement | Match 5 ordinal entry points; return success from each; no actual scanning | Part 1, this doc + doc 04 |
| Launcher wrapper replacement | Export `a,b,c,d,e`; `d` returns success; invoke game | Part 1 |
| Registry baseline | Write all 30 `ErrRpt_*` values to make last session look clean | Part 2.2 |
| TPM provisioning stub | Fake `QuoteKeyStatus` = ok + `QuoteKeyStatusCode` = 0 in registry | Part 2.1 |
| Setup CLI | Respond to all 6 subcommands; at minimum `verify-installation` returns 0 | Part 4 |

### 10.2 What the local stack passes

- EOS SDK `EOS_AntiCheatClient_BeginSession` → returns `EOS_SUCCESS`
- Game's local `verify-installation` check → exits 0
- Game's integrity poll → `PollStatus` returns no violations
- Game's peer registration → accepted with handle

### 10.3 What the local stack **does not** pass

- Epic's server-side session gate — requires a valid signed session token from EOS backend
- EAC's server-side correlation — the backend expects `AntiCheat.Info.*` telemetry events flowing; absence or malformation triggers soft-ban review
- TPM attestation chain — if the server requests a fresh quote, the local emulator can produce one but the attestation key certificate won't chain to a Microsoft-rooted AIK
- `game.bin` signature verification — the catalog is signed by `Anti-Cheat Integrity CA11`; a stub can't resign it, but you can keep the real one and just not verify

### 10.4 Server-side options to complete the picture

- **Private server**: Run your own Fortnite backend that doesn't validate against Epic. Requires reversing Fortnite's network protocol + authentication. Does not use EOS SDK at all. This is what projects like Project Era / Reload-FN target.
- **Dummy backend**: EOS SDK supports configuring arbitrary backend URL (via platform options). Point to a local HTTP server, implement the minimum EOS SDK response set. Works for offline-focused reversing; cannot enter Fortnite matches.

---

## Part 11 — Binary offset quick reference (Nov 20 2026)

For researchers loading these binaries in a disassembler, here are the key offsets:

### Driver (`EasyAntiCheat_EOS.sys`, 46 MB)

| Offset | Content |
|-|-|
| `0x303530` | 45-tag module manifest (previously `0x2CE200`; `IZ` tag removed) |
| `0x303F8E` | secp256r1 OID (`06 08 2A 86 48 CE 3D 03 01 07`) — ECDSA support |
| `0x2C035B6` | First of 12 RSA public-key OIDs (`06 09 2A 86 48 86 F7 0D 01 01 01`) |
| `.text` | 1176 occurrences of MurmurHash3 finalizer constant `0xFF51AFD7ED558CCD` |

### Agent (`EasyAntiCheat_EOS.dll` / `b.dll`, 24 MB)

| Offset | Content |
|-|-|
| `0x4FEA3` (RVA, ord 1) | Agent init / module unpack trampoline (suspected) |
| `0x22DE30` (RVA, ord 2) | BeginSession large handler (suspected) |
| `0x30A0E0` (RVA, ord 3) | PollStatus / message pump (suspected) |
| `0x4FCE2` (RVA, ord 4) | Shutdown / EndSession (suspected) |
| `0x2F2760` (RVA, ord 5) | Callback-register path (suspected) |
| `0x233B87` | zstd magic `28 B5 2F FD` (first of 2 occurrences) |

### Launcher wrapper (`EasyAntiCheat.packed (1).dll` / `a.dll`, 36 MB)

| Offset | Content |
|-|-|
| `0xC7837` (RVA, ord 1 'a') | Small export — version/state getter (suspected) |
| `0xC7892` (RVA, ord 2 'b') | Small export — status getter (suspected) |
| `0xC78C1` (RVA, ord 3 'c') | Small export (suspected) |
| `0x2DDB2` (RVA, ord 4 'd') | **Heavy export** — pre-flight + game launch flow |
| `0xC78F3` (RVA, ord 5 'e') | Small export (suspected) |
| `0xFC000-0x101000` | Plaintext region containing tool blacklist + error codes (see doc 12) |

### Service (`EasyAntiCheat_EOS.exe`, 1 MB, 32-bit)

| Offset / Location | Content |
|-|-|
| `.rdata` | All 30 `ErrRpt_*` registry value strings |
| `.rdata` | All 6 CLI subcommand help text |
| `.rdata` | All 15 DLL names |
| `.rdata` | EventLog XPath query template |
| `.rdata` | Telemetry upload URL templates |
| `.rdata` | `AntiCheat.Error.*` / `AntiCheat.Info.*` event name strings |

---

## Part 12 — Suspected export-to-function mapping (unverified, inference-based)

**Caveat:** Ordinal → function role is inference from RVA cluster patterns and size. Not verified by disassembly. Use this as a starting point — verify by setting breakpoints at each RVA and observing what params the game passes in.

### `b.dll` (agent) ordinals

| Ord | RVA | Suspected role | Likely signature |
|-|-|-|-|
| 1 | `0x4FEA3` | `init` — manual-map entry, unpacks VMP, resolves imports, initializes state | `int __fastcall init(void* ctx, void* platform)` |
| 2 | `0x22DE30` | `begin_session` — huge RVA offset suggests this is the main scanning setup | `int __fastcall begin_session(void* ctx, uint32_t mode, void* opts)` |
| 3 | `0x30A0E0` | `poll` — called repeatedly by game loop | `int __fastcall poll(void* ctx, void* out_msg, uint32_t* out_sz)` |
| 4 | `0x4FCE2` | `end_session` — paired with ord 2 | `int __fastcall end_session(void* ctx)` |
| 5 | `0x2F2760` | `register_callback` — notification registration | `int __fastcall register_cb(void* ctx, void* cb, void* user)` |

### `a.dll` (launcher wrapper) named exports

| Ord | Name | RVA | Suspected role |
|-|-|-|-|
| 1 | `a` | `0xC7837` | Query launcher state |
| 2 | `b` | `0xC7892` | Query specific error code |
| 3 | `c` | `0xC78C1` | Query product state |
| 4 | `d` | `0x2DDB2` | **Run full pre-flight + launch game** |
| 5 | `e` | `0xC78F3` | Cleanup / shutdown |

The 5-small-exports + 1-big-export pattern is identical to what ships in BattlEye's `BEClient.dll` and InfinityWard's wrapper layer — this is just how AAA AC wrappers are shaped. Game launcher calls `d` first; if it returns success, game process is already running by the time `d` returns, and the launcher just waits for the game to exit.

---

## Part 13 — The hard limit — what can't be recreated without more

The on-host stack is fully recreatable from this dossier. The **server-side** stack is not:

1. **Epic Online Services backend** — the EOS platform is a closed service. Session tokens are signed by Epic with keys that live on their servers. No on-host component has those keys.
2. **EAC backend correlation** — the server pipeline that correlates `AntiCheat.Error.IntegrityViolation` reports into ban decisions runs at Epic. Reversing the client tells you what gets reported, not what gets banned.
3. **Live `pbrules.bin`** — updated server-side per `RULES_UPDATE` command. Any stub rules file passes local parsing but misses live blacklist data.
4. **TPM AIK chain-of-trust** — your TPM's endorsement key is certificated by your motherboard vendor, rooted in Microsoft. Emulator can fake the key handle but server-side TPM attestation will reject because the cert chain doesn't terminate at a valid Microsoft AIK root.

**Workarounds** (all require significant additional work):
- Private server — replace the Epic backend entirely with your own
- Patched client — modify Fortnite's binary to skip EOS signature verification (requires defeating Fortnite's own `KiUserExceptionDispatcher` page-encryption anti-dump — see doc 07)
- TPM fake — only works if the game accepts self-signed attestation (most do not)

---

**Next:** [16 — (open slot — future deep-reversal additions)](16-future.md) · **Previous:** [14 — Workflow + checklist](14-workflow-and-checklist.md)

## See also

- Companion PoCs updated to current-build ordinals:
  - [`poc/eac-emu-stub/`](../poc/eac-emu-stub/) — agent DLL replacement, now with the verified 5 b.dll ordinal RVAs
  - [`poc/eac-service-emu/`](../poc/eac-service-emu/) — service emulator skeleton
  - [`poc/eac-launcher-wrapper/`](../poc/eac-launcher-wrapper/) — launcher wrapper replacement
