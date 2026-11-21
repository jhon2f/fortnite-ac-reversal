# 13 — EAC emulation + live-server bypass reality

What emulating EAC means, what live-server bypass would **actually** require (cryptographic signature chain analysis), what real private-server projects do (Project Reboot catalog), the three analyzed emulator architectures, and a working PoC of a stub EAC client.

**Code lives in [`poc/eac-emu-stub/`](../poc/eac-emu-stub/).**

This doc consolidates: emulator architecture concepts, live-server bypass reality, private server implementations, and comparison across the three analyzed real-world emulators.

---

## Part 1 — What "emulating EAC" means

Two possible halves:

| Half | What it is |
|-|-|
| **(1) Client-side stub** | A replacement `EasyAntiCheat_x64.dll` (classic EAC) / `EasyAntiCheat_EOS_x64.dll` (current Nov 2026 EOS build; the launcher-wrapper `a.dll` with 5 named exports `a,b,c,d,e` at RVAs `0xC7837 / 0xC7892 / 0xC78C1 / 0x2DDB2 / 0xC78F3`) with the same export table, same ordinals, same function signatures as real EAC. All exported functions return "success" or no-op values. |
| **(2) Backend emulator** | A stand-in for Epic's EAC backend. Talks the EAC backend protocol over EOS SDK, issues valid-looking session signatures using keys the emulator controls, which the game's local EAC client accepts. |

The PoC in this repo is **(1) only**. (2) is private-server territory.

---

## Part 2 — The signature chain (why live-server bypass is hard)

Fortnite's server-side acceptance of your session depends on EAC producing signed proofs that only the real EAC can produce. Walking the chain:

### The chain of signatures

1. **Launcher → EAC** — `FortniteLauncher.exe` signs a session token with a private key baked into the launcher's signed binary + rotated per Epic build.
2. **EAC Driver → Service** — Driver SELF_CHECK IOCTL signs (hash || nonce || bootCookie) with an **RSA private key embedded in the driver** (12 RSA pubkey OIDs present in driver at offset `0x2C035B6`; a secp256r1 ECDSA-P256 alternate OID sits at `0x303F8E`).
3. **EAC Agent → Fortnite Shipping** — Agent's init callback produces an RSA signature over session state. Private key for this is session-ephemeral and derived via ECDH with Epic's backend.
4. **EAC Service → Epic Datarouter** — Service posts telemetry signed by an authenticated TLS session, cert pinned.
5. **EAC Backend → Game Server** — Epic's backend returns session-attestation tokens the game server verifies.

**Each link must be unforgeable from the client side.** Break any one and the chain's intent is compromised.

### What you'd need to forge a live Fortnite session

| Link | Required to break | Feasibility |
|-|-|-|
| 1 — Launcher session token | Steal launcher signing key OR patch Launcher to use your key | **Infeasible.** Launcher binary is signed with Epic's cert; patching it breaks its own signature check. |
| 2 — Driver SELF_CHECK RSA | Extract RSA private key from signed `.sys` (12 RSA pubkey OIDs cluster at driver offset `0x2C035B6`, secp256r1 alternate at `0x303F8E`) OR find reversal path to leak during runtime | **Infeasible.** Key is in VMProtect'd section. Even if extracted, backend verifies (hash matches public key record) so you'd need to rotate your driver's hash and get it on Epic's whitelist. |
| 3 — Agent init RSA | Compromise the ECDH key agreement OR extract ephemeral key from memory before use | **Hard.** ECDH exchange is with Epic's backend over TLS with pin. |
| 4 — Service → Datarouter TLS | MITM the pinned TLS connection | **Doable for observation** (Kaspersky SSL trick). **Not doable for forgery.** |
| 5 — Backend session attestation | Impersonate Epic's backend to your own game server | **Possible only in a private-server context.** Not possible against Epic's own game servers. |

**The practical conclusion:** live Fortnite server bypass requires either (a) compromising Epic's backend keys (nation-state-level access or insider threat), or (b) running your own full backend + your own patched client.

---

## Part 3 — Theoretical live-server attacks

Not practical. The "what would an advanced adversary need" threat model.

### Attack 3.1 — Extract driver RSA private key

The driver signs SELF_CHECK with an embedded RSA private key (byte-scan: 12 RSA pubkey OIDs at `0x2C035B6`, secp256r1 ECDSA-P256 alternate at `0x303F8E`; zero Ed25519 OIDs anywhere in the current build). If extracted:

Steps required:
1. Reverse `EasyAntiCheat_EOS.sys` past the VMProtect layer around the signing function.
2. Find the RSA private key material OR trace the derivation of a runtime-constructed key.
3. Extract.

Blockers:
- VMProtect devirt is a multi-week effort per build.
- The key may be split across memory + derived at runtime from a boot-cookie-sealed source.
- Even with the key, you need the matching **public key to be in Epic's whitelist on their backend**. Rotating your signing key means Epic doesn't recognize your driver.

**What this gives you:** ability to forge SELF_CHECK responses locally. **Not enough** — the chain still requires live ECDH with Epic's backend for the session-ephemeral key in link 3.

### Attack 3.2 — Compromise ECDH session key during negotiation

Agent and backend do ECDH during session setup. If you can observe both sides:

Steps:
1. Patch EAC's pin check to allow MITM with your CA.
2. MITM the ECDH exchange.
3. Capture shared secret.
4. Use shared secret to sign subsequent messages as the agent.

Blockers:
- ECDH is ephemeral per session — key dies at session end.
- Backend verifies signatures against the agent's ECDH public key.
- There's an implicit authentication binding — Epic's backend expects the ECDH to be signed by the driver's RSA key (link 2). Without link 2, link 3 is rejected.

**Chain-break:** need link 2 + link 3 together.

### Attack 3.3 — Compromise Epic's HSM

Blockers:
- HSMs with FIPS 140-2 Level 3+ don't export keys. Compromise requires either HSM-firmware vulnerability or physical access.
- Epic's HSMs are AWS CloudHSM / Azure Dedicated HSM / physical devices. **(Inference — Epic hasn't disclosed their key-management setup.)**
- A compromise would be headline news. Hasn't happened.

### Attack 3.4 — EAC Oy signing cert leak (historical)

Circa 2020, an alleged leak of an older EAC-signing certificate circulated. Short-term impact — allowed rolling your own "signed" EAC.sys that loaded without SmartScreen warnings, pre-WDAC-blocklist.

Caveats:
- Microsoft revoked within weeks.
- WDAC catches any revoked-cert driver load regardless.
- The leaked cert was a **signing** cert — it signed binaries. **It wasn't the session-attestation key.**

### Attack 3.5 — Insider threat

Theoretical path with highest practical likelihood. An Epic engineer with HSM access leaking keys. No public evidence this has happened.

---

## Part 4 — The "almost works but doesn't" category

### "Patch the EAC_x64 init callback to return success + spoofed signature"

What it attempts: Bypass link 3 by producing a signature with a key the attacker controls.

Why it fails: Shipping exe verifies the signature against a pubkey **pinned in the shipping exe itself**. You'd need to also patch the shipping exe to accept your pubkey. Which is doable — but now you've modified the shipping exe, which:
- Fails EAC's integrity scan if EAC's driver is live.
- Is detected by Epic's backend via hash-reporting.

Partial mitigation: operate in a session where EAC is effectively disabled. But then the backend's first "where is EAC" check fails → session rejection.

**Ends up being:** "patch shipping exe + disable EAC entirely" → the full private-server path, not a live-server bypass.

### "Dual-launch trick"

Run two Fortnite instances — one clean, one modified. Have the clean one authenticate while the modified one plays.

Why it fails: Session tied to a specific process ID + launcher-issued token. Clean instance's session doesn't transfer to modified. Attempts to share tokens trigger duplicate-session detection server-side.

### "MITM via network driver to replay session traffic"

Observe a legitimate session's traffic from a clean machine, replay from a modified machine.

Why it fails: Every message has a per-session nonce bound to the ECDH-derived session key. Replay produces invalid MACs server-side.

### "Use a BYOVD to disable EAC's kernel callbacks mid-session"

Unregister EAC's `PsSet*NotifyRoutine` entries while session is active.

Partial success: unregistering the callbacks does work. BUT:
- The driver's self-watchdog (`Wdog` module) checks callbacks still registered. Unregistering triggers `GameTrust` event.
- ETW-TI still emits events even with callbacks unregistered.
- EAC's `CALLBACK_DUMP` IOCTL detects the unregistration.

**Lives for seconds, not minutes.**

### "DMA card that spoofs its PCI config space"

External PCIe FPGA cheat that presents itself as a legitimate device, reads game memory via DMA.

Partial success, mostly for players without Kernel DMA Protection:
- EAC's PCI enum reads config space → sees the fake device's IDs.
- Device-level anomalies → soft flag.
- Behavioral correlation → ban eventually.

---

## Part 5 — Private server projects (the "(b)" path)

### Project Reboot (and derivatives)

Current state: active, OG-season focused. Main public Fortnite private server project.

Architecture:
- **Custom backend** reimplementing Epic's services: MCP (Master Control Program), Lightswitch, Matchmaking, Friends, Party, Catalog, XMPP, Game Session.
- **Patched `FortniteClient-Win64-Shipping.exe`** to point at the private backend + skip EAC integrity checks.
- **Hand-patched EAC binaries** that accept the emulator's ephemeral keys.
- **Specific chapter/season support** — most popular: Chapter 1 Season 5, Chapter 2 Season 1-2 (OG era).

What they skip:
- No live-server-equivalent anti-cheat. Integrity enforcement is client-side only.
- Behavioral correlation via ML is not implemented.
- Shadow-ban mechanics don't exist.

Why target OG seasons specifically:
- Pre-EAC-expansion Fortnite had weaker integrity.
- Nostalgia market — biggest private-server playerbase wants OG seasons.
- Epic's DMCA attention focuses on current-build piracy; OG seasons get less legal pressure.

GitHub-visible successor projects (names rotate as repos get DMCA'd):
- Reboot Launcher
- LawinServer / Project Lawin
- Momentum
- Neonite (API mock)
- Memento Mori
- Project Aurora

### What a complete Fortnite private server has to implement

The service catalog Epic ships, each needing a mock:

| Service | Purpose | Minimum viable |
|-|-|-|
| Lightswitch | Feature flags per account per app | Static JSON return "service up" |
| MCP (Master Control Program) | Save data — Battle Royale profile, STW profile, Creative profile | Per-user SQLite + MCP profile JSON schema |
| Matchmaker | Session queueing + bucket assignment | Simple queue → start session |
| Session service | Active-session registry | In-memory session list |
| Friends | Friend list CRUD | Per-user friend table |
| Party | Party formation + state sync | WebSocket + state diff protocol |
| XMPP | In-game chat | Prosody or ejabberd configured |
| Catalog | Item Shop | Static JSON of configured items per season |
| Storefront | Entitlement grants | Grant-all or configurable |
| Entitlement | Who owns what | Per-user entitlement table |
| Fortnite Content | CDN for cosmetics/sounds/maps | Pre-cached CDN mirror |
| Launcher Services | Patch/update notification | Return "no updates" |
| Account | Login + profile | Custom auth → returns valid-looking tokens |
| OAuth Token | Access/refresh tokens | Hand-mint JWTs with keys the client is patched to trust |
| EpicGamesService (profile) | Display name, avatar | Per-user profile table |

**Estimate:** 10-30 KLOC of C# or Node.js to get a minimum-viable Chapter 1 OG season working. Active maintenance per Fortnite patch.

### EAC bypass approach in a private server

Specifically what Reboot-style projects do to make EAC not block the client:

1. **Launch bypass** — patch shipping exe to skip the EAC wrapper check, OR launch via `FortniteClient-Win64-Shipping.exe` directly (works for pre-signature-check builds).
2. **Integrity callback stub** — either stub EAC_x64.dll entirely (works for old builds without signature verification) OR patch the shipping exe to not verify the signature on EAC init callback (required for current builds).
3. **Backend keys** — replace Epic's pinned pubkey in the shipping exe with the private server's pubkey. Private server's backend signs session attestations with the matching private key.
4. **EOS SDK** — replace `EOSSDK-Win64-Shipping.dll` with a redirect version or stub that routes to the private backend.

Pattern you see in reality:
- Exact binary patches at known RVAs (changes per Fortnite build — Reboot-style projects maintain a per-build patch catalog).
- Hash-check skipping.
- Session continuation tokens issued by the private backend with the private server's signing key.

### Legal status

- Fortnite EULA prohibits private servers.
- Epic has issued DMCA takedowns + lawsuits against specific projects (Project Lawin targeted repeatedly).
- Most projects operate pseudonymously and host repos in jurisdictions with weaker IP enforcement.
- Playing on a private server doesn't risk your Epic account directly (the private server doesn't touch your Epic account), but **the tools to patch client binaries violate EULA**.

---

## Part 6 — Three analyzed emulator architectures

Three different approaches to defeating EAC, each analyzed from actual binaries + source.

| | Approach | Scope | Required capability |
|-|-|-|-|
| [desire_market](analysis/01-desire-market-emulator.md) | **Full EAC-EOS launcher emulation** with bundled HWID spoof driver | Launch a game under a self-provisioned "EAC" session that reaches real Epic backend with controlled credentials | Kernel driver + real EOS product provisioning |
| [UC Linux-proxy](analysis/02-uc-linux-proxy-emulator.md) | **Windows → Linux EOS/EAC proxy** | Offload EAC/EOS session to Wine/Proton where integrity checks are weaker | Dual-side DLL hook (Windows client + Linux server over WebSocket) |
| [MCC bypass](analysis/03-mcc-in-process-bypass.md) | **In-process EOS integrity-check patch + identity spoof** for Halo MCC | NOP the specific EOS validation function + overwrite local XUID with host XUID | User-mode DLL injection, specific RVA knowledge |

### Full emulation (desire_market) summary

- Ships **its own `FortniteLauncher.exe`, its own `start_protected_game.exe`, its own `eacemu_emu.dll`.**
- Provisions **its own EOS product** (real `product_id`, real `sandbox_id`, real `client_secret`).
- Includes a **`spoof.sys` HWID spoof driver**.
- Replaces the `EasyAntiCheat` directory via a bundled `eac_pack.zip`.
- Target: run a locally-built "protected game" that the real EOS backend will acknowledge as a session.

**Not a Fortnite bypass. It's a toolkit to build your own EAC-protected game using EAC's infrastructure.**

### Linux proxy (UC) summary

- Windows side: replacement `EOSSDK-Win64-Shipping.dll` that **proxies every EOS SDK call over WebSocket / HTTP** to a Linux backend.
- Linux side: `version.dll` loaded via `WINEDLLOVERRIDES` into a Proton prefix where the real EOS SDK + EAC Linux client run.
- Real Linux EOS/EAC client talks to Epic's backend. Session legitimate from Epic's view.
- **Exploits that EAC's Linux-under-Proton integrity checks are weaker** than the full Windows kernel integration.

Works for games that can tolerate running their session under Wine/Proton on the Linux side while the user plays on Windows. **Fortnite doesn't have a Linux build, so no Linux EAC session to proxy to — doesn't work for Fortnite.**

### In-process RVA patch (MCC) summary

- Runtime user-mode DLL injected into a running game.
- NOPs a **specific EOS SDK function** at hard-coded RVA (`0x3AD910` → `ret; nop*4`) to short-circuit the EOS integrity validation.
- Spoofs **XUIDs**: reads the host's XUID from MCC's session object, writes it over the local XUID in the title DLL.

The simplest and most fragile of the three. **Doesn't apply to Fortnite** — Fortnite ships EAC's full kernel driver stack, not just the EOS SDK.

### What each tells us about EAC

- **desire_market**: EAC is provisionable. Epic sells EAC as a service through the EOS developer portal. Any dev can provision an EAC-protected product. The "emulator" doesn't bypass EAC — it uses the official SDK with its own product.
- **UC emulator**: EAC on Linux/Proton is weaker than on Windows. Not useful against Fortnite (no Linux build) but shows the architectural asymmetry.
- **MCC bypass**: EOS integrity validation is a user-mode function that can be short-circuited with a RET. Current-build Fortnite EAC specifically defends against this by cryptographic signature verification.

---

## Part 7 — Stub DLL architecture (the PoC)

The PoC in this repo is a **(1) client-side stub** approach.

### Architecture

- **Match the real `EAC_x64` / `EasyAntiCheat_EOS_x64` export table ordinal-by-ordinal.** The game imports by ordinal.
- **Each stubbed function takes the same parameters** as the real one and returns a value the game interprets as "fine, move on."
- **Callback-registering functions** store the callback pointer and periodically call it with "nothing bad detected" results.

### Ordinal recovery

1. Open the real `EasyAntiCheat_x64.dll` (classic) or `EasyAntiCheat_EOS_x64.dll` (current Nov 2026 EOS launcher wrapper, aka `a.dll`) in CFF Explorer.
2. Dump the export table. The current EOS wrapper exports 5 named functions `a,b,c,d,e` at RVAs `0xC7837`, `0xC7892`, `0xC78C1`, `0x2DDB2` (the heavy one), `0xC78F3` (see doc 15 Part 1); the classic build exports by ordinal only.
3. Open the Fortnite shipping exe's IAT for its EAC wrapper imports.
4. Positional mapping — game's Nth import is EAC's Nth export.
5. Name candidates come from UE5's public anti-cheat module source + EOS SDK public samples.

---

## Part 8 — The PoC — what's in [`poc/eac-emu-stub/`](../poc/eac-emu-stub/)

- [`eac_emu_stub.c`](../poc/eac-emu-stub/eac_emu_stub.c) — single C file implementing the stub.
- [`eac_emu_stub.def`](../poc/eac-emu-stub/eac_emu_stub.def) — module definition file assigning ordinals.
- [`build.bat`](../poc/eac-emu-stub/build.bat) — MSVC build script.
- [`README.md`](../poc/eac-emu-stub/README.md) — PoC-specific notes.

### Build

Open a Developer Command Prompt for VS, run:

```bat
cd poc\eac-emu-stub
build.bat
```

Or manually:

```bat
cl /LD /O2 eac_emu_stub.c /Fe:EasyAntiCheat_x64.dll ^
   /link /DEF:eac_emu_stub.def
```

(For a current-build Fortnite install, substitute the output name `EasyAntiCheat_EOS_x64.dll`.)

### Use

1. Rename the real EAC wrapper in your Fortnite install to `.bak` — classic builds use `EasyAntiCheat_x64.dll` → `EasyAntiCheat_x64.dll.bak`; current Nov 2026 builds use `EasyAntiCheat_EOS_x64.dll` → `EasyAntiCheat_EOS_x64.dll.bak` (and the manual-mapped scanner `EasyAntiCheat_EOS.dll` aka `b.dll` sits alongside it).
2. Drop the stub in its place.
3. Launch via `FortniteClient-Win64-Shipping.exe` directly — not the `_EAC` wrapper.

---

## Part 9 — Limits of this approach

### Server-side rejection

Epic's backend doesn't accept sessions without a valid EAC backend session signature. A stubbed client gets kicked at matchmaking time. **Only useful for:**

- Offline single-player / sandbox / creative modes.
- Private-server implementations where you control both ends.
- Research / modding where EAC integration otherwise prevents loading.

### Launcher wrapper refuses the stub

`FortniteClient-Win64-Shipping_EAC.exe` loads `EasyAntiCheat.exe` first, which verifies the on-disk hash of `EAC_x64.dll` **before** injection. Your stub has a different hash, the launcher refuses.

**Bypass:** Launch the base `FortniteClient-Win64-Shipping.exe` directly.

### Current-build signature check breaks the stub on live Fortnite

Current builds (2026) verify that EAC's init callback has returned not just success but also a matching **RSA signature over session state** (byte-scan: 12 RSA pubkey OIDs in driver, zero Ed25519) that only the real EAC can produce.

A stub's callback return won't carry that signature → current Fortnite will **exit at startup** even when launched directly.

### Workarounds for current-build shipping exe check

- **Patch the shipping exe to skip the EAC init signature check.** Find the verification function via string xrefs like `"anti-cheat init failed"` or similar, replace the compare/branch with a `jmp`.
- **Implement real backend emulation with your own signing key.** Replace the pinned Epic pubkey in the shipping exe (or in `EAC_x64`) with yours. Your emulated backend signs sessions with the matching private key.

---

## Part 10 — Full private-server stack

For running a private Fortnite server, the complete picture:

| Component | What it does |
|-|-|
| **(a) Stub `EasyAntiCheat_x64.dll` / `EasyAntiCheat_EOS_x64.dll`** (or patched shipping exe skipping EAC init signature check) | Makes the client not block on EAC |
| **(b) Private server** | Implements Fortnite's game protocol |
| **(c) Backend emulation** | Stands in for Epic's matchmaking, leaderboards, and critically the EAC backend session-signing |
| **(d) Patched shipping exe** | Accepts your emulated backend's signature (replace pinned pubkey in shipping exe or `EAC_x64` with yours) |

Community-maintained projects doing this openly (Project Reboot and similar efforts) have implemented all four.

---

## Part 11 — Why "crack Epic's keys once and we win forever" is wrong

Even if someone leaked all of Epic's current keys:

- **Session attestation keys rotate per-season** (observed over years of public RE — the RSA/ECDSA session-attestation keypair changes between Fortnite chapters).
- **Backend state has nonces + timestamps** — a stolen key lets you forge sessions for a window (hours), not forever.
- **Epic can invalidate individual session IDs** server-side — mass-invalidate forged sessions the moment they're detected.
- **The ban list is key-independent** — forged sessions still get flagged by behavioral ML, and HWID bans apply regardless of cryptographic authenticity.

A successful key-compromise attack buys **a few sessions of free play before detection** and Epic rotating keys. Not "permanent cheat capability."

---

## Part 12 — The real asymmetry

The pattern across every subsystem in this repo is the same:

- **Cryptographic signatures protect specific events** (session attestation, driver integrity).
- **Behavioral ML protects classes of anomaly** (impossibly consistent aim, impossibly fast reactions).
- **HWID binding protects accounts** across hardware.

A cheat developer can beat one layer but not all three simultaneously for long. **Each session is probabilistic protection; multi-session correlation closes the window.**

**The practical cheat developer's problem:** not "how do I bypass EAC" but "how do I bypass EAC in a way that still looks statistically normal across hundreds of sessions." The second part is where almost every cheat eventually fails.

---

## Part 12.5 — Paid Fortnite EAC emulators (do exist, with caveats)

Per plitorq and Azazelsen (UC thread 782120, Nov 2026):

**Paid EAC emulators that specifically target Fortnite are sold on private channels.** Not public. Consistent community observations:

- **VMProtect-packed** — the emulator binary itself is VMP'd to resist reversal.
- **winhttp license-check** — the emulator makes a winhttp request to a key server at launch to validate the license.
- **Recurring subscription model** — weekly/monthly keys.

### Reversing a paid emulator (per Azazelsen)

> managed to get a paid eac emulator exe tried to reverse it but that bih had vmprotect i have low knowledge abt reversing vmprotected software so im learning it still once i figure it out its just a matter of finding the imported winhttp req and hooking to ur own key sys

Pattern: find the WinHttp API call in the emulator binary, hook it to redirect to an attacker-controlled key server, serve fake "license OK" responses → run the emulator without paying.

### Community consensus on free public emulators for Fortnite

Confirmed across multiple threads (781422, 781288, 782120):
- **"It will never work with EAC on fortnite, maybe on low tier game not fortnite."** (janolaim, direct quote)
- **"only works on free-tier eac games"** (NextrixVFX)
- The DANNZ/huzun1 EAC-EOS Proxy emulator → VRChat and similar, **not Fortnite**.

**Practical takeaway:** no public free Fortnite EAC emulator exists as of Nov 2026. Paid emulators exist but are proprietary + VMP-protected + cycle-key-locked.

### The emulator-vs-reinstall economics for HWID-banned players

Common thread in current discussions: HWID-banned players debating emulator vs full-reinstall.

Averser (UC thread 781505): *"Cleanall diskpart. Reinstall win. Reinstalling Windows is enough to clean everything. because each update leaves a lot of new traces. cleaning software can barely keep up."*

Reinstall-Windows is the **cheapest reliable path** out of HWID-lite bans (24h-365day duration) — not a full hardware-level HWID ban.

**Lesson**: software-only cleaners struggle against EAC's trace surface because Windows auto-regenerates traces across updates. Nuking the OS is operationally simpler than tracking every artifact.

---

## Part 13 — Historical analogies

Nothing novel in the architecture. The specific implementation against current Fortnite is just more work than against older games because current-build EAC verifies signatures the stub can't produce.

- **EmuWarface** — Warface private servers.
- **H1Z1 private servers** (2017-2020) — multiple operated publicly before DMCA.
- **UDK-era Unreal games with EAC stubs** for modding.

Each follows the same pattern: stub client + emulated backend + patched game binary where needed.

---

## Part 14 — What this PoC does NOT do

Being explicit about scope:

- **Does not bypass live-server session signing.** Can't be used to play on Epic's servers.
- **Does not disable EAC's driver.** The kernel driver still loads if the service is running. The stub operates at the DLL layer.
- **Does not provide any cheat capability.** Just makes the game not depend on EAC's integration contract.
- **Does not include the private-server backend.** Just the client-side half.

Purely research / modding / private-server scaffolding.

---

**Next:** [14 — Workflow & verification checklist](14-workflow-and-checklist.md)
