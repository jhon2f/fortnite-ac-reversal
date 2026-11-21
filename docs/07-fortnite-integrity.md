# 07 — Fortnite integrity layer (Epic's own, independent of EAC)

**Separate from EAC.** The Fortnite shipping exe has anti-cheat logic that runs **independent** of EAC's DLL. Mostly wiring into UE5's anti-cheat module feature system, plus server-authoritative game logic, plus Fortnite-specific additions (replay, UEFN sandbox, FNCS tournament controls, cross-play trust, mobile).

Reversing this layer is worth it because:
- Many Fortnite bans are delivered via Fortnite's own server checks, not EAC's scans.
- Understanding the client-server trust boundary tells you which cheats are visible vs invisible to EAC specifically.
- The [13 EAC emulation PoC](13-eac-emulation.md) needs to interact with this layer correctly.
- Private-server implementers need to replicate this layer, not just defeat EAC.

---

## Part 1 — UE5 anti-cheat interface

Unreal has:

```cpp
class IOnlineAntiCheatCommon { ... };
class IAntiCheatModularFeature { ... };
```

Both abstract. EAC implements concretes. The integration lives in a UE module (`OnlineServicesEAC`, `OnlineAntiCheatEAC`, and friends — names vary per UE version). The game registers users (session attendees) via `RegisterUser`. All anti-cheat network traffic between client and server goes through:

```cpp
SendNetworkMessage(FUniqueNetIdRef, const uint8*, int32)
ReceiveNetworkMessage(FUniqueNetIdRef, const uint8*, int32)
```

on this interface. Which means **EAC's reports tunnel through Fortnite's own game netcode to reach Epic**. You can't block EAC telemetry at the network layer without also breaking matchmaking.

Clever design: EAC's reports reach Epic's infrastructure through a channel that already has to work for the game to function.

---

## Part 2 — Export-ordinal map (EAC_x64 ↔ Shipping)

The game calls `EasyAntiCheat_x64.dll` **by ordinal, not by name**. Ordinals rotate per EAC build.

Rough shape (names match the EOS SDK public headers; ordinals are per-build):

| Ord | Name |
|-|-|
| 1 | `Client_Init` |
| 2 | `Client_Shutdown` |
| 3 | `Client_RegisterPeer` |
| 4 | `Client_UnregisterPeer` |
| 5 | `Client_ReceiveMessage` |
| 6 | `Client_PollStatus` |
| 7 | `Client_SetCallback` |
| 8 | `Client_GetProtectedData` |
| 9 | `Client_ReportBehavior` |
| 10 | `Client_AddNetworkToken` |
| 11 | `Client_RemoveNetworkToken` |

Plus a bunch more for session events, message signing, trust-state queries.

### Recovering the map

1. Dump `EAC_x64.dll` exports in CFF Explorer. Exports are by ordinal only; you get numbers.
2. Walk the game's IAT for its `EAC_x64.dll` imports.
3. The correspondence is **positional** — the game's Nth import is EAC's Nth export.
4. Name candidates come from UE5's public anti-cheat module source (in the engine) + the EOS SDK sample for anti-cheat integration (public).

---

## Part 3 — Server-authoritative movement — specifics

The movement system is deeply authoritative. Specifics worth knowing:

### `UCharacterMovementComponent` + custom Fortnite extensions

- Base UE class handles movement replication.
- Fortnite extends with `FortCharacterMovementComponent` (exact class names rotate per build).
- Additional fields for:
  - Build mode state.
  - Edit mode state.
  - Zipline / glider state.
  - Launch pad vectors.
  - Item usage state.

### Movement validation on server

The server:
1. Receives client-reported input vector.
2. Runs authoritative physics simulation with the same input.
3. Computes expected position.
4. Compares against client-reported position.
5. If delta > tolerance → net correction (teleports client to server position).
6. If delta > severe threshold → flag.

### Specific anti-cheat checks

- **Speed hack detection**: velocity exceeds the player's current movement mode's cap for N ticks.
- **Teleport detection**: position changes more than physically possible within one tick.
- **No-clip detection**: player position inside a collision volume server-side.
- **Infinite-jump detection**: multiple jumps without touching ground.
- **Launch-pad spam**: player receives more launch-pad boosts than the server-authoritative count.
- **Zip-line abuse**: player gains velocity while not on a zip-line.

### Why this can't be client-cheated

These are server-side. The cheat client can lie to itself about position, but every network tick the server corrects. Observable "teleport cheats" visible to other players are actually desync artifacts of the server's rejection of the cheater's claimed position.

Reverse via `ACharacter` / `APlayerCharacter` replication + the net-correction logic (`ServerMove` RPCs).

---

## Part 4 — Weapon / combat system integrity

### Shot-rate validation

Each weapon has a server-defined `MinFireInterval`. Client firing faster is caught:
1. Server tracks `LastFireTime` per weapon per player.
2. New fire event rejected if `NewFireTime - LastFireTime < MinFireInterval`.
3. Rejected shots counted; sustained rejection pattern → flag.

### Spread validation

Each weapon has:
- `BaseSpread` (accuracy cone at rest).
- `SpreadModifier` based on movement / recoil / aim state.

Server computes **authoritative** spread. Client-side rendered shots may differ from where projectiles actually go. "No-spread cheats" that reduce the client's display of spread don't change the server's bullet trajectory.

### Headshot vs body hit determination

- Server determines hit location via projectile trajectory + bone hitboxes.
- Client-side hit indicators are cosmetic; damage is server-authoritative.
- **Aimbot cheats that lock to head position**: still shoot where the server thinks they should hit (based on bullet travel time + target movement prediction). Perfect-locking aimbots sometimes miss because of server-prediction mismatch.

### Fortnite-specific weapon mechanics

- **Weapon rarity caps** — damage bonuses by rarity are server-enforced.
- **Mythic weapon limits** — can't duplicate mythics via inventory manipulation.
- **Reload-timing** — server-enforced reload duration.

### Shot spoofing

Client-side cheats that "replay" perfect shot moments don't work because:
- Each shot is a UFUNCTION RPC to the server.
- Server rate-limits + sequence-numbers these.
- Replay attempts produce duplicate or out-of-order RPCs → rejected.

---

## Part 5 — Building / Edit system integrity

Fortnite's unique building mechanic is heavily server-validated:

### Build placement

- Client proposes a build at `(x, y, z, rotation)`.
- Server:
  1. Verifies player has required materials.
  2. Verifies position is not overlapping existing geometry.
  3. Verifies position is within player's reach distance + line-of-sight.
  4. Verifies player's inventory supports the build.
- If any check fails, placement rejected. Client's local build may "snap back" or disappear on reject.

### Build-cheat categories

- **Through-wall builds**: caught by overlap check.
- **Range-extended builds** (building further than normal): caught by reach distance.
- **Material-free builds**: caught by inventory check.
- **Build-anywhere** (ignore collision): caught by overlap.

### Edit-timing cheats

Fortnite's edit system has strict timing. Cheats that pre-emptively edit before the server registers the edit intent:
- Edit requests must have valid sequence numbers.
- Server rejects out-of-order edits.
- Client-side edit previews are not authoritative.

---

## Part 6 — Inventory and item-use integrity

### Item use

- Every item use is a server-authoritative action.
- Client can't manifest items that aren't in the server's inventory.
- Picking up an item that's already been picked up by another player → client sees pickup, server rejects, item disappears for the cheater.

### Dupe prevention

- Server-authoritative inventory counts.
- Drop + pick-up races checked server-side (atomic operations).

### Pet / cosmetic item integrity

- Each cosmetic in inventory must have a backing entitlement.
- Entitlement checks happen via EOS service (per [13 EAC emulation](13-eac-emulation.md)'s service catalog).
- **Entitlement-faking** on private servers is the common path for "unlock all skins" feature in Project-Reboot-style private servers.

### FOV validation

- FOV changers above the game's slider limit caught server-side.
- FOV is replicated for sanity; the server applies its own clamp.

### Resource delta validation

- Mats and ammo cross-checked.
- Impossible deltas (gaining mats without a harvest event) → flag.

None of this is EAC. This is Epic's own UE code.

---

## Part 7 — Kick / soft-ban / hard-ban / HWID-ban taxonomy

Fortnite's enforcement tiers, from lightest to heaviest:

| Tier | What happens | Trigger |
|-|-|-|
| **Kick** | Session-only. No account consequence. | Typically client-side by EAC when the detection is immediate and unambiguous (overlay opened, kernel debugger attached). |
| **Soft ban** | Cooldown after match loss (minutes to hours). | Server heuristics. |
| **Shadow ban** | Matchmaking into a queue of flagged accounts. **No notification.** | Server correlation. **Epic's cleverest mechanism** — took the cheat community a long time to figure out it existed. |
| **Hard ban (account)** | Account termination. | Server correlation across multiple sessions. |
| **Hard ban (platform)** | Login fails across ALL Epic services. | Severe or repeat offenders. |
| **HWID ban** | Hard ban plus hardware fingerprint block. | Repeat offender appears with a fresh account on same hardware. |
| **IP ban** (rare) | Specific IP range blocked. | Egregious cases. |
| **Payment ban** | Account can log in, cannot purchase/receive items. | Chargeback / fraud. |

This 8-tier taxonomy matches [doc 10 Part 7's ban-type summary table](10-cleaner-ban-traces.md). The following are non-anti-cheat sub-categories of Payment / Soft bans that Fortnite ops uses in parallel — listed here for completeness, but they are not separate enforcement tiers in the reverse-engineered backend protocol:

- **V-Bucks hold** — sub-flag under Payment ban. V-Bucks frozen pending review (anti-fraud).
- **Competitive ban** — sub-flag under Soft ban. Can play unranked, can't enter arena / FNCS. Competitive-specific violations.
- **Chat ban** — sub-flag under Soft ban. Can play, chat disabled. Behavior violations.
- **Transaction ban** — sub-flag under Payment ban. Can play, can't buy items. Fraud / chargeback.

### Shadow ban mechanics (specifically interesting)

Specifically interesting because it's invisible. A shadow-banned account:

- Can still queue for matches.
- Only matches with other shadow-banned accounts (or sometimes bots).
- Doesn't earn competitive progress.
- Doesn't realize anything's wrong unless they play with a non-banned friend.

Server-side only. Nothing on the client distinguishes a shadow-matched session from a normal one.

### Signals that correlate to shadow ban

Players often suspect shadow ban but can't confirm. Specific signals:
- **Lobby skill distribution is unusually low** (bots or similarly-flagged accounts).
- **Match search time increases by 2-5x** average.
- **Queue populates with accounts with similar "newness" patterns** (same creation window as yours).
- **Fewer human reactions** — opponents who move but don't "look like" they're reacting to your actions.
- **Reduced cosmetic diversity** — flagged-account lobbies have fewer rare items on display.

None are definitive. Combined across 10+ matches, strong correlation.

### HWID ban binding

Covered in depth in [10 cleaner & ban traces](10-cleaner-ban-traces.md), but the short version: the backend stores a hash over some combination of HWID fields (SMBIOS UUID, motherboard serial, disk serial, TPM EK hash, MAC prefix, machine GUID, …). On session start, agent collects, hashes, sends. Backend matches against ban list.

**Cleaning disk artifacts does not undo HWID bans.** HWID bans are hardware-rooted; the mitigation is spoofing (per [11 HWID spoofing](11-hwid-spoofing.md)) or new hardware.

---

## Part 8 — Fortnite modes — EAC coverage differences

Different Fortnite modes have different EAC integration depth:

| Mode | EAC coverage | Notes |
|-|-|-|
| **Battle Royale** | Full — driver + agent + Fortnite-side integrity | Primary detection mode |
| **Zero Build** | Full | Same as BR |
| **Save The World (STW, campaign)** | Partial | Lighter kernel integration historically; current builds match BR |
| **Creative / UEFN maps** | Partial | Server-side authoritative checks less stringent for private creative sessions |
| **Rocket Racing** | Full | Own EOS product_id but same base stack |
| **Fortnite Festival** | Full | Own EOS product_id |
| **LEGO Fortnite** | Full | Own EOS product_id |

Historical gap: STW's lighter integration was exploited for farming / duplication cheats pre-2021. Closed by Epic post-2022.

### Save The World (STW) specifics

STW is Fortnite's PvE mode, currently in maintenance.

Differences from Battle Royale:
- **PvE-focused** — less direct cheat impact.
- **Historical dupe exploits** — STW's inventory system has had multiple dupe exploits historically (2018-2021). Patched.
- **Trading economy** — STW has an in-game trading economy that historically was exploited. Trading restricted in current builds.
- **V-Bucks farming** — STW grants V-Bucks over time. Automated farming is detected.

Uses the same EAC stack as BR. Server-side validation on inventory + currency grants.

### Rocket Racing / Festival / LEGO inside Fortnite

Each has its own:
- EOS `product_id` + `deployment_id`.
- Same base EAC stack.
- Different server-authoritative checks.
- Different anti-cheat priorities (e.g., Festival's rhythm-game anti-cheat is very different from BR).

**Shared EAC installation**: one `EasyAntiCheat_EOS` service protects all these sub-modes.

---

## Part 9 — Replay system integrity

Fortnite has a replay system — full match recording that plays back with free camera.

### Why replay integrity matters

- Competitive tournaments use replay reviews.
- Cheater reports include replay footage.
- Clip-sharing for social features.
- Spectator mode for esports.

### How replays are protected

- Replays are signed by the server with session-attestation keys.
- Modified replays fail signature verification.
- Replay playback runs under a restricted process mode (no network, limited input).

### Replay-specific cheats

Rare because replays are server-generated, but exist:
- Modified-client replay recording (saves locally with client-side cheats visible).
- Replay-share exploits (faking the sharer's identity).

Minor concern vs match-level cheats.

---

## Part 10 — UEFN (Unreal Editor for Fortnite) integrity

Fortnite Creative 2.0 → UEFN launched 2023. Players can author their own Fortnite maps with custom code (Verse language).

### Verse sandbox

Verse is a **sandboxed** language:
- No memory access primitives.
- No file I/O.
- No network outside the game's RPC system.
- No OS integration.

### Why the sandbox matters

- UEFN maps are user-authored and shared publicly.
- Malicious UEFN maps could be vectors for cheats or attacks.
- The Verse sandbox prevents UEFN maps from compromising the game.

### Current research

- Multiple researchers have probed the Verse sandbox since launch.
- No publicly-disclosed sandbox escape as of 2026.
- Private: unclear — if a sandbox escape exists privately, it's extraordinarily valuable.

### UEFN map integrity

- UEFN maps are deployed as server-side packages.
- When played, the client downloads the map via the Fortnite CDN.
- Maps are signed by Epic (not the creator) before distribution.
- Map modifications fail signature verification.

---

## Part 11 — Account trust signals

Fortnite's matchmaking factors account trust beyond just HWID:

### Signals

- **Account age** — older accounts trusted more.
- **Email verification state** — verified emails trusted.
- **2FA enabled** — 2FA-enabled accounts trusted.
- **Payment history** — accounts with real payments trusted (fraud-resistant accounts).
- **Play history** — long play history trusted.
- **Report history** — multiple reports against an account reduce trust.
- **Connected platforms** — linked Xbox/PlayStation/Switch accounts add trust (consoles are harder to spoof).
- **Device history** — list of trusted devices (see Part 16 below).

### How trust affects matchmaking

- Low-trust accounts get matched with other low-trust accounts (soft shadow-banning effect).
- High-trust accounts get prioritized matchmaking.
- Brand-new accounts have temporary "new player protection" (easier opponents for first N matches).

### How trust affects ban correlation

- Low-trust account flagged for suspicious behavior → banned faster.
- High-trust account flagged → more correlation data gathered before ban.
- Trust doesn't absolve — bans happen regardless, just at different cadences.

---

## Part 12 — Competitive integrity — tournaments / FNCS

Fortnite Champion Series (FNCS) and other competitive events have additional anti-cheat:

### Tournament-specific additions

- **Hardware verification**: participants in top-tier events may be required to use pre-approved hardware configurations.
- **Observer mode monitoring**: tournament observers watch for behavioral anomalies in real-time.
- **Replay review**: all competitive matches reviewed after the fact for suspect play.
- **Spectator restriction**: tournaments have specific spectator modes with limited information.

### Face-cam requirements

For top-level events (FNCS Grand Finals), players may be required to:
- Stream face-cam (visible to Epic officials).
- Use webcam feed as additional attestation that a real human is at the keyboard.
- Not technical anti-cheat but social/compliance.

### Payout holds

Prize money for FNCS placements is held for weeks after the event. If subsequent investigation reveals cheating, payout is revoked. This gives Epic an additional detection window.

---

## Part 13 — Cross-play and console trust

Fortnite is cross-platform. Different platforms have different trust properties:

### Platform trust ranking (roughly)

1. **Switch / Xbox / PlayStation** — highest trust. Consoles are locked-down OSes with mandatory signing. Cheats possible but extremely rare (hardware mod required).
2. **Mobile (Android / iOS)** — moderate trust. Android has root exploits; iOS is harder.
3. **PC (Windows)** — **lowest** trust. Open OS, kernel accessible.

### Cross-play implications

- Console-only lobbies are safer from cheats.
- PC players can opt out of cross-play lobbies in some modes.
- Cross-play matches apply PC-level scrutiny to all players in the lobby.

### Platform-specific anti-cheat

| Platform | AC |
|-|-|
| Xbox | Microsoft's console security + Fortnite server-side |
| PlayStation | Sony's console security + Fortnite server-side |
| Switch | Nintendo's console security + Fortnite server-side |
| Android | Google Play Integrity API + Epic game-side |
| iOS | Apple's app signing + Epic game-side |
| PC | **Full EAC stack** + Fortnite game-side |

Consoles don't run EAC. They don't need to — their OS is the attestation.

---

## Part 14 — Mobile Fortnite status

- **Android**: available via Epic Games Store (not Google Play since 2020 lawsuit).
- **iOS**: available in the EU via the Epic Games Store on iOS (sideloading under DMA, since 2024). Regional availability elsewhere (US included) has shifted multiple times through 2024-2026 as the Apple vs Epic litigation and third-party-storefront rules evolved — treat any specific-region "available / unavailable" claim as time-boxed to its snapshot date (this doc: Nov 20 2026) and verify against the current Epic storefront before relying on it.
- Mobile Fortnite has lighter server-authoritative checks (adapted for mobile performance).

### Mobile anti-cheat specifics

Fortnite mobile uses different techniques:

**Android:**
- **Google Play Integrity API** check (if installed via Play Store, which it isn't since 2020). Uses the current classic / standard / standard-requests tiering — SafetyNet Attestation was deprecated by Google in 2024 and fully removed from Play Services in 2025, so it is **not** used in the Nov 2026 build.
- **Epic's own attestation** via Fortnite app.
- Root detection via `su` binary enumeration.
- Magisk hiding is detected via structural tests.
- Modified APK detection (signature verification).

**iOS:**
- **App signing** by Apple.
- Jailbreak detection via file system / library existence checks.
- EOS SDK's own attestation.
- iOS 17+'s runtime integrity enforcement.

### Mobile vs PC

**Fortnite mobile does not run EAC.** The anti-cheat on mobile is entirely:
- Platform-level app signing.
- Epic's game-side attestation.
- Server-side authoritative checks.

No kernel driver exists on mobile. The EAC stack is PC-specific.

Cheats on Android: root-based memory editors exist. iOS: jailbreak-dependent, rare.

---

## Part 15 — Fortnite's cosmetic verification

Specific to Fortnite: every cosmetic a player owns is server-verified.

### Cosmetic entitlements

Each cosmetic the player owns is an **entitlement** tracked server-side:
- Granted via purchase, Battle Pass, or event reward.
- Each entitlement has an ID + grant timestamp + source.
- Entitlement DB is centralized at Epic.

### Cosmetic-cheat prevention

- Clients can't locally spoof cosmetics they don't own.
- Server sends authoritative entitlement list at match start.
- Client-side modification of cosmetic display is purely cosmetic for the cheater — other players see what the server says.

### Private-server-only cosmetic unlocks

Per [13 EAC emulation](13-eac-emulation.md): private servers often implement "grant all cosmetics" as a feature. Doesn't affect Epic's servers — the private server just returns "player owns everything" from the entitlement service mock.

---

## Part 16 — Fortnite's own HWID/account binding (separate from EAC's)

- **Fortnite stores a per-account "trusted devices" list** — devices that have logged in to the account.
- **New device = email verification required** (if account has 2FA).
- **"New hardware" detection** happens at launch on the Epic launcher side, not inside Fortnite/EAC.
- **Shared with Epic Games Store** for account-protection — the same "new device" check fires for store access.

So an HWID spoofer that beats EAC's HWID fingerprint may still trigger the launcher's new-device check. For a complete setup, the spoofer needs to also keep the Epic launcher's device cache stable.

Files involved:
- `%LOCALAPPDATA%\EpicGamesLauncher\Saved\DeviceIdCache*`
- `%LOCALAPPDATA%\EpicGamesLauncher\Saved\Config\Windows\GameUserSettings.ini`

---

## Part 17 — Match-level fraud detection

Beyond cheats, Epic also detects match-level fraud.

### Win-trading detection

- Pattern: two players repeatedly match against each other, one always wins.
- Server-side detection via pairing-frequency analysis.
- Enforcement: both players banned or soft-banned.

### Account-sharing / smurfing

- Pattern: account played at different skill levels at different times.
- Detection via playstyle fingerprinting (mouse movement + reaction time signatures).
- Enforcement: soft action usually (matchmaking skill-bracket adjustment).

### Carry fraud

- Pattern: paid service where a high-skill player plays on a low-skill account.
- Detected via shared-device patterns + account access logs.
- Enforcement: paid-carry services get explicit violations under TOS.

### Boosting

- Pattern: high-skill player boosts low-skill account into higher brackets.
- Detected via skill-rating velocity.
- Enforcement: skill-rating resets.

---

## Part 18 — Fortnite endpoint URLs (authoritative list)

**This section is the single authoritative endpoint list for the repo.** Doc 04 Part 9 (EOS SDK telemetry), doc 13 Part 5 (private-server service catalog), and doc 15 (EAC CDN endpoints) should link here rather than re-enumerate — previous versions duplicated these URLs across four docs and drifted. Keep additions here; add cross-links elsewhere.

```
https://account-public-service-prod.ol.epicgames.com
https://account-public-service-prod03.ol.epicgames.com
https://fortnite-public-service-prod11.ol.epicgames.com
https://fortnitepublic-service-prod12.ol.epicgames.com
https://friends-public-service-prod.ol.epicgames.com
https://party-service-prod.ol.epicgames.com
https://presence-public-service-prod.ol.epicgames.com
https://lightswitch-public-service-prod06.ol.epicgames.com
https://catalog-public-service-prod06.ol.epicgames.com
https://matchmaking-public-service-prod.ol.epicgames.com
https://entitlement-public-service-prod08.ol.epicgames.com
https://xmpp-service-prod.ol.epicgames.com
https://datarouter.ol.epicgames.com
https://api.epicgames.dev
https://modules-cdn.eac-prod.on.epicgames.com
https://ut-public-service-prod10.ol.epicgames.com
```

For a private-server implementation (see [13 EAC emulation](13-eac-emulation.md)), each of these needs a mock implementation.

---

## Part 18.5 — Fortnite's page-encryption anti-dump mechanism

Beyond EAC's protections, **Fortnite itself implements in-process page encryption** to resist dumping of the shipping EXE. Documented by notaskid65 on UC (thread 772331).

### How it works

1. Fortnite sets protected `.text` pages to **`PAGE_NOACCESS`**.
2. Hooks `KiUserExceptionDispatcher` using a trampoline.
3. When any code tries to access a protected page → access violation → exception dispatched → EAC's trampoline runs.
4. The trampoline checks whether the exception falls within a legitimate region.
5. If legit → decrypts the page on the fly and lets execution continue.
6. If not legit → fails hard.

### The 500-page decryption limit

**There's a hard cap of 500 page decryptions per session.** Beyond this limit, further page accesses fail even from legitimate code paths. Epic's design keeps most of the exe permanently encrypted; only the actively-executing code paths get decrypted.

### Dumping strategy

Per notaskid65:

1. **Scan while playing** — trigger page decryption through normal gameplay (menus, matches, different modes).
2. **Inject a module to force access** — a well-placed read can decrypt specific pages.
3. **Find gadgets scattered through accessible pages** — look for `mov reg, [qword]` instructions pointing at protected ranges and force those to trigger access.

Playing + mode-changing through the limit gives you approximately 40k/118k pages decrypted per session, per Lauv's testing.

### Comparison

This mechanism is **architecturally similar to Byfron's usermode AC** (Roblox) per community observation (manhcot123, UC thread 772331).

Fortnite uses this on top of EAC, not instead of — layered defense.

---

## Part 18.6 — Mid-game ban behavior (observed)

Per ecco271k (UC thread 779558 — AleaClient / ReTrac observations, applicable to Fortnite stock):

**When you get banned mid-game:**
- The game **stops sending packets** from the server to the client.
- All other players appear frozen client-side.
- You can't move / interact.
- On next launch attempt → **infinite matchmaking queue**.

**Diagnostic signal** that you've been HWID-banned on a session you thought was clean: packet freeze + inf-queue pattern.

**Report-based ban enforcement is active** — per CyberTrail (same thread): "if a few people report you I think they just ban off that." The report threshold isn't published, but repeated reports in a short window will trigger review.

---

## Part 19 — Specific Fortnite subprocess architecture

When Fortnite runs, multiple processes exist:

### Main processes

- `FortniteLauncher.exe` — pre-launcher
- `FortniteClient-Win64-Shipping_EAC.exe` — EAC wrapper
- `FortniteClient-Win64-Shipping.exe` — actual game client
- `EasyAntiCheat_EOS.exe` — EAC service

### Child processes

- `CrashReportClient.exe` — crash handler (loads if game crashes)
- `EpicWebHelper.exe` — web overlay / login UI
- `EosOverlayRenderer-Win64-Shipping.exe` — EOS social overlay

### Each process has security implications

- Crash reports: contain minidumps that could include cheat DLLs in memory.
- Web helper: loads CEF (Chromium Embedded Framework); has its own attack surface.
- EOS overlay: renders UI over the game; targeted by overlay cheats.

### Inter-process communication

- Game ↔ EAC: named pipe (per [05 pipe protocol](05-pipe-protocol.md)).
- Game ↔ Launcher: command-line args + session tokens.
- Game ↔ EOS overlay: shared memory + named events.
- Game ↔ CrashReportClient: file-based (dumps written to disk, CRC reads them).

---

## Part 20 — Fortnite history vs anti-cheat

See [doc 00 Part 1](00-overview.md) for the full Fortnite anti-cheat history timeline (BattlEye → dual-stack → EAC-only → EAC-EOS). The crypto details for the current build are covered in [doc 06's Nov 20 2026 correction section](06-ipc-endpoints.md) — the current build uses **RSA signing (likely PSS with SHA384)**, not Ed25519.

**Fortnite private-server emulators specifically target the pre-2021 dual-stack configurations or earlier where defeat conditions are different.**

---

## Part 21 — Fortnite competitive eras + cheat waves

See [doc 00 Part 5 'Milestone cheat events'](00-overview.md) for the full timeline (2019 Winter Cheat Wave, 2020 World Cup qualifier scandal, 2021 RTCore64 crackdown, 2022 LAPSUS$, 2023 BlackLotus, 2024 Project Reboot DMCA wave, 2025 DMA proliferation). Doc 00 is authoritative; this file previously duplicated it and drifted out of sync.

---

## Part 22 — What Fortnite-specific additions tell us about Epic's threat model

Patterns across all the above:

1. **Server-authoritative everything** where latency allows.
2. **Trust graduation** — new players get easier ride, established players get more scrutiny of behavior.
3. **Correlation over time** — single-session catches are rare; cross-session correlation is the primary.
4. **Economic pressure on cheat market** — FNCS payouts held, so top-level cheaters get hurt financially in addition to banned.
5. **Platform differentiation** — PC is lowest trust; consoles get easier rides; mobile sits in between.

For private-server implementers: **the game-side integrity layer is often harder to replicate than EAC itself.** You can bypass EAC with patches. You can't easily replicate the entire server-authoritative game-logic framework Epic built — that's where private servers remain imperfect even when EAC is defeated.

---

**Next:** [08 — Protection stack](08-protection-stack.md)
