# 10 — Cleaner & ban traces (all on-disk + registry artifacts)

The surface involved in **"this machine was flagged / banned"** and **"this machine ran Fortnite / EAC N times."** Two overlapping concerns:

| | Concern | Lives in |
|-|-|-|
| **(a)** | On-DISK traces correlating "your machine" to "this account's ban" via log files, caches, registry, event logs. | Filesystem + registry + system event logs |
| **(b)** | Live-queried machine identifiers correlating "your hardware" to "banned hardware" via hardware fingerprinting. | See [11 HWID spoofing](11-hwid-spoofing.md) |

**Both matter.** Cleaning only (a) when (b) is the real binding gets you nowhere. Cleaning only (b) when (a) still shows "this machine has run and been reported by EAC N times" also gets you nowhere.

This doc is **the exhaustive on-disk and registry trace catalog.**

---

## Part 1 — EAC-specific trace locations

### Main installation directories

```
C:\ProgramData\EasyAntiCheat\                     — persistent config, boot
                                                     cookies, cached session
                                                     metadata
C:\ProgramData\EasyAntiCheat_EOS\                 — same for EOS variant
C:\ProgramData\Epic\EasyAntiCheat\Logs\           — run logs with session IDs
%LOCALAPPDATA%\EasyAntiCheat\                     — per-user caches
%LOCALAPPDATA%\EasyAntiCheat_EOS\
C:\ProgramData\Epic\EpicGamesLauncher\Data\Logs\  — launcher logs, which include
                                                     EAC service start/stop +
                                                     process spawn records
C:\Program Files (x86)\EasyAntiCheat\             — system install dir; shared
                                                     driver copy + setup log
C:\Windows\System32\LogFiles\EasyAntiCheat\       — on some builds: driver-side
                                                     crash dumps + status
```

### Fortnite-specific

```
%LOCALAPPDATA%\FortniteGame\Saved\Logs\           — client-side game logs with
                                                     session IDs Epic can
                                                     correlate
%LOCALAPPDATA%\FortniteGame\Saved\Config\         — user-ID artifacts + session
                                                     continuation data
%LOCALAPPDATA%\FortniteGame\Saved\Crashes\        — crash reports (include
                                                     hardware fingerprints)
%LOCALAPPDATA%\FortniteGame\Saved\WebCache*\      — web cache
%LOCALAPPDATA%\EpicGamesLauncher\Saved\
  DeviceIdCache*                                   — Epic device fingerprint
                                                     cache
```

### Registry locations EAC writes or reads through

```
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS
HKLM\SOFTWARE\EasyAntiCheat
HKLM\SOFTWARE\WOW6432Node\EasyAntiCheat
HKCU\Software\EasyAntiCheat                        — per-user cache
HKLM\SYSTEM\CurrentControlSet\Services\EasyAntiCheat\Enum
                                                    — PnP enum entry for the
                                                      loaded driver
HKLM\SYSTEM\Setup\LastUserShellFolders              — occasionally touched
                                                      during install/update
```

### EAC service-specific state keys

Under `SYSTEM\CurrentControlSet\Services\EasyAntiCheat_EOS\`:

```
Attestation                 — TPM attestation state
ProductsInstalled           — list of EAC-protected products on this system
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

Accessible with any registry viewer. **Useful for ban-trace cleanup — `ErrRpt_*` values survive game-level uninstall.**

### EacQuoteKey (TPM attestation binding)

```
HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\EacQuoteKey
HKLM\SYSTEM\CurrentControlSet\Services\Tpm\PlatformQuoteKeys\AttestationKey
```

These are Windows per-service platform quote key storage. **If present, your TPM has been bound to an EAC session.** Clearing requires TPM clear (destroys BitLocker keys).

> **Caveat (Nov 2026):** presence of `EacQuoteKey` proves TPM was *collected*, not that it is weighted into the current HWID hash. Per [11 HWID spoofing §2.7](11-hwid-spoofing.md#27-tpm) (alexanderyy): *"TPM is collected but I don't think it is used"* — i.e. collected ≠ used in the current ban-hash. Clear it if you're being thorough, but don't expect a TPM clear alone to resolve a ban.

---

## Part 2 — Windows forensic artifacts that outlive EAC's cleanup

### Prefetch

```
C:\Windows\Prefetch\
  EASYANTICHEAT.EXE-*.pf
  EASYANTICHEAT_LAUNCHER.EXE-*.pf
  FORTNITECLIENT-WIN64-SHIPPING_EAC.EXE-*.pf
  FORTNITECLIENT-WIN64-SHIPPING_EAC_EOS.EXE-*.pf
  FORTNITELAUNCHER.EXE-*.pf
  EPICGAMESLAUNCHER.EXE-*.pf
```

Records volume paths, DLLs loaded, run count, first/last run time. **Forensic timeline gold.** Survives uninstall.

### Event Logs (`.evtx`)

```
C:\Windows\System32\winevt\Logs\System.evtx
  — service start/stop events for EasyAntiCheat
  — driver load events (Microsoft-Windows-Services)
  — Code Integrity events if the driver had any load drama

C:\Windows\System32\winevt\Logs\Application.evtx
  — any crashes from the game or EAC

C:\Windows\System32\winevt\Logs\
  Microsoft-Windows-Kernel-PnP%4Device*.evtx
  — device enum events for the EAC driver device

C:\Windows\System32\winevt\Logs\
  Microsoft-Windows-TaskScheduler%4Operational.evtx
  — if EAC used a scheduled task

C:\Windows\System32\winevt\Logs\
  Microsoft-Windows-CodeIntegrity%4Operational.evtx
  — driver load CI events
```

### SRUM database

```
C:\Windows\System32\sru\SRUDB.dat
```

Per-executable network bytes transferred and runtime stats. Shows "this machine ran `EasyAntiCheat.exe` and `FortniteClient-*` and transferred N bytes to Epic endpoints." **Aggregated hourly, kept for ~60 days.**

### BAM (Background Activity Moderator)

```
HKLM\SYSTEM\CurrentControlSet\Services\bam\UserSettings\<SID>
```

Per-SID list of executables run and their last run time. Includes EAC and Fortnite binaries.

### MUICache

```
HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\
  Shell\MuiCache
```

Binary full paths and `FriendlyAppName` values for executables that ran under this user.

### Shimcache (AppCompat)

```
HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

List of executable paths + last-modified times observed. Kept across reboots, flushed to registry only at reboot.

### Amcache.hve

```
C:\Windows\appcompat\Programs\Amcache.hve
```

**The heaviest forensic witness.** Detailed record of every executable run, with SHA1 hashes of the binaries themselves. Amcache shows not just that a binary ran but the specific version.

### Jump Lists

```
%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\
```

Per-application recent-files lists.

### NTFS USN Journal

```
$Extend\$UsnJrnl:$J
```

Filesystem change journal. Records creation/modification of EAC files, log files, etc. Huge, but chunks can survive long enough to matter.

### Paging / hibernation

```
C:\pagefile.sys
C:\hiberfil.sys
C:\swapfile.sys
```

Paged-out memory from any process. Can contain literal cleartext of pipe frames, session IDs, HWID tokens that EAC computed.

### Volume Shadow Copies

```
vssadmin list shadows
```

Point-in-time snapshots. Any snapshot made while EAC was installed contains the full forensic record above.

### WER (Windows Error Reporting) queue

```
C:\ProgramData\Microsoft\Windows\WER\
C:\Users\<user>\AppData\Local\Microsoft\Windows\WER\
```

Cached crash dumps that haven't been uploaded yet. If Fortnite or EAC ever crashed, a minidump may be here with a full memory snapshot of the crashing process.

### Memory dumps

```
C:\Windows\Minidump\*.dmp
C:\Windows\Memory.dmp
```

Full memory snapshots on crash (if crash dump enabled). Can contain cheat DLL memory.

### Browser caches

```
Edge/Chrome/Firefox profile directories
```

May contain:
- Epic account email in form history.
- Epic session cookies.
- Epic launcher download history.

### Epic launcher caches

```
C:\ProgramData\Epic\EpicGamesLauncher\
%LOCALAPPDATA%\EpicGamesLauncher\
C:\ProgramData\Epic\SocialBackendCache\
```

Contain your Epic account ID, device ID cache, sessions, auth tokens. **Tied to your account even if you log out.**

---

## Part 3 — Advanced forensic artifacts

### ActivityHistory / Timeline

```
%LOCALAPPDATA%\ConnectedDevicesPlatform\<id>\ActivitiesCache.db
```

SQLite database of app activity. Shows Fortnite / EAC launches. Only on Win 10/11.

### Diagnostic data

```
C:\ProgramData\Microsoft\Diagnosis\
```

ETW traces, telemetry events. Includes Fortnite + EAC activity.

### Shellbags

```
HKCU\Software\Microsoft\Windows\Shell\Bags
HKCU\Software\Microsoft\Windows\Shell\BagMRU
```

Folder view history — shows folders you've navigated, including the Fortnite install directory.

### Thumbcache

```
%LOCALAPPDATA%\Microsoft\Windows\Explorer\thumbcache_*.db
%LOCALAPPDATA%\IconCache.db
```

Thumbnails cached when you browsed folders containing Fortnite screenshots/files.

### LNK files + RecentDocs

```
%APPDATA%\Microsoft\Windows\Recent\
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\
```

Per-file shortcuts for recently opened files.

### UserAssist

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\
```

ROT13-encoded app launch counts. Shows every launch of Fortnite.exe + EAC binaries.

### TypedPaths + OpenSaveMRU

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\
```

Address-bar typed paths + file-dialog history.

### RDP connection history

```
HKCU\Software\Microsoft\Terminal Server Client\
```

Remote desktop connection history.

### Windows Push Notification db

```
%LOCALAPPDATA%\Microsoft\Windows\Notifications\wpndatabase.db
```

Notification history (including Fortnite / Epic launcher notifications).

### Credential Manager

```
%APPDATA%\Microsoft\Credentials\
%LOCALAPPDATA%\Microsoft\Credentials\
```

Stored credentials (if Epic account credentials cached).

### DPAPI master keys

```
%APPDATA%\Microsoft\Protect\<SID>\
```

Keys used to decrypt DPAPI-protected data.

### LSA secrets

```
HKLM\SECURITY\Policy\Secrets
```

Requires SYSTEM to read. Contains cached account credentials.

### Scheduled Tasks

```
C:\Windows\System32\Tasks\
```

Task scheduler entries (some EAC installers add tasks).

### DriverStore

```
C:\Windows\System32\DriverStore\FileRepository\
```

**Every driver INF ever installed** — EAC's driver may have a persistent entry here even after service uninstall.

### Windows Search index

```
C:\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb
```

Full-text index of your system, including Fortnite log contents.

### ReadyBoot

```
C:\Windows\Prefetch\ReadyBoot\
```

Boot optimization traces — show boot-time EAC service load.

### Setup logs

```
C:\Windows\inf\setupapi.dev.log
C:\Windows\inf\setupapi.app.log
```

Every driver + device install event. Includes EAC driver install.

### Panther logs

```
C:\Windows\Panther\
```

Setup/upgrade logs. Record app installs during Windows updates.

### SxS / CBS logs

```
C:\Windows\Logs\CBS\CBS.log
```

Component-based servicing — record Windows updates that affected EAC's compatibility.

### Services registry

```
HKLM\SYSTEM\CurrentControlSet\Services\
```

Every service ever installed. EAC has its own entries; other historical AC services' entries may also be present.

### Windows.old (if upgrade)

```
C:\Windows.old\
```

Prior OS install remnants from an in-place upgrade. Contains all forensic artifacts from before the upgrade.

### Index.dat / WebCache

```
%LOCALAPPDATA%\Microsoft\Windows\WebCache\
```

IE legacy but still touched by various Windows components.

### NTFS low-level

```
$MFT          — Master File Table, every file record including slack entries
                of deleted files
$LogFile      — NTFS transaction log of recent filesystem ops
$INDX records — Directory index entries that survive file deletion
$Boot         — Volume boot sector (contains volume serial)
$Secure       — File security metadata
```

### Quarantine folders (Defender / AV)

```
C:\ProgramData\Microsoft\Windows Defender\Quarantine\
```

If Defender quarantined a cheat or EAC component, it's here.

### Game-specific additional traces

```
Discord logs + install path
Discord Rich Presence state
Steam install dir + friend list (if Steam running alongside)
NVIDIA Shadowplay captures (%USERPROFILE%\Videos\<Game>\)
OBS/streamlabs configs
AMD ReLive captures
Game bar captures (Win+G)
NVIDIA Container service logs (C:\ProgramData\NVIDIA\NVIDIA Container\*.log)
GeForce Experience tokens
```

---

## Part 4 — Epic account identifiers (Fortnite-specific)

Fields that correlate to Epic's server-side records:

| Field | Source |
|-|-|
| Epic Account ID (EpicAccountId) | Online auth session |
| Epic Product User ID (EOS_ProductUserId) | Per-product-sandbox identity |
| Epic Device ID | `%LOCALAPPDATA%\EpicGamesLauncher\Saved\DeviceIdCache` |
| Epic launcher install GUID | `HKLM\SOFTWARE\Epic Games\EpicGamesLauncher\AppDataPath` + install-time stamp |
| OAuth refresh tokens | Encrypted in launcher data |
| Session access tokens (JWT) | Memory + launcher data |
| EOS SandboxId (per game) | Per product |
| EOS DeploymentId | Per product |
| Linked platform accounts | Steam, Xbox, PSN, Nintendo — linked at account level |
| Fortnite session continuation tokens | Per-match |
| Battle Pass state | Per-account |
| Friend list | Server-side, cached locally per session |

**Account-level HWID binding:** Epic ties specific machine identifiers to the account at signup time + first-time-on-new-hardware moments. Playing from a new HWID on a banned account requires either (a) HWID spoof to match a non-banned HWID, (b) a new account and new hardware altogether.

---

## Part 5 — Comprehensive cleaner operation inventory

The full surface you'd need to touch for a comprehensive clean. This is an **inventory**, not an operational guide. Operational steps are left to the operator. Reinstalling Windows is the "nuclear" option and cleaner than any delete script because it regenerates the Windows identity fields along with the forensic artifacts.

| # | Step |
|-|-|
| 1 | Uninstall EAC and Fortnite via Epic launcher (regular path) |
| 2 | Uninstall system-wide EAC via its uninstaller |
| 3 | Delete `ProgramData` and `LocalAppData` directories listed in Part 1 |
| 4 | Delete Epic Games Launcher install directory |
| 5 | Delete Fortnite's saved data |
| 6 | Clear registry keys listed in Part 1 |
| 7 | Clear prefetch (files, not the directory) |
| 8 | Clear event logs (requires admin; **creates its own event log entry about the clearing**, which is itself forensically relevant) |
| 9 | Clear BAM via the SID subkey |
| 10 | Clear MUICache |
| 11 | Clear Shimcache — requires a reboot after registry wipe because Shimcache is read at boot and flushed at shutdown |
| 12 | Delete `Amcache.hve` — locked at runtime; needs offline boot or scheduled deletion |
| 13 | Wipe NTFS `$UsnJrnl` |
| 14 | Delete `pagefile.sys`, `hiberfil.sys`, `swapfile.sys` (disable paging, reboot, re-enable to regenerate empty) |
| 15 | Delete all VSS snapshots: `vssadmin delete shadows /all /quiet` |
| 16 | Delete WER queued dumps |
| 17 | Delete jump lists |
| 18 | Clear Windows Search index: `net stop wsearch` then delete `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\` |
| 19 | Clear recycle bin |
| 20 | Clear browser caches and history for any browser used to access Epic accounts |
| 21 | Delete ActivityHistory / Timeline SQLite db |
| 22 | Delete Shellbags registry keys |
| 23 | Delete UserAssist entries |
| 24 | Delete TypedPaths / OpenSaveMRU |
| 25 | Delete WPN notification db |
| 26 | Delete Credential Manager + DPAPI master key entries |
| 27 | Delete Panther / CBS / SxS logs |
| 28 | Clear EAC driver INF from DriverStore |
| 29 | Clear Windows.old if present |
| 30 | Clear thumbcache + iconcache |
| 31 | Clear Fortnite-related NVIDIA Shadowplay / AMD ReLive captures |
| 32 | Clear Discord / Steam / overlay app logs |
| 33 | Clear ReadyBoot traces |
| 34 | **Recognize that none of this touches the HWID binding — see Part 7** |

---

## Part 6 — Community observations on cleaning effectiveness (Nov 2026)

Direct observations from active Fortnite HWID-ban debugging (UC thread 779558 — AleaClient/ReTrac, generalizable):

### CatCaller's "only registry" claim (contested)

CatCaller (average-trust): *"The only 'traces' are in registry they do not leave any other. And yes, I have confirmed it just yesterday."*

**Followed by:** *"MAC, SMBIOS and Volume ID is also not needed."* (for unban)

### Counter from SOHELDAGOAT

*"doubt it he is wrong anyways like u need to spoof another identifier to get unbanned its not enough what he said."*

### Interpretation

The split suggests:
- **Registry-based trace** is a meaningful component — potentially the primary surface for session-level ban enforcement.
- **But not sufficient alone** — the HWID hash includes identifiers beyond MAC/SMBIOS/VolumeID, and spoofing only the obvious ones leaves gaps.

### Averser's "reinstall Windows" position

Averser (UC thread 781505): *"Cleanall diskpart. Reinstall win. Reinstalling Windows is enough to clean everything. because each update leaves a lot of new traces. cleaning software can barely keep up. so to avoid falling into an endless ban loop, the quickest solution to diagnose is to reinstall Windows and spoof."*

### Operational takeaway

If you have a cleaner that doesn't track **every** Windows-Update-generated trace point, you'll miss newly-created artifacts. Reinstalling Windows resets all of them at once. **Reinstall-and-spoof is the standard community approach for HWID-lite bans (24h to 365day).**

For permanent HWID bans: new hardware required, cleaning doesn't help.

### Short-duration HWID bans exist

Not all HWID bans are permanent. Observed durations in UC community:
- **24-hour HWID bans** — kaiquemarianoah (thread 781505): "banned for 24h after 1 year."
- **365-day HWID bans** — saseeexfg (thread 781256): "I recently got hwid banned on fortnite for 365 days."
- **Permanent HWID bans** — the classic.

Epic's enforcement tiers include time-limited HWID restrictions — not just binary banned/not-banned.

---

## Part 7 — Why cleaning alone doesn't beat HWID bans

**The critical point.** EAC's and Epic's backend don't need your on-disk forensic artifacts to re-recognize banned hardware. At next session start:

1. Agent collects the live-queried identifiers (see [11 HWID spoofing](11-hwid-spoofing.md)).
2. Hashes them.
3. Sends the hash.
4. Backend compares against the ban list.
5. Match → ban.

### Cleaning helps

- Prevent a **future** investigation from tying a new identifier to the old ban through log correlation on your disk.
- Make a disputed appeal less open-and-shut.
- Reset local caches that EAC uses for drift detection (future sessions start fresh).

### Cleaning does not

- Unban your hardware.
- Prevent the HWID hash on next launch from matching the ban list.
- Affect Epic's server-side records of your ban at all.

### The one operation that does beat an HWID ban on the same hardware

Spoof the inputs that go into the HWID hash. That's [11 HWID spoofing](11-hwid-spoofing.md).

---

## Part 8 — Ban status checking

### Specific URLs to check account state

```
https://www.epicgames.com/account/personal
```

Shows account-level restrictions. Doesn't show shadow-ban state (shadow bans are specifically designed to be opaque to the user).

Fortnite-specific ban history can be requested via Epic Support but requires identity verification and doesn't disclose shadow bans.

### Shadow-ban detection signals

Signals that correlate (see also [07 Fortnite integrity Part 7](07-fortnite-integrity.md#part-7--kick--soft-ban--hard-ban--hwid-ban-taxonomy)):

- Lobby skill distribution unusually low.
- Match search time increases 2-5x.
- Queue populates with accounts with similar "newness" patterns.
- Fewer human reactions from opponents.
- Reduced cosmetic diversity.

None definitive. Combined across 10+ matches, strong correlation.

### Ban-type summary table

Full taxonomy with user-facing symptoms lives in [07 Fortnite integrity Part 7](07-fortnite-integrity.md#part-7--kick--soft-ban--hard-ban--hwid-ban-taxonomy) — not duplicated here. Deltas specific to this doc (short-duration HWID tiers, not covered in doc 07):

| Ban type | What you experience |
|-|-|
| **HWID ban — 24h** | New account on same hardware blocked for 24 hours (kaiquemarianoah, thread 781505). |
| **HWID ban — 365d** | New account on same hardware blocked for a year (saseeexfg, thread 781256). |
| **HWID ban — permanent** | Classic case; new hardware required. |

---

## Part 9 — Operational cheat-market vernacular

2026-era cheat-market terms for ban states:

| Term | Meaning |
|-|-|
| "Flagged" | Server-side correlation data point added. Not yet a ban. |
| "Rolled" | Ban wave hit — account caught in a scheduled correlation sweep. |
| "Cooked" | Detected but not yet banned — the pre-ban correlation phase. |
| "HWID lock" | HWID ban. |
| "Spooged" | HWID detection tripwire fired, forthcoming ban. |
| "Dusted" | Account fully banned, hard. |
| "Chain lock" | Multi-account linked ban — Epic detects account-linked patterns and bans the chain. |
| "Burned" | Hardware HWID-banned and spoofer no longer helping; need new hardware. |

Useful for interpreting community-forum discussion.

---

**Next:** [11 — HWID spoofing surface](11-hwid-spoofing.md)
