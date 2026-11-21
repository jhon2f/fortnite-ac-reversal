# `eac-launcher-wrapper` — launcher wrapper replacement (`a.dll`)

Replacement for `EasyAntiCheat.packed (1).dll` (internal name `a.dll`) — the pre-flight + game-launch DLL.

## Why a separate PoC

The agent (`b.dll`) and the launcher wrapper (`a.dll`) are two different DLLs with two different responsibilities:

| DLL | Role | Runs in |
|-|-|-|
| `a.dll` (this PoC) | Pre-flight checks + launch game | FortniteLauncher.exe |
| `b.dll` (../eac-emu-stub) | Scanning / EOS SDK integration | FortniteClient-Win64-Shipping.exe |

The launcher wrapper is where the long error-code list lives (`error_dtrace_enabled`, `error_dotlocal`, `error_patched_boot_loader`, etc. — see `docs/12-cheat-detection.md`). Replacing it bypasses the pre-launch environment checks.

## Byte-verified ordinal map (Nov 20 2026 build)

```
ord 1 'a'  RVA 0xC7837   — status getter (small, in cluster)
ord 2 'b'  RVA 0xC7892   — error getter (small, in cluster)
ord 3 'c'  RVA 0xC78C1   — product state getter (small, in cluster)
ord 4 'd'  RVA 0x2DDB2   — pre-flight + launch game  ← HEAVY
ord 5 'e'  RVA 0xC78F3   — cleanup (small, in cluster)
```

This stub uses the same ordinals + names. Drop-in order compatible.

## Build

```cmd
cl /LD /O2 eac_launcher_wrapper.c /Fe:EasyAntiCheat.dll ^
   /link /DEF:eac_launcher_wrapper.def kernel32.lib
```

## Install

Copy the output `EasyAntiCheat.dll` to Fortnite's `EasyAntiCheat\` directory (back up the real one first):

```cmd
cd "C:\Program Files\Epic Games\Fortnite\FortniteGame\Binaries\Win64\EasyAntiCheat"
copy EasyAntiCheat.dll EasyAntiCheat.dll.backup
copy <path-to-built-stub>\EasyAntiCheat.dll EasyAntiCheat.dll
```

The real wrapper has VMProtect packing. Your replacement doesn't need packing — Fortnite's launcher only cares about the named exports being present and returning expected values.

## Known limits

- **Calling convention is uncertain.** Real wrapper may use custom convention or pack extra context into args. Verify by setting a breakpoint at `0x2DDB2` in the real `a.dll` and observing stack / register state on entry.
- **Parameters to `d` are inferred.** The real signature may include additional args (platform handle, console callback, etc.). Minimum viable is `(wchar_t* exe, wchar_t* cmdline)` based on the typical `CreateProcess` convention.
- **Server-side gate still rejects.** Pre-flight bypass means the game launches; it does not mean the game's EOS session completes. See `docs/15-protocol-recreation.md` Part 13.
- **EAC_LAUNCHERDIR env var is byte-verified** — set it to the directory the launcher was launched from so the agent finds `EasyAntiCheat\Certificates\` etc.

## See also

- `docs/15-protocol-recreation.md` — complete recreation dossier
- `docs/03-user-mode-launcher.md` — launcher-side control flow
- `docs/12-cheat-detection.md` — complete tool blacklist + error code taxonomy
- `../eac-emu-stub/` — agent DLL replacement (`b.dll`)
- `../eac-service-emu/` — service emulator (`EasyAntiCheat_EOSSys`)
