# eac-emu-stub — EAC client-side emulation PoC

Single-source stub replacement for `EasyAntiCheat_x64.dll`. Satisfies a game's EAC integration contract without running anti-cheat checks.

**Full context + architecture + limits:** [`../../docs/13-eac-emulation.md`](../../docs/13-eac-emulation.md).

---

## Files

| File | Purpose |
|-|-|
| [`eac_emu_stub.c`](eac_emu_stub.c) | The stub itself. ~200 lines of C. Implements the public EOS AntiCheat Client interface + classic EAC client exports. All functions return success. |
| [`eac_emu_stub.def`](eac_emu_stub.def) | Module definition — exports with placeholder ordinals. Replace classic-EAC ordinals with ones lifted from your target build's real `EasyAntiCheat_x64.dll`. |
| [`b_dll_ordinals.c`](b_dll_ordinals.c) | **Byte-verified ordinal-only stub** matching Nov 20 2026 `b.dll` (5 unnamed ordinals at verified RVAs). Build standalone to produce a `b.dll` replacement. |
| [`b_dll_ordinals.def`](b_dll_ordinals.def) | `.def` for the ordinal-only stub — produces a DLL with 5 `NONAME` exports exactly matching the real agent's export table layout. |
| [`build.bat`](build.bat) | MSVC build script. |

## Companion PoCs

The stub in this directory replaces the client-side EOS SDK DLL. For complete on-host emulation:

- [`../eac-service-emu/`](../eac-service-emu/) — service emulator (`EasyAntiCheat_EOSSys`), pipe server, named events, shared memory, 23× `ErrRpt_*` registry values, 6× setup CLI subcommands.
- [`../eac-launcher-wrapper/`](../eac-launcher-wrapper/) — replacement for `a.dll` (launcher wrapper) with 5 named exports `a,b,c,d,e` matching Nov 20 2026 byte layout.

All three PoCs together recreate the on-host stack. Server-side gate (Epic + EAC backend) still rejects — see [`../../docs/15-protocol-recreation.md`](../../docs/15-protocol-recreation.md) Part 13 for the hard limit.

---

## Build

### Requirements

- Windows + Visual Studio (or VS Build Tools) 2019 or newer.
- Open a **Developer Command Prompt for VS** so `cl.exe`, `link.exe`, `dumpbin.exe` are on `PATH`.

### Run

```bat
cd poc\eac-emu-stub
build.bat
```

Output: `EasyAntiCheat_x64.dll` in the same directory.

### Manual build (if you don't want the batch file)

```bat
cl /nologo /LD /O2 /W3 /DWIN32_LEAN_AND_MEAN ^
   eac_emu_stub.c ^
   /Fe:EasyAntiCheat_x64.dll ^
   /link /DEF:eac_emu_stub.def
```

Verify exports:

```bat
dumpbin /exports EasyAntiCheat_x64.dll
```

---

## Install

**Research / modding / private-server use only.** Does not enable playing on Epic's live Fortnite servers.

1. Back up the real DLL:
   ```
   cd FortniteGame\Binaries\Win64\EasyAntiCheat
   ren EasyAntiCheat_x64.dll EasyAntiCheat_x64.dll.bak
   ```
2. Copy the stub in:
   ```
   copy <path>\poc\eac-emu-stub\EasyAntiCheat_x64.dll .
   ```
3. Launch via `FortniteClient-Win64-Shipping.exe` **directly**, **not** `FortniteClient-Win64-Shipping_EAC.exe`.

---

## Customizing for a target build

Per-build ordinal matching:

1. Open the real `EasyAntiCheat_x64.dll` for your target Fortnite build in CFF Explorer.
2. Dump its export table (sorted by ordinal).
3. Open the target Fortnite's `FortniteClient-Win64-Shipping.exe`'s IAT.
4. Find the imports from `EasyAntiCheat_x64.dll` — positional with the exports above.
5. Update [`eac_emu_stub.def`](eac_emu_stub.def) ordinals to match.
6. If the game uses functions not in this stub, add thin wrappers to [`eac_emu_stub.c`](eac_emu_stub.c) returning success.
7. Rebuild.

---

## Known limits (short version — long version in the doc)

- Current-build Fortnite (2026) verifies an Ed25519 signature on EAC's init callback. A stub can't produce that signature. Fortnite will exit at startup. Bypass requires patching the shipping exe's verification function.
- Any live-server session is rejected regardless because Epic's backend verifies session signatures the stub can't produce.
- The kernel driver still loads if the EAC service is running. The stub operates at the DLL layer only.

See [`../../docs/13-eac-emulation.md`](../../docs/13-eac-emulation.md) for the full private-server stack that works around these.

---

## Not a cheat

This PoC:

- Does not provide cheat capability.
- Does not bypass server-side correlation.
- Does not disable EAC's kernel driver.
- Does not include backend emulation.

It's research / modding / private-server client-side scaffolding. Nothing more.
