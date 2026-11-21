# `eac-service-emu` — service-side emulator skeleton

Companion to [`eac-emu-stub`](../eac-emu-stub) (the agent DLL replacement). That one replaces the client-side scanner; this one stands up the on-host service stack that the agent and game expect to be present.

## What it provides

| Surface | Object |
|-|-|
| Windows service | `EasyAntiCheat_EOSSys` |
| Pipe server | `\\.\pipe\EasyAntiCheat_EOS` |
| Shared memory mapping | `Global\EasyAntiCheat_EOSBin` (64 KB) |
| Named event (driver → UM) | `Global\EasyAntiCheat_EOSEventDriver` |
| Named event (service → game) | `Global\EasyAntiCheat_EOSEventGame` |
| Named event (agent → service) | `Global\EasyAntiCheat_EOSEventModule` |
| Registry values | 23× `HKLM\Software\EasyAntiCheat_EOS\ErrRpt_*` |
| TPM status stubs | `HKLM\SYSTEM\...\EasyAntiCheat_EOS\Attestation\QuoteKey*` |
| CLI subcommands | `install`, `uninstall`, `repair`, `verify-and-install`, `verify-installation`, `qa-factory-reset` |

## What it does not provide

- Driver (`\Device\EasyAntiCheat_EOS` creation requires a kernel driver — see `docs/02-kernel-driver.md`)
- TPM attestation — only stubs the status values; a real TPM quote requires `Microsoft Platform Crypto Provider` + a provisioned AIK
- EventLog subscription — the strings are documented in `docs/15-protocol-recreation.md` Part 5 but not reimplemented here
- Real crypto on the pipe frames — frames are echoed as success
- Chain to EOS backend — see `docs/15-protocol-recreation.md` Part 13

## Build + install

```cmd
rem Build (open "x64 Native Tools Command Prompt for VS")
cl /O2 /DUNICODE /D_UNICODE eac_service_emu.c /Fe:EasyAntiCheat_EOS.exe ^
   /link advapi32.lib kernel32.lib user32.lib

rem Install as Windows service (requires Administrator)
sc create EasyAntiCheat_EOSSys binPath= "C:\path\to\EasyAntiCheat_EOS.exe" start= demand
sc description EasyAntiCheat_EOSSys "Provides security for online multiplayer games."

rem Also register install-time (writes registry baseline)
EasyAntiCheat_EOS.exe install 95e760e6a6a447c28dc50db3e78d060f

rem Start
sc start EasyAntiCheat_EOSSys
```

## Observability

When running, use Process Explorer to verify:
- Service process has handles to all 3 named events
- `Global\EasyAntiCheat_EOSBin` appears in `\BaseNamedObjects\Global`
- `\Device\NamedPipe\EasyAntiCheat_EOS` appears in Named Pipes
- `HKLM\Software\EasyAntiCheat_EOS` contains the 23 `ErrRpt_*` values

To probe the pipe from another process:

```c
HANDLE p = CreateFileW(L"\\\\.\\pipe\\EasyAntiCheat_EOS",
                      GENERIC_READ|GENERIC_WRITE, 0, NULL,
                      OPEN_EXISTING, 0, NULL);
/* Write any frame → service echoes success envelope. */
```

## Known limits

- Shared memory header uses speculative magic (`'EACS'`). Real magic is not byte-verified from current binaries. If you're trying to drive an actual game process against this stub, patch the game side to accept the stub header or reverse the real magic from `b.dll` at RVA `0x4FEA3`.
- Pipe frame format assumes the reconstructed `{len,seq,opcode,flags,body}` layout from doc 05. Real opcodes are not byte-verified.
- `QuoteKeyStatus=1` is accepted locally but server-side TPM attestation will reject without a real quote.

## See also

- `docs/15-protocol-recreation.md` — complete recreation dossier (byte-verified service internals)
- `docs/02-kernel-driver.md` — IOCTL surface for the driver side
- `docs/05-pipe-protocol.md` — pipe frame format
- `../eac-emu-stub/` — client-side agent replacement (ordinals + EOS SDK)
- `../eac-launcher-wrapper/` — launcher wrapper replacement (`a.dll` exports)
