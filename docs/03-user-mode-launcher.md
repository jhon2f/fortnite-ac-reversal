# 03 — User-mode launcher (`EasyAntiCheat_EOS.exe`, current)

Thin bridge between the Fortnite launcher, the EAC service, the driver, and the game. Its job is to spawn the game with the EAC forwarder stub (`EasyAntiCheat_EOS_x64.dll`, the on-disk 24 MB `b.dll` payload) preloaded, open a named pipe for the agent, and forward messages. The real scanner is subsequently manual-mapped into the game process by the EAC service — see [04 — User-mode agent, Part 2](04-user-mode-agent.md) and Part 7.5.

> Naming note: older docs (and the pre-EOS architecture) refer to `EasyAntiCheat.exe` / `EasyAntiCheat_x64.dll`. Current Nov 2026 builds ship as `EasyAntiCheat_EOS.exe` / `EasyAntiCheat_EOS_x64.dll`. Where this doc says `EasyAntiCheat_EOS_x64.dll`, treat it as the on-disk forwarder stub, not the real scanner.

Not where you spend most of your reversing time — but you need to understand the launcher because it holds the session-token chain that authenticates the agent to the driver.

---

## argv parsing

- `argv[1]` — session token. Short-lived signed blob issued by `FortniteLauncher.exe`. Contains expected game executable hash, timestamp, nonce. Signed by Epic.
- `argv[2]` — path to the game exe.
- `argv[3]` — the game's own command line (passed through).

---

## Flow

```
wmain:
  1. OpenSCManager + OpenService + StartService("EasyAntiCheat")
     wait for SERVICE_RUNNING
  2. CreateFile("\\.\EasyAntiCheat"), probe with HEARTBEAT
  3. CreateNamedPipe("\\.\pipe\EasyAntiCheat_<guid>", ...)
       message-mode, overlapped, REJECT_REMOTE_CLIENTS
  4. CreateProcess game in CREATE_SUSPENDED
  5. inject the EAC forwarder stub (EasyAntiCheat_EOS_x64.dll / b.dll) via
       VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
       thread start = LoadLibraryW, arg = remote wchar path
       (this is the forwarder only — the real scanner is NOT loaded here;
        the EAC service manual-maps it into the game later, with no LDR
        entry, see 04 Part 2)
  6. ResumeThread on the game's main thread
  7. ConnectNamedPipe, wait for the agent to come up and HELLO
  8. run the pipe server loop until the game exits
```

### Current-build injection hedge

Current builds also carry a secondary injection path using `NtCreateThreadEx` with a slightly different attribute list, as a hedge against `CreateRemoteThread` being filtered by third-party endpoint products. Both paths resolve to the same semantic: load the **forwarder stub** (`EasyAntiCheat_EOS_x64.dll`) in the game process before resume. The real scanner never goes through `LoadLibrary` on either path — it is manual-mapped by the service after injection (see [04 Part 2](04-user-mode-agent.md)), which is why DllMain-triggered thread-creation heuristics never fire on the scanner itself.

---

## Why the injection method is boring on purpose

EAC could use any number of exotic injection techniques and has historically flirted with some. What ships is `LoadLibrary`-via-`CreateRemoteThread` because the trust isn't in the injection method — it's in the **session token handoff**.

The chain:

1. `FortniteLauncher.exe` signs a session token with Epic's private key.
2. The token is passed via argv to `EasyAntiCheat.exe`.
3. `EasyAntiCheat.exe` appends it to the game's command line.
4. The game's main thread starts, agent DLL is injected, agent reads the token from `GetCommandLineW()`.
5. Agent presents the token back to the launcher's pipe server during `HELLO`.
6. Launcher validates the token's signature against Epic's pinned pubkey.

Only an agent-inside-the-real-game can present a valid token because only the real `FortniteLauncher.exe` can mint one, and tokens include a short-lived timestamp so you can't replay.

This is why "inject your own code alongside EAC_x64.dll" doesn't just-work. Your injected code can run, but it can't produce the signed token the agent needs to reach the driver. Without driver IOCTLs, the agent can't do its own scans either — you'd end up with a broken session the backend rejects immediately.

---

## Pipe server loop

Once the pipe is up and the agent has `HELLO`'d:

- Read framed messages from the agent.
- Dispatch by opcode (see [05 — pipe protocol](05-pipe-protocol.md)).
- Forward telemetry messages over a second named pipe to the **EAC service** (`EasyAntiCheat.exe`), which owns the outbound libcurl + mbedTLS socket to the backend (see [04 Part 7.5](04-user-mode-agent.md)).
- Forward `RULES_UPDATE` / `REMOTE_MODULE_LOAD` push messages from the backend (relayed back through the service) down to the agent.

The launcher is dumb — it doesn't inspect pipe payloads semantically. It's a demuxer between the agent and the service pipe, and a watchdog on the agent (if `HEARTBEAT` goes stale, it reports). The outbound TLS 1.2 session lives in the service process, not in the launcher and not in the agent.

---

## The launcher's own self-integrity

The launcher checks its own `.text` on startup (same as the agent and driver do), and verifies that the on-disk `EasyAntiCheat_EOS_x64.dll` (the 24 MB forwarder stub / `b.dll`) matches an expected hash before injecting it. The hash is baked into the launcher's binary at build time, which is why **replacing `EasyAntiCheat_EOS_x64.dll` with a modified copy causes the launcher to refuse to launch the game**.

Note that this check only covers the on-disk forwarder — the real scanner image never touches disk as a loadable file; it's manual-mapped by the service from an in-memory blob (see [04 Part 7.5](04-user-mode-agent.md)), so its integrity is enforced by the service, not by this launcher hash-check.

The workaround for research — if you want to run a modified agent DLL — is to also patch the launcher's hash-check, or to launch `FortniteClient-Win64-Shipping.exe` directly and skip the EAC launcher entirely. See [13 — EAC emulation](13-eac-emulation.md) for notes on the direct-launch path.

---

**Next:** [04 — User-mode agent](04-user-mode-agent.md)
