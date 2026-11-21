# Analysis 02 — UC Linux-proxy EAC/EOS emulator

Full-source dual-architecture emulator that **proxies EOS SDK calls from a Windows game client to a Linux/Proton backend**, letting Linux-side EAC (weaker integrity) authenticate the session against Epic's backend.

Analyzed from `eac-emulator_[unknowncheats.me]_.zip`. Author credit: `mrdhanz` / `@ShimadaNanaki`.

---

## What the emulator is

**Not a stub.** A genuine proxy that forwards every EOS SDK call across a WebSocket, so the real EOS SDK + real EAC Linux client can process it in a Wine/Proton environment, talk to Epic's backend, and produce a legitimate session. The Windows game thinks it's talking to its local EOS SDK; it's actually talking to EOS SDK running on a Linux VM / WSL instance.

### Why this works

EAC has three target platforms: Windows native, Linux native, and Linux-via-Proton. The Linux-under-Proton variant exists for Steam Deck compatibility. **It runs with much weaker kernel integration** because Wine doesn't give you a real Windows kernel to install drivers in. The Linux EAC client is essentially a user-mode checker.

If you can run that Linux EAC client in an environment you control, you can subvert its user-mode checks (hook, patch, selectively break), let it successfully authenticate to Epic's backend, and relay the resulting valid-session state to a Windows game that's unaware the authentication happened off-system.

---

## Architecture (from `README.md`)

```
+-------------------------------------------------------------+
|                     WINDOWS HOST MACHINE                    |
|                                                             |
|  [ Game Executable ]                                        |
|          |                                                  |
|          v (Calls EOS/EAC APIs)                             |
|  [ EOSSDK-Win64-Shipping.dll ]  <-- CLIENT PROXY HOOK       |
|          |                                                  |
|          |  HTTP:7778 + WebSocket:7777 to localhost         |
+----------|--------------------------------------------------+
           |
           v (Localhost or LAN relay)
+-------------------------------------------------------------+
|                 LINUX / PROTON / QEMU / WSL                 |
|                                                             |
|  [ version.dll ]               <-- LOADED VIA WINEDLLOVERRIDES
|          |                         (Hosts HTTP + WebSocket)
|          v                                                  |
|  [ REAL EOS SDK + EAC CLIENT ]  <-- validates in Proton     |
+-------------------------------------------------------------+
```

---

## Windows side (`src/win/`)

### Entry: `DllMain`

```cpp
BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH && utils::is_game_process()) {
        init();
    }
    return TRUE;
}
```

The DLL only activates when loaded inside the actual game process (not when loaded by other tools inspecting it).

### Exports (`src/win/exports.def`)

**677 exports** — every single public EOS SDK function. Count was obtained from the module definition file:

```bash
# Count EXPORTS entries in the .def
grep -cE '^\s+EOS_' src/win/exports.def
# → 677

# Or, after build, confirm against the produced DLL:
dumpbin /exports EOSSDK-Win64-Shipping.dll | grep -cE '^\s+[0-9]+\s+[0-9A-F]+'
# → 677
```

Most are `dummy_func` stubs; the critical ones are routed to `Dummy*` implementations:

| Export (classical EOS SDK) | Implementation |
|-|-|
| `EOS_Initialize` | `DummyEOS_Initialize` |
| `EOS_Platform_Create` | `DummyEOS_Platform_Create` |
| `EOS_Platform_Tick` | `DummyEOS_Platform_Tick` |
| `EOS_Platform_GetAntiCheatClientInterface` | `DummyEOS_Platform_GetAntiCheatClientInterface` |
| `EOS_Platform_GetConnectInterface` | `DummyEOS_Platform_GetConnectInterface` |
| `EOS_Connect_Login` | `DummyEOS_Connect_Login` |
| `EOS_Connect_GetLoginStatus` | `DummyEOS_Connect_GetLoginStatus` |
| `EOS_AntiCheatClient_BeginSession` | `DummyEOS_AntiCheatClient_BeginSession` |
| `EOS_AntiCheatClient_EndSession` | `DummyEOS_AntiCheatClient_EndSession` |
| `EOS_AntiCheatClient_ReceiveMessageFromServer` | `DummyEOS_AntiCheatClient_ReceiveMessageFromServer` |
| `EOS_AntiCheatClient_AddNotifyMessageToServer` | `DummyEOS_AntiCheatClient_AddNotifyMessageToServer` |
| `EOS_AntiCheatClient_AddNotifyClientIntegrityViolated` | `DummyEOS_AntiCheatClient_AddNotifyClientIntegrityViolated` |
| ...a few other `Dummy*` for session tick, status, etc. | |

Everything else is a stub `dummy_func` returning success.

### The actual AntiCheat proxy

From `eos_impl/eos_anticheat_impl.cpp`:

```cpp
EOS_DECLARE_FUNC(EOS_EResult)
DummyEOS_AntiCheatClient_BeginSession(
    EOS_HAntiCheatClient handle,
    const EOS_AntiCheatClient_BeginSessionOptions* options
) {
    PLOGI.printf("Beginning session with mode: %d", options->Mode);
    auto packet = std::make_shared<begin_session_packet>();
    packet->api_version = options->ApiVersion;
    packet->user_id = options->LocalUserId;
    packet->mode = options->Mode;
    emulator_client::get_instance()->send_packet(packet);
    {
        std::lock_guard lock(session_state_mutex);
        has_active_session = true;
        last_begin_api_version = options->ApiVersion;
        last_begin_user_id = options->LocalUserId;
        last_begin_mode = options->Mode;
    }
    return EOS_Success;
}

EOS_DECLARE_FUNC(EOS_EResult)
DummyEOS_AntiCheatClient_ReceiveMessageFromServer(
    EOS_HAntiCheatClient handle,
    const EOS_AntiCheatClient_ReceiveMessageFromServerOptions* options
) {
    const auto* bytes = static_cast<const char*>(options->Data);
    auto message_base64 = (bytes != nullptr && options->DataLengthBytes > 0)
        ? base64::encode_into<std::string>(bytes, bytes + options->DataLengthBytes)
        : std::string();
    auto packet = std::make_shared<receive_message_packet>();
    packet->api_version = options->ApiVersion;
    packet->base64_message = nullable_string(message_base64);
    packet->data_length_bytes = options->DataLengthBytes;
    emulator_client::get_instance()->send_packet(packet);
    return EOS_Success;
}
```

**Every incoming EAC server→client message gets base64-encoded, wrapped in a `receive_message_packet`, and forwarded to the Linux backend over WebSocket.** The Linux backend passes it to the real EAC Linux client, which processes it (verifies signatures, updates trust state), and emits any outbound client→server reply, which the backend forwards back.

### Transport

```cpp
emulator_client(std::string address, int http_port) {
    sender = std::make_shared<packet_sender>(client.getWebsocketClient());
    sender->start();
    client.set_packet_handler(std::make_shared<client_packet_handler>(sender));
    client.run(address, tcp_port);
}
```

- **WebSocket on port 7777** for bidirectional packet flow.
- **HTTP on port 7778** for request/response (login, id→string, status queries).
- Config stored in `config.json` next to the game exe.

---

## Linux side (`src/linux/`)

### Entry: `DllMain` + hook `UnityMain`

```cpp
BOOL WINAPI DllMain(HINSTANCE, DWORD fdwReason, LPVOID) {
    if (fdwReason != DLL_PROCESS_ATTACH) return TRUE;
    forwarder::setup();
    if (!utils::is_game_process()) return TRUE;
    // ... exception handler, console, config.json
    bootstrapper::main(json["tcp"], json["http"]);
    return TRUE;
}
```

`forwarder::setup()` installs forwarder exports so other DLLs in the Wine prefix depending on `version.dll` keep working.

### The hook: `UnityMain` interception

```cpp
void bootstrapper::hook_winmain() {
    MH_Initialize();
    HMODULE unityPlayerHandle = GetModuleHandleA(UNITY_PLAYER_MODULE_NAME);
    if (unityPlayerHandle == nullptr) {
        unityPlayerHandle = LoadLibraryA(UNITY_PLAYER_MODULE_NAME);
    }
    void* unityMain = GetProcAddress(unityPlayerHandle, "UnityMain");
    MH_CreateHook(unityMain, &Dummy_WinMain, &originalFunc);
    MH_EnableHook(unityMain);
}

int bootstrapper::Dummy_WinMain() {
    handler_registry::init();
    api_handler_registry::init();
    websocket_server::launch(tcp_port);
    http_server::run(http_port);
    while (true) {
        if (!websocket_server::has_connection()) {
            websocket_server::wait_for_connection();
        }
        Sleep(1000 / 30);  // 30 fps
        websocket_server::tick();
        if (eos::is_eos_initialized() && eos_platform::is_platform_created()) {
            eos_platform::tick();
        }
    }
}
```

**The Linux side hijacks the Unity game's `UnityMain` entry point** — instead of running the game, it runs the EOS proxy server. The Linux-side "game" is just infrastructure; the real game is on Windows.

Under Proton, the Linux side launches a Wine environment with `WINEDLLOVERRIDES="version.dll=n,b"`, which makes Wine load the attacker's `version.dll` *instead of* the system `version.dll`. That's the loader entry point. Since `version.dll` has export forwarders, other DLLs looking for `version.dll` functions still work.

### Real EOS SDK invocation

The Linux side uses the actual EOS SDK (statically linked or loaded alongside). `src/linux/eos/` contains `eos.cpp`, `eos_platform.cpp`, `eos_anticheat.cpp`, `eos_connect.cpp`. Each wraps a real EOS SDK call that the Windows proxy's packets eventually invoke.

**This is the key:** the Linux side IS running real EOS + real EAC. From Epic's view, there's a legitimate Proton player authenticating with their EOS backend. The proxy relays the resulting session state to the Windows game, which plays with the backend's stamp of approval.

---

## Packet protocol

### Common types (`src/common/protocol/packets/`)

| Packet | Direction | Payload |
|-|-|-|
| `handshake_packet` | Both | Initial setup |
| `initialize_eos_packet` | Win → Linux | `EOS_Initialize` options |
| `create_platform_packet` | Win → Linux | `EOS_Platform_Create` options |
| `begin_session_packet` | Win → Linux | AntiCheat BeginSession options |
| `end_session_packet` | Win → Linux | AntiCheat EndSession |
| `receive_message_packet` | Win → Linux | Base64 server-to-client AC message |
| `notify_message_to_server_packet` | Linux → Win | Outbound client-to-server AC message |

### Serialization

Custom stream-based binary over WebSocket. From `src/common/protocol/stream/`:

- `read_stream.h` / `write_stream.h` / `buffer.h` — binary packet codec.
- `packet_codec.cpp` / `packet_factory.cpp` — routes packet ids to constructors.

### HTTP API

From `src/common/api/requests/`:

| Request | Purpose |
|-|-|
| `login_request` | EOS Connect login |
| `login_status_request` | Query login state |
| `id2string_request` | Convert EOS id types to strings |

Routed HTTP POST to `/task` endpoint on port 7778.

---

## Session recreation

```cpp
void recreate_anticheat_session_if_needed() {
    // ... reload state from last begin
    PLOGW.printf("Recreating AntiCheat session...");
    auto end_packet = std::make_shared<end_session_packet>();
    emulator_client::get_instance()->send_packet(end_packet);
    client_packet_handler::replay_notify_message_to_server_bindings();
    auto begin_packet = std::make_shared<begin_session_packet>();
    // ... resend
}
```

If the WebSocket drops mid-session, the client caches the last `BeginSession` parameters and replays them after reconnect. This is what makes the proxy survive network blips — the Linux side can be recreated and the session resumed without the game process ever knowing the backend connection flaked.

---

## Operational setup

Short version of `SETUP_GUIDE_WSL.md`:

1. Build in Visual Studio 2022 — outputs `EOSSDK-Win64-Shipping.dll` + `version.dll`.
2. On WSL2 Ubuntu: install Steam, Proton, the target game. Run the game once to initialize the Proton prefix.
3. Copy `version.dll` into `~/.steam/steam/steamapps/common/<GameFolder>/`.
4. Launch via:
   ```bash
   WINEDLLOVERRIDES="version.dll=n,b" ~/proton.sh ~/.steam/steam/steamapps/common/<GameFolder>/<GameExecutable>.exe
   ```
   The `n,b` flag means "native before builtin" — Wine loads the attacker's `version.dll` first.
5. On Windows: copy `EOSSDK-Win64-Shipping.dll` into `<Game>_Data\Plugins\x86_64\`.
6. Edit `config.json` on Windows side to point at WSL's IP (default 127.0.0.1 with WSL2 localhost forwarding).
7. Launch Proton game first (starts the proxy servers), then launch the Windows game client.

---

## What this achieves

- **Game runs on Windows at full performance.**
- **EOS SDK calls are proxied to Linux.**
- **Linux EAC client runs in a Wine environment** where its kernel-integration isn't a real Windows kernel.
- **Real EOS backend authenticates the session.**
- **Windows game receives valid session state.**

For an EAC-protected game whose Windows integrity checks would normally detect cheat tools / modified binaries / HWID anomalies: **the Windows side is clean because none of the EAC logic runs there.** The Linux side's EAC can be tolerated because its integrity checks are user-mode-only and don't observe the Windows machine's state.

---

## What this does NOT do

- **Does not work for Fortnite.** Fortnite has no Linux build to proxy to. The Linux EAC client exists for Linux-native games, not for cross-platform relay.
- **Does not defeat server-side correlation.** Session state is legitimate from Epic's view, but if the Linux-side user is a Steam account that Epic's backend recognizes as the same person across machines, same correlation applies.
- **Does not provide cheat capability.** Just makes the Windows side not need to pass EAC's integrity checks.

---

## Target titles

The README mentions:
- **VRChat** (Unity, uses EOS for matchmaking)
- **SpiritVale** (Unity, EAC-protected)
- Generic Unity + EOS-based titles

The emulator's hook into `UnityMain` on the Linux side ties it to Unity games. Not usable against non-Unity targets.

---

## Dependencies (from the source)

- **MinHook** — API hooking (used on the Linux side to hook `UnityMain`)
- **libhv** — event loop + HTTP + WebSocket server/client
- **nlohmann/json** — JSON serialization
- **plog** — logging

All MIT-licensed, standard open-source toolchain.

---

## What this reveals about EOS SDK

- **The 677 EOS SDK exports can be fully proxied** without the game noticing — meaning the SDK is a thin veneer around network protocols, not a cryptographic black box.
- **AC message bytes (base64-encoded in the proxy) are opaque to both sides** — EAC's message format is just forwarded, both client and server endpoints handle semantics.
- **Session state is per-platform at the SDK level** but resolves to per-product at the backend level. The proxy exploits that.

---

**Next:** [03 — MCC in-process bypass](03-mcc-in-process-bypass.md)
