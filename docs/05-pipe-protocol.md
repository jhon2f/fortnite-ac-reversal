# 05 — Pipe protocol

Named pipe between `EasyAntiCheat.exe` (server) and the injected `EasyAntiCheat_x64.dll` (client).

- Path: `\\.\pipe\EasyAntiCheat_<session-guid>`
- Mode: `PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE`
- Flags: `PIPE_REJECT_REMOTE_CLIENTS`
- Overlapped I/O both sides.

---

## Frame format

```
'EACP'       u32  magic
opcode       u16
flags        u16  (bitfield — see below)
payloadLen   u32
crc32        u32  (of payload)
payload      u8[payloadLen]
```

### Flags

| Bit | Meaning |
|-|-|
| `0x1` | `ENCRYPTED` — payload is AES-GCM under session ephemeral key. |
| `0x2` | `ACK_REQUIRED` — sender expects an ack frame. |
| `0x4` | `FRAGMENT` — payload continues in next frame. |

### Encryption (when `ENCRYPTED` is set)

- Cipher: **AES-GCM** (AES-128-GCM or AES-256-GCM — both mode strings are present in the agent DLL).
- Nonce: 12 bytes = `[session_nonce_prefix (8)] + [counter (4)]`. Counter increments per frame.
- Tag: 16-byte GCM tag appended after the ciphertext.
- Key: session ephemeral key (16 or 32 bytes), delivered by the launcher in `WELCOME`.

> **Correction (2026-11-20 audit):** earlier drafts of this doc claimed ChaCha20-Poly1305. A byte-scan of all four current binaries found zero occurrences of ChaCha/Poly1305/XChaCha; the agent contains only AES mode strings. AEAD is AES-GCM. See doc 04 Part 4 and doc 06 for the crypto correction.
- CRC coverage: the `crc32` field is computed over the bytes that appear in `payload` on the wire. When `ENCRYPTED` is set that means the CRC covers the ciphertext **including the trailing 16-byte GCM tag** — not the plaintext. Verify CRC first, then decrypt.

---

## Handshake

First few frames are unencrypted so both sides can agree on the session key.

### 1. `HELLO` (agent → launcher)

```
protocolVer   u16
agentBuild    char[32]      // "EAC_2026_MM_DD" style
processId     u32
bootCookie    u64
```

### 2. `WELCOME` (launcher → agent)

```
sessionId        u8[16]       // GUID
ephemeralKey     u8[32]       // AES-GCM session key (128/256-bit)
serverTime       u64
```

From here on frames can set `ENCRYPTED`.

### 3. `AUTH` (agent → launcher)

```
sessionToken     u8[...]      // the launcher's signed proof-of-launch blob
```

### 4. `AUTH_OK` or `AUTH_FAIL` (launcher → agent)

```
AUTH_OK:
  capsBitmap     u32          // which features the launcher's build supports

AUTH_FAIL:
  reasonCode     u32
```

### 5. `CONFIG` (launcher → agent)

```
scan_intervals {
  module_s, window_s, hook_s, integrity_s, input_s     // all u16
}
enabled_modules          u64       // bitmap of which scanners are on
frame_capture_period_s   u16
env_check_period_s       u16
```

The `enabled_modules` bit-to-scanner mapping is **not fixed** — the backend rotates per-handler feature flags per session, and the bit order shifts with each driver build (see doc 04 Part 16). To recover the current mapping, cross-reference the dispatch table that the agent indexes with this bitmap against the handler offsets listed in docs 02 and 04. Do not hard-code bit numbers.

Handshake ends here — once `CONFIG` is applied the agent transitions to the steady-state loop. `REMOTE_MODULE_LOAD` is a server-push opcode that may arrive at any point during the session, not a handshake frame; see the deep-dive below the opcode table.

---

## Opcode table

Numbers rotate per build — descriptions by behavior.

### Recovering current-build numbers

The opcode space is a dense `switch` inside the agent's pipe-frame dispatcher. To anchor it for a given build:

1. Find the dispatch switch in the agent DLL (the function called immediately after frame CRC/decrypt, taking `opcode` as its selector).
2. Anchor opcode `1` by setting a breakpoint on the `HELLO` handler — it is always the first frame the agent sends, so it is trivial to catch at session start and walk back to the switch arm.
3. Once `HELLO` is anchored you can label the remaining arms by behavior (every other opcode in the agent → launcher column has a distinct handler: scan triggers, report serializers, keepalive, etc.).
4. For launcher → agent opcodes, hook `WELCOME` first (second frame on the wire) and work outward.

Alternatively, dump a few sessions of plaintext pre-encryption frames and correlate payload shapes with the handler bodies.

### Agent → launcher

| Opcode | Content |
|-|-|
| `HELLO` | Build id, protocol version, pid. |
| `AUTH` | Session token blob. |
| `HEARTBEAT` | Periodic keepalive. |
| `REPORT_FLAG` | A scan found something. |
| `REPORT_MODULE_LIST` | Periodic LDR snapshot. |
| `REPORT_VAD` | Periodic VAD snapshot. |
| `REPORT_DRIVERS` | Periodic kernel driver list. |
| `REPORT_CALLBACKS` | Competing kernel callbacks. |
| `REPORT_SCREENSHOT` | Compressed captured frame (JPEG or AVIF). |
| `REPORT_INPUT_STATS` | Binned mouse distributions. |
| `REPORT_ENV_DRIFT` | Environment-fingerprint change observed. **(New in current.)** |
| `PIPE_LOG` | Debug log. Usually debug builds only. |
| `BAIL` | Fatal, closing connection. |

### Launcher → agent

| Opcode | Content |
|-|-|
| `WELCOME` | Session id, ephemeral key, server time. |
| `AUTH_OK` / `AUTH_FAIL` | Response to agent `AUTH`. |
| `CONFIG` | Scan intervals + enabled module bitmap. |
| `RULES_UPDATE` | Push a refreshed rules blob. |
| `REQUEST_SCAN` | Immediate scan of category N. |
| `REQUEST_SCREENSHOT` | Capture a frame now. |
| `KICK` | Please close gracefully. |
| `HARD_KILL` | Die now. |
| `REMOTE_MODULE_LOAD` | Load a signed auxiliary scanner DLL from the module CDN. **(New in current.)** |

---

## `REMOTE_MODULE_LOAD` deep dive

The interesting current-build opcode.

### Why

Lets Epic deploy new detections without shipping a new EAC version. A new cheat loader appears in the wild; Epic reverses it, writes a scanner, signs it, pushes it. Next session start, every player's agent pulls the new scanner down, runs it alongside the baked-in ones.

### How

1. Launcher receives (or has cached) a signed module blob from `modules-cdn.eac-prod.on.epicgames.com`.
2. Launcher pushes it to the agent over the pipe via `REMOTE_MODULE_LOAD`.
3. Agent verifies the **RSA** signature with a baked-in Epic pubkey (see the crypto correction in doc 06 — zero Ed25519 OIDs exist in any Nov 20 2026 binary; the driver carries 12 RSA pubkey OIDs).
4. Agent **manually maps** the module (not `LoadLibrary` — adding an unsigned-path-looking module to LDR would be hygiene-breakage and self-flag).
5. Agent builds a minimal IAT via `GetProcAddress` internally.
6. Agent calls the module's exported entrypoint with a pointer to an EAC-provided `scan context`.
7. The scan module reports findings back via a callback in the context.
8. Module stays resident for the session, unmapped at teardown.

### How to capture

Two routes:

- **Pipe tap.** Dump pipe frames from inside the game process. When you see a `REMOTE_MODULE_LOAD` frame, the payload is the raw signed DLL bytes.
- **CDN tap.** mitmproxy on `modules-cdn.eac-prod.on.epicgames.com` after patching EAC's pin check per [08 — protection stack](08-protection-stack.md).

Capture every remote module every session. They accumulate — new detections get added, old ones get retired. Build a corpus; each module is a mini-RE project on its own.

---

**Next:** [06 — rules.bin](06-rules-bin.md)
