# Analysis 03 — MCC in-process EOS bypass + XUID spoof

In-process memory patcher for Halo: The Master Chief Collection. **NOPs the EOS integrity check** at a specific RVA + **spoofs host XUID** over local XUID across all MCC sub-titles.

Analyzed from `mcc_[unknowncheats.me]_.zip` — source + compiled DLL + injector. The simplest and most fragile of the three architectures.

---

## What it is

A user-mode DLL (`mcc_eos_bypass.dll`) injected into the MCC game process. Runs a background worker thread every 500ms that:

1. **Patches `EOSSDK-Win64-Shipping.dll`** at RVA `0x3AD910` with `C3 90 90 90 90` (`ret; nop*4`) — short-circuits the EOS integrity validation.
2. **Reads the host player's XUID** from MCC's session object in memory.
3. **For each loaded Halo title DLL** (Reach / H3 / ODST / H4 / H2A), writes the host XUID over the local XUID in the title DLL's memory and NOPs validation sites that would otherwise reject the overwrite.

Backs up original bytes before patching. Restores on process detach.

---

## File manifest

| File | Size | Purpose |
|-|-|-|
| `compiled/dlls/mcc_eos_bypass.dll` | 140 KB | Prebuilt bypass DLL |
| `compiled/injector.exe` | — | Manual-map injector |
| `src/mcc_eos_bypass/mcc_eos_bypass.cpp` | 15.7 KB | Full source |
| `src/mcc_eos_bypass/CMakeLists.txt` | — | Build config |
| `src/injector/Program.cs` | 9.3 KB | C# injector source |

---

## Core constants

```cpp
constexpr const char* kEosModule = "EOSSDK-Win64-Shipping.dll";
constexpr uint32_t kEosPatchRva = 0x3AD910;
constexpr uint8_t kEosPatch[5] = {0xC3, 0x90, 0x90, 0x90, 0x90}; // ret; nop*4

constexpr const char* kMccModule = "MCC-Win64-Shipping.exe";
constexpr uint32_t kMccSessionRva = 0x4000A48;
constexpr uint32_t kMccSessionToPlayerManager = 0x60;
constexpr uint32_t kMccHostXuidOffset = 0x6A0;
```

### What these mean

- **`kEosPatchRva = 0x3AD910`** — the RVA inside `EOSSDK-Win64-Shipping.dll` where the EOS integrity check function starts. The bypass turns its prologue into a `ret;` so it returns immediately without checking anything.
- **`kMccSessionRva = 0x4000A48`** — pointer in MCC's main module pointing to the session object.
- **`kMccSessionToPlayerManager = 0x60`** — field offset inside the session object pointing to the player manager.
- **`kMccHostXuidOffset = 0x6A0`** — field offset inside the player manager pointing to the host's XUID.

The chain to read host XUID:
```
MCC.exe + 0x4000A48  →  [session*]
session* + 0x60      →  [player_manager*]
player_manager* + 0x6A0  →  [host_xuid: u64]
```

---

## Per-title tables

Each Halo title inside MCC loads as its own DLL (`haloreach.dll`, `halo3.dll`, `halo3odst.dll`, `halo4.dll`, `groundhog.dll` (= Halo 2: Anniversary)). Each has its own XUID storage location and its own validation sites.

```cpp
struct TitleInfo {
    const char* module_name;
    uint32_t local_xuid_rva;     // current identity read by the cheat
    uint32_t first_nop_rva;      // validation site NOPed before the write
    uint32_t first_nop_size;
    uint32_t write_rvas[2];      // XUID/network identity fields
    int write_count;
    const NopSite* post_nops;
    int post_nop_count;
    uint32_t state_ptr_rva;      // player-state pointer (0 = no check)
    uint32_t state_flag_offset;  // match-ended flag inside that state
    bool state_required;         // skip spoof if the pointer is invalid
    uint32_t ui_string_rva;      // in-game/menu UI string (0 = no gate)
};
```

Full table (from the source):

```cpp
constexpr TitleInfo kTitles[] = {
    {"haloreach.dll", 0x2A1E978, 0x2A7ACA, 8, {0x2A1E978, 0}, 1, kReachPost, 8, 0xB87E90, 0x5DED10, true, 0x274DE9F},
    {"halo3.dll",     0x1E24938, 0x2BBB1E, 8, {0x1E24938, 0}, 1, kH3Post,   1, 0x8DDF48, 0x47FDD4, false, 0x20F677B},
    {"halo3odst.dll", 0x1E6C658, 0x2E34FC, 8, {0x1E6C658, 0}, 1, kOdstPost, 1, 0, 0, false, 0},
    {"halo4.dll",     0x3197A68, 0x3A8B45, 8, {0x3197A68, 0}, 1, kH4Post,  11, 0x107C0C8, 0x5881CC, true, 0x2A30393},
    {"groundhog.dll", 0x1BCB0E8, 0x3A9715, 8, {0x1BCB0E8, 0x1BC99A0}, 2, kH2aPost, 2, 0x106DFC8, 0x5881CC, true, 0},
};
```

Each title has a different number of post-NOP sites — Halo 4 has 11, Halo 3 has 1. This is why per-title tables are needed: each title's EOS integration has different validation points.

### Example — Reach's post-NOPs

```cpp
constexpr NopSite kReachPost[] = {
    {0x2C932B, 9}, {0x0D162B, 2}, {0x0D19C9, 2}, {0x2C80D3, 8},
    {0x2C7D32, 6}, {0x2C80ED, 8}, {0x2C7FBC, 7}, {0x2A6A6E, 6},
};
```

8 separate validation sites in `haloreach.dll` NOPed after the XUID write. Each is a `cmp` + `jne` or equivalent check that would see "this XUID doesn't match what I remember from earlier" and either refuse to proceed or crash.

---

## The worker loop

```cpp
DWORD WINAPI WorkerThread(LPVOID) {
    while (true) {
        const DWORD wait = WaitForSingleObject(g_stop_event, 500);
        if (wait == WAIT_OBJECT_0)
            break;
        ApplyEosPatch();
        AutoSpoofTick();
    }
    return 0;
}
```

Runs every 500ms. Two operations per tick:

### `ApplyEosPatch()` — EOS integrity check NOP

Checks if the EOS module's RVA `0x3AD910` has been reset to its original bytes (which happens if the game reloads the module). If so, patches again. If already patched, no-op.

Keeps a saved copy of the original 5 bytes for clean restoration on detach.

### `AutoSpoofTick()` — XUID spoofing state machine

1. **Find the active title DLL.** Walks the title table, calls `GetModuleHandleA` for each, checks if the title's UI string (at `ui_string_rva`) **doesn't** look like a menu string. If every loaded title is in main-menu state, no spoof needed.
2. **Read the host XUID** from MCC's session chain.
3. **Check player state** (if the title requires one). State pointer must be valid (`>= 0x10000 && <= 0x7FFFFFFEFFFF`). Match-ended flag at `state_flag_offset`: if nonzero, don't spoof.
4. **Read the local XUID** from the title DLL. If it already equals host XUID, no-op (don't re-patch).
5. **Apply spoof:**
   - NOP the "first" validation site (before the write).
   - Write host XUID at each of the `write_rvas` (1 or 2 locations).
   - NOP all the "post" validation sites.

### The menu check

```cpp
bool LooksLikeMenu(const char* ui) {
    if (ui == nullptr || ui[0] == 0) return true;
    if (ui[0] == '?' && ui[1] == '?' && ui[2] == 0) return true;
    if (strncmp(ui, "Unknown", 7) == 0) return true;
    if (strstr(ui, "main_menu") != nullptr) return true;
    if (strstr(ui, "mp_mainmenu") != nullptr) return true;
    if (strstr(ui, "Main Menu") != nullptr) return true;
    return false;
}
```

Reads the UI-state string at `ui_string_rva`. If it's blank or looks like a menu, the game isn't in a match yet and spoofing would be premature (would get overwritten when the match loads).

---

## Backup / restore mechanism

```cpp
struct PatchRecord {
    uintptr_t address;
    std::vector<uint8_t> original;
    std::vector<uint8_t> patched;
};

std::mutex g_patch_mutex;
std::vector<PatchRecord> g_patches;
```

Every patch operation records:
- Address
- Original bytes
- Patched bytes

### Restoration

```cpp
void RestoreAllLocked() {
    for (auto it = g_patches.rbegin(); it != g_patches.rend(); ++it) {
        if (!IsRangeCommitted(it->address, it->patched.size()))
            continue;
        std::vector<uint8_t> current(it->patched.size());
        memcpy(current.data(), reinterpret_cast<const void*>(it->address), current.size());
        if (current != it->patched)
            continue;   // something else already patched it, don't touch
        // ... VirtualProtect + memcpy original + FlushInstructionCache
    }
    g_patches.clear();
}
```

Walks patches **in reverse order** (so overlapping patches restore correctly). Verifies the current bytes still match the patched state before restoring (avoids stomping on something else that modified the same address).

Called on `DLL_PROCESS_DETACH` when `reserved == nullptr` (orderly unload).

---

## The patch primitive

```cpp
bool PatchBytes(uintptr_t address, const void* data, size_t size, bool record = true) {
    if (data == nullptr || size == 0 || !IsRangeCommitted(address, size))
        return false;

    std::lock_guard lock(g_patch_mutex);

    if (record) {
        // record original bytes for future restore
    }

    DWORD old_protect = 0;
    if (VirtualProtect(reinterpret_cast<LPVOID>(address), size,
                       PAGE_EXECUTE_READWRITE, &old_protect) == FALSE)
        return false;
    memcpy(reinterpret_cast<void*>(address), data, size);
    FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), size);
    VirtualProtect(reinterpret_cast<LPVOID>(address), size, old_protect, &old_protect);
    return true;
}
```

Standard user-mode patcher:
1. `VirtualProtect` → RWX.
2. `memcpy`.
3. `FlushInstructionCache` (critical — without this, CPU caches may serve stale instructions).
4. `VirtualProtect` → original protection.

`IsRangeCommitted` guard: checks via `VirtualQuery` that both the first and last bytes of the range are in a `MEM_COMMIT` + not-`PAGE_NOACCESS` region. Prevents AV if the module's memory got decommitted between iterations.

---

## What this does NOT do

- **Does not disable EAC.** MCC doesn't use EAC's kernel-driver stack — only the EOS SDK. The equivalent patch in an EAC-protected title would face kernel-side integrity checks.
- **Does not bypass server-side correlation.** Spoofed XUIDs still look like legitimate XUIDs (they're the host's real XUID). The spoof is about making the client behave as if the local player is the host — useful for exploits like persistent host privilege or spoofed identity in P2P.
- **Does not protect the bypass DLL itself.** It's in-memory as a mapped DLL in the game process. Any EAC-style scan of game process VADs would find it (if there were such a scan).

---

## Why this works for MCC and not for Fortnite

### MCC

- Uses EOS SDK for matchmaking + player identity.
- **Does not have EAC's full kernel driver stack** for live sessions (the EAC component in MCC is lighter, user-mode only on the EOS side).
- EOS integrity validation is a user-mode function in a user-mode DLL.
- Can be NOPed with a `ret` from another user-mode DLL in the same process.

### Fortnite

- Uses EAC's **full kernel-driver stack** (`EasyAntiCheat.sys` / `EasyAntiCheat_EOS.sys`).
- The handle-strip ObCallback prevents `OpenProcess` with memory-access rights from getting a useful handle (see [02 — kernel driver](../02-kernel-driver.md) Part N — ObRegisterCallbacks handle strip). So an **external** injector can't write to Fortnite's memory.
- Fortnite's EAC init callback produces an Ed25519 signature that the shipping exe verifies ([13 — EAC emulation](../13-eac-emulation.md)). NOPing a validation function gets you a "success" but no valid signature → game refuses to continue.

The MCC approach is specific to EAC-less-via-EOS-only architectures.

---

## Injector (`src/injector/Program.cs`)

C# user-mode manual-map injector. Standard pattern:

1. Find MCC process.
2. Open process handle with `PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE`.
3. Allocate memory in target.
4. Write `mcc_eos_bypass.dll` path.
5. `CreateRemoteThread` → `LoadLibraryA`.

Not sophisticated — works for MCC because MCC doesn't have EAC's handle-strip protection. For an EAC-protected process this injector would fail immediately on step 2.

---

## What this reveals about EOS SDK integrity checks

- The EOS SDK has a function at `0x3AD910` (in this build) that validates something. **Short-circuiting with `ret;` is accepted upstream**, meaning the check's result isn't verified by a downstream crypto-signature check — if it returns, "success" is assumed.
- This is the **simplest** EOS integrity model. Fortnite's current-build EAC does **not** work this way — it expects a cryptographic signature on the init callback result, which you can't fake by just returning early.
- Different EOS-integrated games have different integrity-check architectures. Games that use EOS without EAC's kernel driver (like MCC) are easier. Games that use EAC's full stack (like Fortnite) require Ed25519 signatures the attacker can't produce.

---

## Fortnite relevance

**Direct bypass: no.** The architecture doesn't translate.

**Indirect learning:**

- The pattern of **"find the EOS/EAC init callback, short-circuit with a `ret`"** is well-documented and well-understood. Current Fortnite builds specifically defend against this by cryptographic signature verification.
- The RVA-driven per-title table approach shows how in-process bypasses are built per-game (per-DLL, per-version). Every build change breaks these.
- Backup/restore with per-patch bookkeeping is clean engineering. Worth adopting for any in-process patcher.

---

**Back to:** [Analysis index](00-index.md)
