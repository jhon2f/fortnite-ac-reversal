# 11 — HWID checks, kernel spoofers, the spoof surface

Covers **every HWID source EAC reads**, the mechanism by which each source is actually read on Windows, how kernel-level spoofers alter each source, the kernel hazards (PatchGuard / HVCI / ETW-TI / WDAC) that constrain spoofers, and the full spoofer architecture requirements.

Consolidates everything about machine-identity attack surface into one reference.

---

## Part 1 — Live-queried machine identifiers (the HWID / fingerprint set)

Fields EAC reads and reports to the backend as hardware fingerprint. Backend stores a hash per session. HWID ban blacklists that hash.

### 1.1 — CPU identifiers

**Via CPUID (user-mode accessible, no kernel required):**

| Leaf | Field |
|-|-|
| `0x00` | Vendor string (GenuineIntel / AuthenticAMD / HygonGenuine / CentaurHauls / etc.) + max leaf |
| `0x01` | Family / Model / Stepping (EAX), brand / APIC ID / core count (EBX), feature flags (ECX + EDX) |
| `0x02` | Cache + TLB descriptors (Intel legacy) |
| `0x03` | **Processor Serial Number** — deprecated on P4+, still probed by EAC |
| `0x04` | Cache topology (deterministic cache parameters) |
| `0x05` | MONITOR/MWAIT info |
| `0x06` | Thermal and power management features |
| `0x07` | Structured extended feature flags (sub-leaves 0, 1, 2) |
| `0x09` | Direct Cache Access (DCA) |
| `0x0A` | Architectural Performance Monitoring |
| `0x0B` | Extended topology (SMT, core, package) |
| `0x0D` | XSAVE features + state components |
| `0x0F` | Resource Director Technology (RDT) monitoring |
| `0x10` | RDT allocation |
| `0x12` | SGX capabilities |
| `0x14` | Processor Trace enumeration |
| `0x15` | **TSC and core crystal clock info** |
| `0x16` | Processor frequency info (Base, Max, Bus) — must be nonzero on real hardware |
| `0x17` | SoC Vendor attributes |
| `0x18` | Virtual Address Translation parameters |
| `0x19` | Key Locker info (Intel KL) |
| `0x1A` | Hybrid information (P-core vs E-core on 12th gen Intel+) |
| `0x1B` | PCONFIG target identification |
| `0x1C` | Last Branch Records (LBR) |
| `0x1D` / `0x1E` | AMX (Advanced Matrix Extensions) tile / TMUL info |
| `0x1F` | V2 extended topology |
| `0x20` | HRESET features |
| `0x21` | Reserved / AMX-reserved |
| `0x40000000` | **Hypervisor-present leaf** — brand string if HV present |
| `0x40000001..0x4000000A` | Hyper-V TLFS leaves if Hyper-V is HV |
| `0x80000000` | Max extended leaf |
| `0x80000001` | Extended features (LAHF, SVM, LM, etc.) |
| `0x80000002..0x80000004` | Brand string ("Intel(R) Core(TM)...") — 48 chars |
| `0x80000005` | L1 cache + TLB |
| `0x80000006` | L2 + L3 cache |
| `0x80000008` | Virtual + physical address sizes |
| `0x8000000A` | SVM (AMD virtualization) features |
| `0x8000001D` | Cache properties |
| `0x8000001E` | Extended APIC + topology |
| `0x8000001F` | SEV + SME features (AMD confidential compute) |
| `0x80000021` | Extended feature identification (AMD) |

**Via MSR reads (kernel-mode only):**

| MSR | Address | What |
|-|-|-|
| `IA32_PLATFORM_ID` | `0x17` | Platform ID for microcode binding |
| `IA32_APIC_BASE` | `0x1B` | APIC base + enable + BSP flag |
| `IA32_FEATURE_CONTROL` | `0x3A` | VMX enable, SGX enable, etc. |
| `IA32_TSC_ADJUST` | `0x3B` | TSC adjustment value (per-core) |
| `IA32_SPEC_CTRL` | `0x48` | Speculation control |
| `IA32_PRED_CMD` | `0x49` | Branch prediction barrier |
| `IA32_BIOS_UPDT_TRIG` | `0x79` | Microcode update |
| `IA32_BIOS_SIGN_ID` / `IA32_UCODE_REV` | `0x8B` | **Microcode revision** |
| `IA32_PLATFORM_INFO` | `0xCE` | Platform-specific info |
| `IA32_PERFEVTSEL0..7` | `0x186+` | Performance counter config |
| `IA32_PERFCTR0..7` | `0xC1+` | Performance counter values |
| `IA32_MTRRCAP` | `0xFE` | MTRR capabilities |
| `IA32_SYSENTER_CS/ESP/EIP` | `0x174..0x176` | SYSENTER state |
| `IA32_DEBUGCTL` | `0x1D9` | Debug control (LBR, BTS) |
| `IA32_MTRR_PHYSBASE0..N` | `0x200+` | Memory Type Range Registers |
| `IA32_PAT` | `0x277` | Page Attribute Table |
| `IA32_EFER` | `0xC0000080` | Extended Feature Enable Register |
| `IA32_STAR/LSTAR/CSTAR/FMASK` | `0xC0000081..84` | Syscall state (PatchGuard protects) |
| `IA32_FS_BASE` / `GS_BASE` / `KERNEL_GS_BASE` | `0xC0000100..102` | Thread-local base registers |

### 1.2 — SMBIOS (all tables)

Accessed via `NtQuerySystemInformation(SystemFirmwareTableInformation, 'RSMB')`, WMI `Win32_*`, or `GetSystemFirmwareTable`. **Includes history** — driver remembers values across sessions.

| Type | Table | Key fields |
|-|-|-|
| 0 | BIOS | Vendor, Version, Release Date, BIOS Characteristics, Embedded Controller firmware version |
| 1 | System | Manufacturer, Product, Version, **Serial Number**, **UUID**, WakeUp Type, SKU, Family |
| 2 | Baseboard | Manufacturer, Product, Version, **Serial Number**, Asset Tag, Features, Chassis Handle |
| 3 | Chassis | Manufacturer, Type, Version, **Serial Number**, Asset Tag, Boot-up State, Power Supply State, Thermal State, Security Status, OEM Info |
| 4 | Processor (per CPU) | Socket, Manufacturer, Version, Voltage, External Clock, Max Speed, Current Speed, Status, **Processor ID**, Serial Number, Asset Tag, Part Number |
| 7 | Cache (per cache) | Socket Designation, Configuration, Max Size, Installed Size, Speed, Error Correction Type |
| 9 | System Slots | Slot Designation, Type, Data Bus Width, Current Usage, Length, Slot ID |
| 11 | OEM Strings | Free-form OEM strings (often contain Windows OEM activation keys, vendor info) |
| 12 | System Configuration Options | Configuration strings |
| 13 | BIOS Language Info | Installable languages, current language |
| 16 | Physical Memory Array | Location, Use, Error Correction, Max Capacity, Number of Devices |
| 17 | Memory Device (per DIMM) | Total Width, Data Width, Size, Form Factor, Locator, Bank Locator, Type, Type Detail, Speed, Manufacturer, **Serial Number**, Asset Tag, Part Number, Rank |
| 19 | Memory Array Mapped Address | Starting Address, Ending Address, Memory Array Handle |
| 20 | Memory Device Mapped Address | Starting Address, Ending Address, Memory Device Handle |
| 32 | System Boot Info | Boot Status |
| 38 | IPMI Device Info | IPMI version, I2C target address |
| 39 | Power Supply (per supply) | Manufacturer, Serial Number, Asset Tag, Model, Revision |
| 41 | Onboard Devices Extended Info | Reference Designation, Device Type, Device Status, Bus/Device/Function Number |

### 1.3 — Storage devices

| Field | Access path |
|-|-|
| Physical disk serial, model, firmware | `IOCTL_STORAGE_QUERY_PROPERTY` → `StorageDeviceProperty` |
| Disk adapter info | `IOCTL_STORAGE_QUERY_PROPERTY` → `StorageAdapterProperty` |
| NVMe EUI64 + NGUID | NVMe Identify Controller via `IOCTL_STORAGE_PROTOCOL_COMMAND` |
| NVMe namespace ID | per-namespace identifier |
| NVMe controller ID (CNTLID) | Identify Controller response |
| NVMe subsystem NQN | NVMe Subsystem Qualified Name |
| SATA controller device ID | PCI config space of the storage controller |
| **SCSI LUN** | per [02 driver](02-kernel-driver.md) — formatter string `":lun=%llx"` |
| **MBR disk signature** | Dword at offset `0x1B8` of MBR — formatter `"MBR:%08x"` |
| **Partition index** | formatter `"Part:%u"` |
| **Optical drive index** | formatter `"CD:%u"` |
| Volume serial (NTFS) | 32-bit, boot sector |
| Volume serial (FAT) | 32-bit, VBR |
| $MFT entry 0 creation time | Volume creation timestamp, forensically stable |
| EFI System Partition GUID | GPT, stable per install |
| GPT Disk GUID | GPT header, per-disk unique |
| GPT Partition GUIDs | per-partition, stable |
| S.M.A.R.T attribute values | Power-on hours, reallocated sector count |
| BitLocker volume ID (if encrypted) | per-volume FVE ID |

### 1.4 — Network

| Field | Source |
|-|-|
| **Permanent MAC per adapter** | `OID_802_3_PERMANENT_ADDRESS` via NDIS (NOT `CURRENT_ADDRESS` — EAC reads the burned-in one) |
| Current MAC | `OID_802_3_CURRENT_ADDRESS` |
| Interface GUID | `HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-...}\<guid>` |
| Driver DeviceInstanceID | `PCI\VEN_XXXX&DEV_XXXX&SUBSYS_XXXX&REV_XX\<instance>` |
| IPv6 interface identifier (SLAAC) | EUI-64 derived from MAC |
| IPv6 temporary addresses | RFC 4941, randomized |
| Configured DNS servers | per-interface |
| DHCP client identifier | `DhcpIdentifier` registry value |
| WAN public IP | External HTTPS probe or routing table |
| ARP cache entries | gateway MAC + neighbor list |
| **Wi-Fi SSID history** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\` + `Signatures\Unmanaged\` |
| Wi-Fi BSSID during session | wlanapi |
| **Bluetooth adapter address** | `HKLM\SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\LocalServices` |
| Bluetooth paired device list | Same registry hive |
| **TLS JA3/JA4 fingerprint** | Backend observes passively |
| TCP MSS, window size, timestamp option | OS fingerprint passive |
| NDI telemetry provider | ETW |

### 1.5 — Display / graphics

| Field | Source |
|-|-|
| GPU adapter LUID | `IDXGIAdapter::GetDesc1` |
| GPU device description | Same |
| GPU vendor/device/subsystem/revision | PCI config space + `HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_*\DEV_*` |
| **GPU vBIOS version** | **NVAPI / `NvAPI_GPU_GetVbiosVersionString`** (confirmed collected by EAC — lukiuz0x thread 778933) |
| GPU VRAM size | Dedicated/shared video memory |
| WDDM version | `DXGI_GPU_PREFERENCE` |
| D3D feature level | Highest supported FL |
| NVIDIA GPU UUID | NVAPI `NvAPI_GPU_GetGPUInfo` or NVML `nvmlDeviceGetUUID` |
| NVIDIA PCI bus address | NVAPI |
| NVIDIA driver version | registry + NVAPI |
| NVIDIA ReBAR state | NVAPI |
| AMD GPU UUID | ADLX |
| Intel GPU UUID | IGCL |
| **Monitor EDID** (per monitor) | `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\*\Device Parameters\EDID` |
| EDID parsed fields | Manufacturer ID (PNP), Product code, Serial number, Mfg year/week, Preferred timing (DTD) |
| EDID extensions (CEA) | Audio formats, HDMI vendor-specific data block |
| DisplayPort DPCD | AUX channel, OUI, device IDs |

### 1.6 — USB / HID

| Field | Source |
|-|-|
| USB device VID/PID/revision | PnP enum path |
| USB device serial number | USB string descriptor |
| USB class/subclass/protocol | USB device descriptor |
| Container ID GUID | `HKLM\SYSTEM\CurrentControlSet\Enum\USB\*\*\Properties\{...}\0008` |
| Hub location path | PnP device instance path `USB\ROOT_HUB...` |
| **USB connection history** | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` + `USB\VID_*` — forensic |
| HID top-level collection usage | HID report descriptor |
| HID report descriptor hash | For mouse/keyboard identifies the device |
| Mouse polling rate (measured) | Input event timing |
| Keyboard layout ID | `HKEY_CURRENT_USER\Keyboard Layout` |

### 1.7 — Audio

| Field | Source |
|-|-|
| Audio endpoint device IDs (GUIDs) | `IMMDeviceEnumerator::EnumAudioEndpoints` |
| Primary playback endpoint | `GetDefaultAudioEndpoint(eRender, eConsole)` |
| Primary capture endpoint | `GetDefaultAudioEndpoint(eCapture, eConsole)` |
| Endpoint friendly names | device property store |
| Audio session GUIDs | per-app audio sessions |

### 1.8 — Firmware / boot

| Field | Source |
|-|-|
| UEFI firmware vendor + version | `GetFirmwareEnvironmentVariable` |
| **Secure Boot state** | `BOOT_OPTIONS` + UEFI var `SecureBoot` |
| **Secure Boot DB / DBX / KEK / PK hashes** | UEFI vars, TPM-measured |
| Boot Configuration Data (BCD) GUIDs | `HKLM\BCD00000000` mount (or disk BCD file) |
| BootCurrent / BootNext / BootOrder | UEFI vars |
| **Boot GUID** | **EFI var — collected by EAC per lukiuz0x thread 778933** |
| **Boot ID** | **EFI var — collected by EAC per lukiuz0x thread 778933** |
| **Partition GUIDs** | **GPT — collected (alexanderyy thread 778933)** |
| HVCI state | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity` |
| VBS state | `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity` |
| DMA Protection (Kernel DMA) | Policy registry + ACPI DMAR table |
| IOMMU (VT-d / AMD-Vi) state | ACPI DMAR/IVRS table parsing |
| **WBCL** (Measured Boot) | `C:\Windows\Logs\MeasuredBoot\` per-boot `.log` files |
| **ACPI tables (all)** | `NtQuerySystemInformation(SystemFirmwareTableInformation, 'ACPI')` |
| ACPI OEM ID + OEM Table ID | All tables have these — fingerprint of firmware |
| Firmware mode (UEFI vs Legacy) | `GetFirmwareType` API |
| TPM version (1.2 / 2.0) | TBS `Tbsi_GetDeviceInfo` |
| TPM manufacturer | TBS |
| **TPM Endorsement Key public** | TPM2_ReadPublic for EK handle |
| EK certificate | `TpmRetrieveEkCertificate` |
| TPM PCR values (per bank: SHA1, SHA256) | TPM2_PCR_Read |
| AIK (Attestation Identity Key) | Per-platform, OS-provisioned |
| TPM quote on PCRs | Bound to EAC session via `EacQuoteKey` |

### 1.9 — RAM

| Field | Source |
|-|-|
| RAM module serials (per-DIMM) | SMBIOS type 17 |
| **SPD (Serial Presence Detect) raw data** | SMBus (via `\Driver\smbctrl` / `\Driver\i801`) — `RamSpdSerials` field |
| XMP profile ID (if enabled) | SPD extension blocks |
| Memory channel configuration | SMBIOS |
| ECC vs non-ECC | SMBIOS + chipset |

### 1.10 — Windows identity

| Field | Registry path / Source |
|-|-|
| `MachineGuid` | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| `MachineSid` | `HKLM\SECURITY\SAM\Domains\Account\F` (requires SYSTEM) |
| `SqmClient\MachineId` | `HKLM\SOFTWARE\Microsoft\SQMClient\MachineId` |
| Windows **InstallDate** | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallDate` — **32-bit Unix epoch** (seconds since 1970) |
| Windows **InstallTime** | Same key, `InstallTime` — **64-bit FILETIME QWORD** (100 ns ticks since 1601). **Both values must be kept consistent**: a spoofer that writes only `InstallDate` leaves `InstallTime` pointing at the real install moment, and EAC's env_worker compares them. |
| `ProductId` | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId` |
| `DigitalProductId` | Same key — 4 bytes of install ID, per-install unique |
| Edition ID | Same key, `EditionID` |
| Product Name | Same key, `ProductName` |
| CurrentBuild / UBR | Same key |
| DisplayVersion / ReleaseId | Same key — "22H2" / "24H2" etc. |
| Current user SID | Current token |
| User profile path | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath` |

### 1.11 — PCI device enumeration

For every PCI device, EAC's `Devi` module can extract:

| Field |
|-|
| Vendor ID / Device ID |
| Subsystem Vendor ID / Subsystem Device ID |
| Revision ID |
| Class / Subclass / Programming Interface |
| Capabilities list (walk linked list at config offset 0x34) |
| PCIe capability — Device/Link/Slot caps + control + status |
| MSI/MSI-X state |
| Bus/Device/Function (BDF) — topology |
| Secondary bus number (bridges) |
| BAR values (Base Address Registers) |
| Interrupt line + pin |
| **PnP instance path** — `PCI\VEN_10DE&DEV_2504&SUBSYS_41501458&REV_A1\4&3C24B4C&0&0008` |
| ACS (Access Control Services) capability |
| ATS (Address Translation Services) state |

---

## Part 2 — Per-field spoofer mechanics

### 2.1 — SMBIOS

**How Windows exposes SMBIOS:**

```
(a) user-mode via WMI:
      Win32_BIOS                → BIOS info (type 0)
      Win32_ComputerSystemProduct → system info (type 1)
      Win32_BaseBoard           → baseboard (type 2)
      Win32_SystemEnclosure     → chassis (type 3)

(b) user-mode via GetSystemFirmwareTable:
      GetSystemFirmwareTable('RSMB', 0, buffer, size)

(c) kernel-mode via NtQuerySystemInformation:
      NtQuerySystemInformation(SystemFirmwareTableInformation,
                               request, requestSize, &returned)
```

A spoofer that wants to change what EAC sees has to patch **all three paths**. The real work is at the kernel path — user-mode paths funnel through kernel-side firmware-table retrieval.

**Kernel-side work** involves intercepting `ExpQuerySystemFirmwareTable`. Two approaches:

1. **Hook `ExpQuerySystemFirmwareTable` directly.** Painful because PatchGuard protects ntoskrnl `.text`.
2. **Patch the SMBIOS table itself in physical memory** — more durable. Map it via `MmMapIoSpace` and overwrite the string fields.

**The caching problem:** Windows caches the SMBIOS table at boot. A proper spoofer alters the cached copy inside ntoskrnl's data section too.

**The drift-detector problem:** EAC's `env_worker` runs environment-consistency checks every 30s. Re-reads SMBIOS vs session-init snapshot. Lazy spoofers get caught.

**ACPI table spoof-weight table** — covers **every ACPI table the shipped `spoof.sys` actually patches** (34 tables; verified against the driver's verbatim string block in Part 4). Builders that only patch the top ~17 leave the rest fingerprinting the host:

| Table | What it is | Spoof weight |
|-|-|-|
| `DSDT` | Differentiated System Description Table — motherboard device tree | **High** |
| `SSDT` | Secondary SDT — supplemental devices | Medium |
| `FACP` / `FADT` | Fixed ACPI Description Table | Low |
| `APIC` / `MADT` | Multiple APIC Description Table — CPU/core layout | Medium |
| `DMAR` | DMA Remapping | **High** |
| `IVRS` | I/O Virtualization Reporting Structure (AMD) | **High** |
| `HPET` | High Precision Event Timer | Low |
| `WAET` | Windows ACPI Emulated devices Table | Low |
| `MCFG` | Memory-mapped Config space | Medium |
| `BGRT` | Boot Graphics Resource Table — OEM boot logo | **Fingerprint** |
| `TPM2` | TPM 2.0 device description | **High** |
| `TCPA` | TPM 1.2 device description (legacy) | Medium |
| `SLIC` | Software Licensing table | **Fingerprint** — OEM Windows license binding |
| `MSDM` | OEM Activation 2.0 — contains OEM product key | **Fingerprint** |
| `SRAT` | System Resource Affinity Table — NUMA | Medium |
| `OEM1..4` | Vendor-specific | **Fingerprint** |
| `SLIT` | System Locality Information Table — NUMA inter-node distances | Medium |
| `BERT` | Boot Error Record Table — pre-boot error log | Low |
| `HEST` | Hardware Error Source Table — RAS source descriptors | Low |
| `ERST` | Error Record Serialization Table | Low |
| `FPDT` | Firmware Performance Data Table — boot timing history | **Fingerprint** — timing history is per-host |
| `NHLT` | Non-HD-Audio Link Table — DSP / soundwire / audio-codec topology | Medium |
| `XSDT` | Extended System Description Table — 64-bit root of ACPI tables | **High** — must stay consistent with patched children |
| `RSDT` | Root System Description Table — 32-bit legacy root | **High** — same consistency requirement as XSDT |
| `DBG2` | Debug Port Table 2 — serial/USB debug endpoints | Low |
| `DBGP` | Debug Port Table (legacy) | Low |
| `WSMT` | Windows SMM Security Mitigations Table — SMM capability flags | Medium |
| `IORT` | IO Remapping Table (ARM; occasionally present on hybrid boards) | Low |
| `LPIT` | Low Power Idle Table — C-state residency structure | Medium |

Tables above the horizontal section in the real `spoof.sys` are the "classic ~17" most builders cover. Everything from `SLIT` down is what the shipping spoofer additionally patches — leaving any of these intact lets EAC's ACPI-OEM-ID walk still fingerprint the host firmware.

**Anomaly-list hazard:** Rules.bin section `0x70` (SMBIOS anomaly list) blocks known filler strings:
- `"To be filled by O.E.M."`
- `"Default string"`
- `"System Manufacturer"`
- Known public OEM strings reused by spoofers

Section `0x71` (firmware version block list) blocks known fake BIOS versions.

### 2.2 — Disk serials — **direct cache-bypassing IOCTLs**

**Important detail from alexanderyy (thread 778933):**

> disks (with direct ioctl's that don't use cache too)

EAC uses **direct IOCTLs that bypass the Windows storage cache** when reading disk identifiers. Significance:

- Common disk-serial spoofers rely on caching: respond once with the fake value, let it get cached, Windows serves the cached response to subsequent queries.
- **EAC defeats this by issuing cache-bypassing IOCTLs.** Every query goes to the storage stack for a fresh read. The spoofer's one-time response gets overwritten by the real disk's response on EAC's next read.
- To beat this, the spoofer has to intercept **every single read**, not just the cached first one. Storage-stack filter driver that intercepts **all** IOCTLs in both directions.

**Physical disk serial** via `IOCTL_STORAGE_QUERY_PROPERTY`:

The IOCTL is handled by `\Driver\disk` → `\Driver\storport` → the SCSI/NVMe miniport. A spoofer either hooks `disk.sys`'s dispatcher (more PatchGuard-flaggable) or — more durably — registers a filter driver above `disk.sys`.

**Must filter every IOCTL, not just the first cached one.** Lazy spoofers that trust Windows's caching lose this battle.

**NVMe-specific identifiers** via `IOCTL_STORAGE_PROTOCOL_COMMAND`:
- NVMe `identify-controller` returns `EUI64` (8 bytes) and `NGUID` (16 bytes).
- Hardware-rooted. Spoof via the same filter approach.

**Per-volume serial** (NTFS):
- Stored in NTFS boot sector.
- Spoofing requires altering boot sector (conflicts with Secure Boot + BitLocker detection) OR hooking user-mode API chain.

**Spoofer considerations:**
1. Disk serials are read at various times by various code paths. The spoofer has to filter every path.
2. Filter driver above `disk.sys` is the clean approach.
3. Current-build EAC compares disk serial via both the user-mode IOCTL path and a WMI query. A spoofer that only hooks one shows drift.

### 2.3 — MAC addresses — **FOUR collection paths (critical update)**

Per **alexanderyy** (UC legend, trust 78 — thread 778933):

> Permanent MAC is collected 4 different places, common ndis way, then own entry from arp table, ExAllocateUUID and PCIE Config Space DSN (unspoofable without hypervisor)

(**Spelling correction:** `ExAllocateUUID` is not a real `ntoskrnl` export. The actual kernel APIs are `ExUuidCreate` (single UUID, modern name) and `ExAllocateUuids` (batch of UUIDs, plural lowercase). alexanderyy's shorthand covers both; EAC reads whichever the current build calls. A hook written against the literal spelling `ExAllocateUUID` resolves to nothing.)

Four collection paths EAC uses for permanent-MAC fingerprinting:

| # | Path | Spoofable via |
|-|-|-|
| 1 | **`OID_802_3_PERMANENT_ADDRESS` via NDIS** | NDIS filter driver (standard approach) |
| 2 | **ARP table own-entry** | Hook ARP table API or filter at NDIS |
| 3 | **`ExUuidCreate` / `ExAllocateUuids`** — v1 UUID generation historically embeds the first NIC's MAC into the node field of generated UUIDs | Hook `ExUuidCreate` (single) and/or `ExAllocateUuids` (batch) and rewrite the trailing 6 bytes of each output UUID. EAC reads whichever variant the current build calls, so a complete spoofer hooks both. |
| 4 | **PCIe Config Space DSN** (Device Serial Number capability) | **UNSPOOFABLE without hypervisor** |

#### The PCIe Config Space DSN path — the hardest one

The PCIe Device Serial Number is an extended capability (`capability ID 0x03`) on PCIe devices that includes the EUI-64, which embeds the device's MAC for NICs. Reading via PCI config space (`setupapi` → `IoGetDeviceProperty` → read config space directly from the HAL).

**Why it's unspoofable without a hypervisor:** Reads go directly to the PCIe root complex / IOMMU translation. There's no kernel-callable hook point between the config-read instruction and the hardware response. A hypervisor can intercept PCIe config-space reads at the VM-exit level; a kernel driver cannot.

#### Operational implication

A spoofer that only hooks the NDIS path leaves three other collection paths exposed. **A complete MAC spoofer requires:**
1. NDIS filter for path 1.
2. ARP-table interception for path 2.
3. `ExUuidCreate` **and** `ExAllocateUuids` hooks for path 3 (both; the correct kernel exports — `ExAllocateUUID` is not a real symbol).
4. **Hypervisor for path 4** — or accept the PCIe DSN contribution to your HWID hash and hope the backend tolerates drift.

Most commercial HWID spoofers only hit path 1 (and maybe 2). This is why "I spoofed my MAC but still get HWID banned" is a common experience — the other three paths still reveal the real MAC.

**MAC prefix hazard still applies:** If your fake permanent MAC uses a prefix not matching any registered OUI, EAC flags. The anomaly list blocks known fake prefixes. A spoofer generates MACs with real-OUI prefixes. And now all 4 paths need to agree on the fake value.

### 2.4 — CPU identifiers

CPUID is a CPU instruction. The kernel can intercept it via VT-x / AMD-V by causing vmexits — but that's a **hypervisor-level** spoofer, not a driver one. **On bare metal, CPUID returns what the silicon returns. You cannot spoof CPUID via a kernel driver.**

**Spoofer options:**

| Option | Trade-off |
|-|-|
| Run under a hypervisor that intercepts CPUID | EAC detects hypervisors → triggers anti-VM flags |
| Hook the user-mode agent's CPUID wrapper | Fragile; EAC's agent has multiple CPUID call sites |
| Hook ntoskrnl's CPUID helpers | Same risk; PatchGuard-adjacent |

**Bottom line:** CPUID spoofing on bare metal requires hypervisor-level control.

### 2.5 — GPU and DXGI adapter

**GPU LUID** — 64-bit identifier assigned by Windows. Stable per boot per adapter, regenerates on driver reinstall or major Windows updates.

**Spoofing:**
- Hook `IDXGIAdapter::GetDesc1` at user-mode inside the agent.
- Or more durably at `dxgi.dll` system-wide. **But** EAC's integrity timer hashes `dxgi.dll`'s `.text`, so inline-patching in memory is caught.
- Need API-hook approach that doesn't modify `.text` — EAT/IAT hooking (own detection surface) or `PAGE_EXECUTE_WRITECOPY` CoW tricks.

**Vendor-specific UUIDs** read via NVAPI/ADLX/IGCL. Per-vendor hook work.

**PCI subsystem/vendor/device IDs** — spoofable at registry layer **but** the driver still knows the real IDs via PCI config-space reads. EAC's driver can enumerate PCI config space directly. **Pure-registry spoofing is caught by driver-side cross-check.**

### 2.6 — Monitor EDID

Stored in registry: `HKLM\SYSTEM\CurrentControlSet\Enum\DISPLAY\*\*\Device Parameters\EDID`.

**Spoofing:** Write the altered EDID into the registry key. Also need to intercept any code path that reads EDID directly from the display (bypassing the registry cache) — filter driver on the display stack can intercept.

### 2.7 — TPM endorsement key

Current-build EAC queries TPM EK via TBS (TPM Base Services) APIs. EK public is the strongest-stable hardware identifier.

#### Nuance per alexanderyy (UC thread 778933)

> TPM is collected but i don't think it is used.

alexanderyy's observation of Fortnite EAC: TPM EK values **are collected** but may **not be used in the ban-hash itself**. The collection might be for separate behavioral correlation or future-use, not current HWID-ban binding.

This is uncertain. Treat as: **collect TPM anyway**, assume it matters, but recognize that current-build enforcement may primarily use SMBIOS + disk serials + MAC + machine GUID rather than TPM EK.

#### How EAC actually validates TPM attestation (per flow1777, thread 781177)

> EAC go through tbs.sys directly or do remote attestation where the tpm signs a nonce with the fused EK and ms/vendor pki validates it server side, your hook never touches that signed material.

Two paths:
1. **Direct `tbs.sys` calls** — EAC's driver calls `TbsiSubmitCommand`, `TbsiGetDeviceInfo`, etc. Returns include the EK public portion.
2. **Remote attestation** — TPM signs a nonce with the fused EK, result sent to Epic's backend, MS/vendor PKI validates server-side. **Hooks don't touch this** — the signed material is produced inside the TPM.

#### Sanity check tool

**`tpmtool getdeviceinformation`** — reads TPM EK via the same path EAC uses. If a spoofer is working at the TBS level, this command shows the spoofed EK. If it shows the real EK after your spoofer is loaded, your hook isn't hitting EAC's actual read path.

#### Reference projects

Mentioned in thread 781177:
- **hitome55's "Bypassing TPM/Secureboot" thread** on UC anti-cheat-research.
- **qwnd1's pulzar-hypervisor base** — kernel/bare-metal TPM emulation starting point. qwnd1 is a UC legend who notes: *swtpm is horrible for this use case (usermode-only). Bare-metal TPM emulation needs a TPM worker thread because crypto operations are slow and synchronous responses create visible lag.*

For freestanding (kernel/pre-OS) TPM emulation: **TCG reference code** can be compiled freestanding if you supply the mandatory platform layer. Serious engineering effort (weeks).

**Why TPM is nearly impossible to spoof:**
- EK private key never leaves the TPM. You can't extract it.
- Quotes are AIK-signed, AIKs are themselves rooted in the EK.
- Even if you virtualize the TPM, the EK is different, and Epic's backend binds the session to the EK it saw on signup.

**Spoofing options:**

| Approach | Trade-off |
|-|-|
| Virtualized TPM (fTPM / dTPM emulation in a hypervisor) | EAC detects hypervisors → triggers anti-VM flags |
| Clearing the physical TPM (changes EK) | **One-shot** — destroys your BitLocker keys among other things |
| Hook TBS at user-mode or driver level to return altered EK public | Fragile; EAC's env_worker re-reads |

**No general-purpose durable TPM EK spoofer exists** that is robust against re-read drift.

### 2.8 — PCR values

Windows measures boot into TPM PCRs. Key PCR meanings:

| PCR | What it measures |
|-|-|
| 0 | CRTM (BIOS code) |
| 1 | Platform configuration / firmware options |
| 2 | Option ROM code |
| 3 | Option ROM configuration |
| 4 | IPL (Windows Boot Manager) |
| 5 | IPL configuration |
| 6 | State transitions |
| 7 | **Secure Boot policy, DB, DBX, KEK, PK** |
| 8 | Windows OS Loader (winload.efi) |
| 9 | Windows Resume Loader |
| 10 | Windows OS Kernel |
| 11 | BitLocker access control |
| 12-15 | Reserved |
| 17-22 | Dynamic Root of Trust (TXT/SVM) |
| 23 | Application support |

**Why PCR 7 matters:** if PCR 7 changes between sessions on the same machine, Secure Boot policy / DB / KEK was touched → anomaly. **Loading unsigned drivers changes measured boot → PCR drift → EAC sees inconsistent attestation.**

### 2.9 — Windows identity fields

Machine GUID, ProductId, DigitalProductId, SQMClient MachineId — all registry writes. Spoofable trivially **but** EAC's env_worker re-reads at the 30s cadence. So long as the spoofer altered the registry before session start AND values remain altered, fine. Windows itself doesn't regenerate these except at reinstall/sysprep.

**User SID** — tied to the local user account. "Switch user accounts" is the non-spoof workaround.

---

## Part 3 — ETW-TI and kernel hazards

### Microsoft-Windows-Threat-Intelligence ETW provider

GUID: `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`.

Kernel ETW provider that emits events **from inside ntoskrnl** for specific suspicious operations. Normally subscribable only by Protected Process Light (PPL) subscribers — EAC's driver qualifies via its WHQL cross-signature.

**What TI reports** when a process calls these:

| Operation | Event |
|-|-|
| `NtAllocateVirtualMemory` with exec protection | Virtual-allocation event |
| `NtProtectVirtualMemory` to change protection | **ProtectVirtualMemory event** |
| `NtMapViewOfSection` with exec | Mapped-view event |
| `NtReadVirtualMemory` cross-process | Cross-process-read event |
| `NtWriteVirtualMemory` cross-process | Cross-process-write event |
| `NtSetContextThread` cross-process | Context-set event |
| `NtQueueApcThread` cross-process | APC-queue event |
| `NtCreateThreadEx` cross-process | Remote-thread event |

Each event includes **source process, target process, operation parameters, call stack**.

### Confirmed in a real shipping HWID spoofer

Analyzed `desire_market` HWID spoof driver strings include:

```
shm PATCH_PTE refused (EAC TI ProtectVm)
shm ALLOC refused (EAC TI AllocVm)
```

The spoofer uses a **shared-memory IPC** (`\BaseNamedObjects\EacEmuShm`) for user-mode cheat code to request kernel operations. When the driver detects that EAC's TI subscription is active, it **refuses to perform PATCH_PTE or ALLOC on behalf of user-mode**, because those would generate TI events the EAC agent relays.

**The spoofer loses capability when EAC is watching.** Real commercial spoofers either:
1. Load **before** EAC's ETW subscription registers (race at boot).
2. Use operations that don't trigger TI events (physical-memory PTE writes, direct MMIO).
3. Accept the restriction and operate in constrained ways.

### PatchGuard

Periodically verifies kernel structures. Modifications → bugcheck `CRITICAL_STRUCTURE_CORRUPTION` (0x109).

Protected:
- `ntoskrnl.exe` `.text` (inline hooks = bugcheck)
- `SSDT` (patching = bugcheck)
- `IDT` (hooking = bugcheck)
- `GDT` (modifications = bugcheck)
- Syscall MSRs `LSTAR` (rewriting = bugcheck)

**Legal alternatives for cheat / spoof drivers:**
- `PsSet*NotifyRoutine` for process/thread/image creation observation.
- `ObRegisterCallbacks` for handle-open interception.
- `CmRegisterCallback` for registry monitoring.
- `FltRegisterFilter` for filesystem filtering.
- `NdisFRegisterFilterDriver` for NDIS filtering.
- `MmGetSystemRoutineAddress` + device filter stacks for IOCTL interception.

### HVCI (Hypervisor-Protected Code Integrity)

When enabled:
- Kernel pages marked executable must have a valid Microsoft-rooted signature.
- No kernel-mode `rwx` pages.
- Driver loads outside the Microsoft signing chain are rejected by the hypervisor.

**Implications:**
- **BYOVD on HVCI-enabled system is harder.**
- `kdmapper` fails on HVCI-enabled systems unless specifically designed for HVCI bypass.
- EAC reports HVCI state. **Turning HVCI off to run a cheat is itself a soft flag.**

### DMA Protection / Kernel DMA Protection

- UEFI firmware's `DMA Protection` setting.
- Windows' `Kernel DMA Protection` policy.
- VT-d / AMD-Vi (IOMMU) state.

When enabled, **PCIe devices can only DMA into memory the OS has explicitly mapped for them.** Breaks external DMA cheats.

EAC reports DMA Protection state. Systems with it off while a DMA cheat is active is a correlation data point.

### WDAC — vulnerable driver block list

Updated by Windows Update quarterly. EAC's `DRIVER_LIST` IOCTL returns each loaded driver's WDAC-match state.

**Cross-reference:** the authoritative BYOVD catalog EAC enforces against is maintained in [docs/12 Part 1](12-cheat-detection.md). The list below is the WDAC-blocklist subset observed in this driver's string table; `GPC-U64.sys` appears in this WDAC list but was historically omitted from doc 12's catalog — treat both files as needing to agree, and if you add/remove a driver here, mirror it there.

Known block-listed vulnerable drivers:

```
RTCore64.sys       (MSI Afterburner — arbitrary MSR R/W)
GPC-U64.sys        (GPC — physical memory R/W)
ATSZIO64.sys       (ATSZ — arbitrary MSR + I/O)
GDRV.sys           (Gigabyte — arbitrary I/O port)
DBUTIL_2_3.sys     (Dell — arbitrary MSR R/W)
WDLoadNTDriver.sys / WinRing0*.sys (arbitrary MSR)
AsIO.sys / AsIO2.sys / AsIO3.sys (ASUS — arbitrary I/O port + MSR)
EneIo.sys          (ENE — physical memory read)
NalDrv.sys         (Intel Nahimic — arbitrary MSR)
AMDRyzenMasterDriver.sys  (MSR + memory primitives)
cpuz141.sys / cpuz149.sys  (MSR + physical memory)
GLCKIO2.sys        (GIGABYTE)
HwRwDrv.sys / HpqKbFiltr.sys  (various HP)
rzpnk.sys          (Razer Synapse — CVE-2022-27235-ish)
piddrv.sys / piddrv64.sys
```

**EAC flags on WDAC-match regardless of whether the signature is still valid.**

### WDAC bypass history

Even with WDAC blocklist, bypasses demonstrated:
- **Allowed-list rename** — rename vulnerable driver image to Microsoft-signed name. Fails hash-based WDAC, succeeds if WDAC is name-only.
- **Signature stripping + re-signing** — change driver's hash. WDAC catches hash so new-hash works.
- **Driver hooking of WDAC enforcement** — using BYOVD to disable WDAC itself.
- **Boot-time load before WDAC policy applies** — rare on specific configs.

---

## Part 4 — The desire_market spoof.sys deep dive

Full breakdown of the `spoof.sys` HWID spoof driver's capabilities from string analysis.

### Spoofed Windows identity

- `MachineGuid`
- `MachineSid`
- `SqmMachineId`

### Spoofed SMBIOS

- `SmbiosBiosSerial`
- `SmbiosBoardSerial`
- `SmbiosChassisSerial`
- `SmbiosChassisAssetTag`
- `SmbiosSystemSerial`
- `SmbiosSystemUuid`
- `SmbiosProcessorId`
- `SmbiosProcessorName`

### Spoofed storage

- `DiskSerials`
- `DiskModelPrimary`
- `VolumeSerials`
- `RamSpdSerials`

### Spoofed network

- `NicMacAddresses`
- `MACAddress`

### Spoofed audio

- `AudioEndpointGuids`
- `AudioEndpointGuidPrimary`
- `AudioDeviceNames`

### Spoofed display

- `MonitorName`
- `MonitorSerial`
- `Adapters1`
- `HardwareInformation.AdapterString`

### Spoofed boot / firmware

- `BootCurrent`, `BootNext`, `BootOrder`, `BootOptionSupport`
- `SecureBoot`
- `WBCLColdboot`, `WBCLDrtmColdboot`
- `WindowsBootSession`
- `AcpiRegistryPatched`, `AcpiTablesPatched`
- `BootEfiActiveSec`

### Spoofed ACPI tables

Verbatim strings from the driver:

```
DSDT SSDT FACP APIC DMAR IVRS HPET WAET MCFG BGRT TPM2 TCPA
SLIC MSDM SRAT SLIT BERT HEST ERST FPDT NHLT XSDT RSDT
OEM1 OEM2 OEM3 OEM4 DBG2 DBGP WSMT IORT LPIT
```

### Hooked driver stack

```
\Driver\Disk
\Driver\storahci
\Driver\stornvme
\Driver\storport
\Driver\USBHUB      \Driver\USBHUB3
\Driver\BTHPORT     \Driver\BTHUSB
\Driver\hidusb
\Driver\SMBUS       \Driver\AMDSMBUS      \Driver\amd_smbus
\Driver\i801        \Driver\smbctrl
\Driver\IntelTA
\FileSystem\Ntfs    \FileSystem\refs
```

### Spoofed PCI classes

```
{4d36e967-e325-11ce-bfc1-08002be10318}   Disk drives
{4d36e968-e325-11ce-bfc1-08002be10318}   Display adapters
{4d36e96e-e325-11ce-bfc1-08002be10318}   USB controllers
{4d36e97b-e325-11ce-bfc1-08002be10318}   SCSI and RAID controllers
```

### Configuration toggles

```
EnableFsctlSpoof
EnableSmbusSpoof
EnableAudioSpoof
```

### IPC

- Shared memory object: `\BaseNamedObjects\EacEmuShm`
- Filter instance: `\Instances\XHWIDSpoofer Instance`

### Hardcoded fake values

Cached strings in the driver — fake hardware the spoofer can pretend to be:

- `Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz`
- `Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz`
- `Intel(R) Core(TM) i9-12900K CPU @ 3.20GHz`
- `NVIDIA GeForce RTX 3060 Ti`
- `NVIDIA GeForce RTX 3070 Ti`
- Various Realtek / HDAUDIO / USB audio strings

### ETW-TI awareness (the critical strings)

```
shm PATCH_PTE refused (EAC TI ProtectVm)
shm ALLOC refused (EAC TI AllocVm)
```

The driver explicitly detects EAC's TI subscription and refuses user-mode-requested operations that would trigger TI events. **State-of-the-art spoofer design.**

---

## Part 5 — Full spoofer architecture requirements

A complete HWID spoofer that beats EAC's current fingerprint surface needs all of the following capabilities. Omitting any one creates a detectable gap.

### 1. Kernel-mode presence

Achieved through one of:

**(a) A signed driver.** Unusual — signed driver attack surface is small and usually gets revoked once detected.

**(b) BYOVD (Bring Your Own Vulnerable Driver).** Load a known-vulnerable signed driver and use its arbitrary read/write primitive to map and execute the spoofer's unsigned code. Current vulnerable drivers rotate as Microsoft revokes via WDAC.

**(c) Manual mapping** via `kdmapper` or similar, using a BYOVD primitive. The mapped driver has no backing `\SystemRoot` file but still gets a VAD entry.

### 2. SMBIOS patching

Both physical memory + ntoskrnl cached copy. See 2.1.

### 3. `disk.sys` / `storport` filter

For `IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_STORAGE_PROTOCOL_COMMAND`. See 2.2.

### 4. NDIS filter or miniport filter

For `OID_802_3_PERMANENT_ADDRESS`. See 2.3.

### 5. Display stack filter OR EDID registry overwrite + hotplug interception

See 2.6.

### 6. Registry writes

For machine GUID, ProductId, DigitalProductId, SQMClient MachineId. See 2.9.

### 7. TPM strategy

Either clear the TPM, run under a hypervisor, or accept the TPM-hash contribution. See 2.7.

### 8. GPU

DXGI adapter desc hook (best-effort, not durable), vendor driver API hook (per-vendor work). See 2.5.

### 9. Anti-detection hardening

- **Don't register competing kernel callbacks** that EAC would see in `CALLBACK_DUMP`.
- **Don't leave the driver in loaded-driver lists** where EAC's `DRIVER_LIST` would return it.
- **Don't be visible in VAD scan** for the game process.
- **Re-patch on 30s cadence** to defeat EAC's env_worker drift detection — but ideally with a durable patch that doesn't need re-patching.

### 10. ETW-TI awareness

Don't trigger TI events during spoofer operation. Either operate pre-TI-subscription or use TI-silent operations (physical memory, direct MMIO).

---

## Part 6 — Spoofability hierarchy

Ranked worst-to-best spoofer target:

1. **TPM EK public hash** — near-impossible without clearing physical TPM or hypervisor virt-TPM.
2. **TPM PCR values / attestation quotes** — hypervisor virt only.
3. **SMBIOS values with history matching** — hard but doable with persistent driver.
4. **CPU identifiers (CPUID)** — hypervisor-level only; bare-metal nearly impossible.
5. **ACPI OEM IDs (DSDT, SSDT, OEM strings)** — doable with ACPI table patching at boot.
6. **Permanent MAC via NDIS** — doable with NDIS filter.
7. **Physical disk serial** — doable with storage filter driver.
8. **Volume serial (NTFS boot sector)** — doable but conflicts with Secure Boot + BitLocker.
9. **Monitor EDID** — doable via registry write + display driver filter.
10. **Machine GUID / registry identity fields** — trivial registry writes.

**Operational implication:** a spoofer handling only items 6-10 looks like a spoofer. A spoofer handling 3-10 is "commercial quality." Items 1-2 require either TPM clear (destroys BitLocker) or hypervisor (triggers anti-VM).

---

## Part 7 — KVM / VM-passthrough — a viable alternative path

**Important community finding (UC thread 781548, Nov 2026):**

EAC does **NOT** care about VM timing checks. Confirmed by adversemiller (legend tier, 60+ trust): *"there is zero reason to patch the host kernel for EAC."*

This contradicts a common assumption that kernel-level timing patches are required. For EAC specifically, **passing environmental checks is sufficient** — timing side-channel analysis is not part of EAC's anti-VM surface.

### What the community uses

Two main public paths for running Fortnite in a VM:

| Project | Author | What it is |
|-|-|-|
| **Nika-Read-Only** | ApexCV | Step-by-step QEMU/KVM Fortnite setup guide. Public. Not fully undetected. |
| **AutoVirt** | Scrut1ny | Alternative VM-setup automation. Requires more VM-config knowledge. |

Both on GitHub. Names rotate as repos get taken down.

### Pre-requisites for the Nika path

- Intel 12th gen+ or AMD Zen 4+ (per Nika guide): required for handling HVCI / EPT / NPT / LBR probing checks.
- At least 16 GB RAM.
- PC, not laptop.
- Hyper-V must be enabled on the guest (mandatory per guide).

### What has to pass checks

- al-khaser (latest).
- VM-Aware (latest + debug version).
- All checks must show "good/undetected."

### Common failure points

Per janolaim (same thread):
- Boot logo visible in VM-Aware debug → flag.
- QEMU firmware visible → flag.
- Standard NIC device description → emulate your own.

### AMD vs Intel

Per adversemiller:
- **AMD lets you do whatever you want.** Simpler VM setup.
- **Intel is a little more complex.** Different implementation needed.
- Zen 3 (AMD, pre-Zen-4) may require extra work to handle EPT/LBR probing since Nika guide mandates Zen 4+.

### The ongoing debate

Per mattdevs (legend tier): *"I highly doubt any of these kids in here are actually ud on kvm. they beat vmaware and think they are good. big anticheat have private detection routines for this."*

Per adversemiller (counter): *"there isn't really such a thing as 'private' detection methods anymore. If you make your VM look like baremetal, their methods will do nothing."*

Operational takeaway: **VM-based Fortnite with Nika/AutoVirt + properly-spoofed firmware/boot/NIC is a viable current-build path**, but not a free lunch. Correlation ML still applies.

---

## Part 8 — The arms race summarized

Three detection axes a spoofer has to stay ahead of:

| If the spoofer… | …it gets caught by |
|-|-|
| Patches once at load but doesn't sustain | `env_worker` drift detection |
| Patches durably but registers detectable kernel callbacks | `CALLBACK_DUMP` |
| Does neither but uses a vulnerable driver with a revoked signature | `DRIVER_LIST` + WDAC state |
| Operates when ETW-TI is active | TI events relayed to EAC telemetry |
| Changes SMBIOS values across sessions | SMBIOS history drift |
| Spoofs hypervisor-level CPUID | Anti-VM detection |

The operational problem for spoofers is **staying ahead of all four simultaneously.** Commercial spoofers rotate BYOVDs on a cadence matching Microsoft's revocation pace; open-source spoofers lag and get caught faster.

---

## Part 9 — Weight summary (which fields matter most)

Each field is hashed into contributions to the backend fingerprint. Weighting (reconstructed from observed behavior — exact weights are Epic's secret):

- **Heaviest:** motherboard UUID, TPM EK, disk serials, permanent MAC, machine GUID.
- **Moderate:** baseboard serial, chassis serial, system product/manufacturer, CPU brand + topology, GPU LUID.
- **Lightest:** monitor EDID, audio endpoints, BIOS vendor/version strings.

An HWID ban blacklists a combination hash. Exact combination is Epic's secret. Probability of getting past an HWID ban by changing one field is low; the ban hash is tolerant to single-field drift up to a point.

---

**Next:** [12 — Cheat detection surface](12-cheat-detection.md)
