#!/usr/bin/env python3
"""
strip_pdata.py — zero DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] in a
PE32+ driver so RAGE's mapper skips the nt!RtlInsertInvertedFunctionTable
call.

Root cause for BSOD 0xE4 WORKER_INVALID param1=1 (worker item queued twice):
  - .pdata present → mapper logs "RtlInsertInvertedFunctionTable -> RVA ..."
    and inserts entry into nt!PsInvertedFunctionTable
  - Kernel SEH dispatch (RtlLookupFunctionEntry → RtlpxLookupFunctionTable)
    then walks our image's unwind data on every exception taken by any
    worker thread → corrupts WORK_QUEUE_ITEM.List.Flink → next
    ExQueueWorkItem fires the sanity check → bugcheck.

Fix: NULL out OptionalHeader.DataDirectory[3] (VirtualAddress + Size).
The mapper reads this directory to decide whether to call RIFT. Zeroed
directory = no call. .pdata section bytes stay in the file but go
unreferenced — equivalent to the NULL-driver path that provably works.

Usage:
  python strip_pdata.py path\\to\\rage_drv.sys
"""

import sys, struct

def strip_pdata(path):
    with open(path, 'r+b') as f:
        data = f.read()
        # DOS header: e_lfanew at offset 0x3C
        e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
        # NT headers: Signature(4) + FileHeader(20) → OptionalHeader at +24
        opt_off = e_lfanew + 24
        magic = struct.unpack_from('<H', data, opt_off)[0]
        if magic != 0x20b:
            print(f'ERROR: Not PE32+ (magic=0x{magic:x})')
            return 1
        # OptionalHeader (PE32+): DataDirectory array starts at offset 112
        # Each entry = 8 bytes (RVA u32, Size u32). Index 3 = EXCEPTION.
        dd3_off = opt_off + 112 + 3 * 8
        rva, size = struct.unpack_from('<II', data, dd3_off)
        if rva == 0 and size == 0:
            print(f'[strip_pdata] DataDirectory[3] already zero — nothing to do')
            return 0
        print(f'[strip_pdata] DataDirectory[3] before: RVA=0x{rva:x} Size=0x{size:x}')
        # Write zeroes
        f.seek(dd3_off)
        f.write(struct.pack('<II', 0, 0))
        f.flush()
        print(f'[strip_pdata] DataDirectory[3] after:  RVA=0x0 Size=0x0')
        print(f'[strip_pdata] mapper will now skip RtlInsertInvertedFunctionTable')
    return 0

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: python strip_pdata.py <driver.sys>')
        sys.exit(1)
    sys.exit(strip_pdata(sys.argv[1]))
