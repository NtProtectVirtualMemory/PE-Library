#!/usr/bin/env python3
"""Generate a minimal valid PE64 seed for the fuzz corpus.

The result passes PE::Image validation and carries one ".text" section, giving
the coverage-guided fuzzer a valid skeleton to mutate directories onto. Writes
seed_pe64.bin next to this script (or to argv[1]).
"""
import struct
import sys

DOS_SIZE = 64
OPT64_SIZE = 240          # sizeof(ImageOptionalHeader64)
FILE_HDR_SIZE = 20
SECTION_SIZE = 40
NUM_DIRS = 16

e_lfanew = DOS_SIZE
opt_off = e_lfanew + 4 + FILE_HDR_SIZE
sect_off = opt_off + OPT64_SIZE
headers_end = sect_off + SECTION_SIZE
file_align = 0x200
sect_align = 0x1000
size_of_headers = (headers_end + file_align - 1) // file_align * file_align
raw_data_off = size_of_headers
raw_data_size = file_align

# DOS header: only e_magic and e_lfanew matter to the parser.
dos = bytearray(DOS_SIZE)
struct.pack_into("<H", dos, 0, 0x5A4D)               # "MZ"
struct.pack_into("<I", dos, 60, e_lfanew)            # e_lfanew

# NT signature + file header.
nt_sig = struct.pack("<I", 0x00004550)               # "PE\0\0"
file_hdr = struct.pack(
    "<HHIIIHH",
    0x8664,          # Machine = AMD64
    1,               # NumberOfSections
    0,               # TimeDateStamp
    0,               # PointerToSymbolTable
    0,               # NumberOfSymbols
    OPT64_SIZE,      # SizeOfOptionalHeader
    0x22,            # Characteristics (EXECUTABLE | LARGE_ADDRESS_AWARE)
)

# Optional header (PE32+).
opt = bytearray(OPT64_SIZE)
struct.pack_into("<H", opt, 0, 0x020B)               # Magic = PE32+
opt[2] = 14                                           # MajorLinkerVersion
struct.pack_into("<I", opt, 16, 0x1000)              # AddressOfEntryPoint
struct.pack_into("<Q", opt, 24, 0x140000000)        # ImageBase
struct.pack_into("<I", opt, 32, sect_align)         # SectionAlignment
struct.pack_into("<I", opt, 36, file_align)         # FileAlignment
struct.pack_into("<H", opt, 48, 6)                  # MajorSubsystemVersion
struct.pack_into("<I", opt, 56, sect_align * 2)     # SizeOfImage
struct.pack_into("<I", opt, 60, size_of_headers)    # SizeOfHeaders
struct.pack_into("<H", opt, 68, 2)                  # Subsystem = GUI
struct.pack_into("<I", opt, 108, NUM_DIRS)          # NumberOfRvaAndSizes
# DataDirectory[16] left zeroed: no directories present in the seed.

# One ".text" section.
section = bytearray(SECTION_SIZE)
section[0:5] = b".text"
struct.pack_into("<I", section, 8, raw_data_size)   # VirtualSize
struct.pack_into("<I", section, 12, sect_align)     # VirtualAddress
struct.pack_into("<I", section, 16, raw_data_size)  # SizeOfRawData
struct.pack_into("<I", section, 20, raw_data_off)   # PointerToRawData
struct.pack_into("<I", section, 36, 0x60000020)     # CODE | EXECUTE | READ

image = bytearray(raw_data_off + raw_data_size)
image[0:DOS_SIZE] = dos
image[e_lfanew:e_lfanew + 4] = nt_sig
image[e_lfanew + 4:e_lfanew + 4 + FILE_HDR_SIZE] = file_hdr
image[opt_off:opt_off + OPT64_SIZE] = opt
image[sect_off:sect_off + SECTION_SIZE] = section

out = sys.argv[1] if len(sys.argv) > 1 else "seed_pe64.bin"
with open(out, "wb") as f:
    f.write(image)
print(f"wrote {out} ({len(image)} bytes)")
