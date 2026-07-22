#pragma once

// Platform compatibility layer.
//
// On Windows/MSVC the canonical PE constants, the IMAGE_FIRST_SECTION helper,
// and the *_s CRT functions all come from <windows.h>. On other platforms
// (Linux/macOS with GCC or Clang) this header supplies portable equivalents
// for exactly the subset PE-Library uses, so the library builds and can be
// fuzzed natively. The PE struct layouts themselves live in defs.hpp and are
// identical on every platform.

#if defined(_WIN32)

#include <windows.h>

#else // ---------------------------------------------------------------------

#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cerrno>
#include <type_traits>
#include <strings.h> // strcasecmp / strncasecmp

// --- Compiler keywords ------------------------------------------------------
#ifndef __forceinline
#define __forceinline inline __attribute__((always_inline))
#endif

// --- Data directory indices -------------------------------------------------
#define IMAGE_DIRECTORY_ENTRY_EXPORT     0
#define IMAGE_DIRECTORY_ENTRY_IMPORT     1
#define IMAGE_DIRECTORY_ENTRY_RESOURCE   2
#define IMAGE_DIRECTORY_ENTRY_BASERELOC  5
#define IMAGE_DIRECTORY_ENTRY_DEBUG      6
#define IMAGE_DIRECTORY_ENTRY_TLS        9

// --- Signatures and magics --------------------------------------------------
#define IMAGE_DOS_SIGNATURE              0x5A4D     // "MZ"
#define IMAGE_NT_SIGNATURE               0x00004550 // "PE\0\0"
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC    0x010B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC    0x020B
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME          8

// --- Import ordinal flags ---------------------------------------------------
#define IMAGE_ORDINAL_FLAG64             0x8000000000000000ULL
#define IMAGE_ORDINAL_FLAG32             0x80000000U

// --- Base relocation types --------------------------------------------------
#define IMAGE_REL_BASED_ABSOLUTE          0
#define IMAGE_REL_BASED_HIGH              1
#define IMAGE_REL_BASED_LOW               2
#define IMAGE_REL_BASED_HIGHLOW           3
#define IMAGE_REL_BASED_HIGHADJ           4
#define IMAGE_REL_BASED_DIR64            10

// --- Debug directory types --------------------------------------------------
#define IMAGE_DEBUG_TYPE_UNKNOWN                 0
#define IMAGE_DEBUG_TYPE_COFF                    1
#define IMAGE_DEBUG_TYPE_CODEVIEW                2
#define IMAGE_DEBUG_TYPE_FPO                     3
#define IMAGE_DEBUG_TYPE_MISC                    4
#define IMAGE_DEBUG_TYPE_EXCEPTION               5
#define IMAGE_DEBUG_TYPE_FIXUP                   6
#define IMAGE_DEBUG_TYPE_OMAP_TO_SRC             7
#define IMAGE_DEBUG_TYPE_OMAP_FROM_SRC           8
#define IMAGE_DEBUG_TYPE_BORLAND                 9
#define IMAGE_DEBUG_TYPE_RESERVED10             10
#define IMAGE_DEBUG_TYPE_CLSID                  11
#define IMAGE_DEBUG_TYPE_VC_FEATURE             12
#define IMAGE_DEBUG_TYPE_POGO                   13
#define IMAGE_DEBUG_TYPE_ILTCG                  14
#define IMAGE_DEBUG_TYPE_MPX                    15
#define IMAGE_DEBUG_TYPE_REPRO                  16
#define IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS  20

// --- IMAGE_FIRST_SECTION ----------------------------------------------------
// Windows' macro is defined against its own IMAGE_NT_HEADERS. PE-Library
// passes a pointer to its own PE::ImageNtHeaders{32,64}, which share the
// on-disk layout, so the offset of OptionalHeader is identical (24). We
// compute it from the argument's actual type to stay correct for both.
//
// Yields a std::uintptr_t so callers can reinterpret_cast to const or
// non-const ImageSectionHeader*, matching the Windows macro's usage.
#define IMAGE_FIRST_SECTION(nt)                                            \
	(reinterpret_cast<std::uintptr_t>(nt) +                                \
	 offsetof(std::remove_cv_t<std::remove_pointer_t<decltype(nt)>>,       \
	          OptionalHeader) +                                            \
	 (nt)->FileHeader.SizeOfOptionalHeader)

// --- CRT compatibility ------------------------------------------------------
#define _stricmp  strcasecmp
#define _strnicmp strncasecmp

#endif // _WIN32