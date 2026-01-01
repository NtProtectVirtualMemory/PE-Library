#pragma once

/* PE.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

#include <vector>

// Typedefs

typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef long				LONG;
typedef unsigned __int64	ULONGLONG;

// Constants

constexpr WORD	IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr WORD	IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
constexpr WORD	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b; // PE32
constexpr WORD	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b; // PE32+ (64-bit)
constexpr WORD	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

#if ( defined(__midl) && (501 < __midl) )

typedef [public] __int3264 INT_PTR, * PINT_PTR;
typedef [public] unsigned __int3264 UINT_PTR, * PUINT_PTR;

typedef [public] __int3264 LONG_PTR, * PLONG_PTR;
typedef [public] unsigned __int3264 ULONG_PTR, * PULONG_PTR;

#else  // midl64
// old midl and C++ compiler

#if defined(_WIN64)
typedef __int64 INT_PTR, * PINT_PTR;
typedef unsigned __int64 UINT_PTR, * PUINT_PTR;

typedef __int64 LONG_PTR, * PLONG_PTR;
typedef unsigned __int64 ULONG_PTR, * PULONG_PTR;

#define __int3264   __int64

#else
typedef _W64 int INT_PTR, * PINT_PTR;
typedef _W64 unsigned int UINT_PTR, * PUINT_PTR;

typedef _W64 long LONG_PTR, * PLONG_PTR;
typedef _W64 unsigned long ULONG_PTR, * PULONG_PTR;

#define __int3264   __int32

#endif
#endif // midl64

// Structs

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
	WORD   e_magic;                     // Magic number
	WORD   e_cblp;                      // Bytes on last page of file
	WORD   e_cp;                        // Pages in file
	WORD   e_crlc;                      // Relocations
	WORD   e_cparhdr;                   // Size of header in paragraphs
	WORD   e_minalloc;                  // Minimum extra paragraphs needed
	WORD   e_maxalloc;                  // Maximum extra paragraphs needed
	WORD   e_ss;                        // Initial (relative) SS value
	WORD   e_sp;                        // Initial SP value
	WORD   e_csum;                      // Checksum
	WORD   e_ip;                        // Initial IP value
	WORD   e_cs;                        // Initial (relative) CS value
	WORD   e_lfarlc;                    // File address of relocation table
	WORD   e_ovno;                      // Overlay number
	WORD   e_res[4];                    // Reserved words
	WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
	WORD   e_oeminfo;                   // OEM information; e_oemid specific
	WORD   e_res2[10];                  // Reserved words
	LONG   e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD    Machine;
	WORD    NumberOfSections;
	DWORD   TimeDateStamp;
	DWORD   PointerToSymbolTable;
	DWORD   NumberOfSymbols;
	WORD    SizeOfOptionalHeader;
	WORD    Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD   VirtualAddress;
	DWORD   Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_OPTIONAL_HEADER {
	//
	// Standard fields.
	//

	WORD    Magic;
	BYTE    MajorLinkerVersion;
	BYTE    MinorLinkerVersion;
	DWORD   SizeOfCode;
	DWORD   SizeOfInitializedData;
	DWORD   SizeOfUninitializedData;
	DWORD   AddressOfEntryPoint;
	DWORD   BaseOfCode;
	DWORD   BaseOfData;

	//
	// NT additional fields.
	//

	DWORD   ImageBase;
	DWORD   SectionAlignment;
	DWORD   FileAlignment;
	WORD    MajorOperatingSystemVersion;
	WORD    MinorOperatingSystemVersion;
	WORD    MajorImageVersion;
	WORD    MinorImageVersion;
	WORD    MajorSubsystemVersion;
	WORD    MinorSubsystemVersion;
	DWORD   Win32VersionValue;
	DWORD   SizeOfImage;
	DWORD   SizeOfHeaders;
	DWORD   CheckSum;
	WORD    Subsystem;
	WORD    DllCharacteristics;
	DWORD   SizeOfStackReserve;
	DWORD   SizeOfStackCommit;
	DWORD   SizeOfHeapReserve;
	DWORD   SizeOfHeapCommit;
	DWORD   LoaderFlags;
	DWORD   NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64                 PIMAGE_NT_HEADERS;
#else
typedef IMAGE_NT_HEADERS32                  IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32                 PIMAGE_NT_HEADERS;
#endif

typedef struct _IMAGE_SECTION_HEADER {
	BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD   PhysicalAddress;
		DWORD   VirtualSize;
	} Misc;
	DWORD   VirtualAddress;
	DWORD   SizeOfRawData;
	DWORD   PointerToRawData;
	DWORD   PointerToRelocations;
	DWORD   PointerToLinenumbers;
	WORD    NumberOfRelocations;
	WORD    NumberOfLinenumbers;
	DWORD   Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

// Defines

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((LONG)(LONG_PTR)&(((type *)0)->field))
#endif

#define IMAGE_FIRST_SECTION( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

namespace PE
{
	class Image; // Forward declaration

	class Section
	{
	public:
		Section(Image* image) : m_image(image) {}
		/*
		* @brief Retrieves section header based on the specified name
		* @param name The name of the section to retrieve
		* @return A pointer to the section header, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_SECTION_HEADER Get(const char* name) noexcept;

	private:
		Image* m_image;
	};

	class DosHeader
	{
	public:
		DosHeader(Image* image) : m_image(image) {}
		/*
		* @brief Retrieves the DOS header
		* @param none
		* @return A pointer to the DOS header, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_DOS_HEADER Get() noexcept;

	private:
		Image* m_image;
	};

	class NtHeaders
	{
	public:
		NtHeaders(Image* image) : m_image(image) {}
		/*
		* @brief Retrieves the Optional 32-bit headers
		* @param none
		* @return Pointer to the Optional 32-bit headers, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_NT_HEADERS32 Get32() noexcept;
		/*
		* @brief Retrieves the Optional 64-bit headers
		* @param none
		* @return Pointer to the Optional 64-bit headers, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_NT_HEADERS64 Get64() noexcept;
		/*
		* @brief Retrieves the NT headers based on the specified type
		* @param none
		* @return A pointer to the NT headers of type T
		*/
		template<typename T>
		[[nodiscard]] T* Get() noexcept
		{
			static_assert(std::is_same_v<T, IMAGE_NT_HEADERS32> ||
				std::is_same_v<T, IMAGE_NT_HEADERS64>,
				"T must be IMAGE_NT_HEADERS32 or IMAGE_NT_HEADERS64");

			if constexpr (std::is_same_v<T, IMAGE_NT_HEADERS32>)
				return Get32();
			else
				return Get64();
		}

	private:
		Image* m_image;
	};

	class OptionalHeader
	{
	public:
		OptionalHeader(Image* image) : m_image(image) {}
		/*
		* @brief Retrieves the Optional 32-bit headers
		* @param none
		* @return Pointer to the Optional 32-bit headers, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_OPTIONAL_HEADER32 Get32() noexcept;
		/*
		* @brief Retrieves the Optional 64-bit headers
		* @param none
		* @return Pointer to the Optional 64-bit headers, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_OPTIONAL_HEADER64 Get64() noexcept;
		/*
		* @brief Retrieves the Optional headers based on the specified type
		* @param none
		* @return A pointer to the Optional headers of type T
		*/
		template<typename T>
		[[nodiscard]] T* Get() noexcept
		{
			static_assert(std::is_same_v<T, IMAGE_OPTIONAL_HEADER32> ||
				std::is_same_v<T, IMAGE_OPTIONAL_HEADER64>,
				"T must be IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64");

			if constexpr (std::is_same_v<T, IMAGE_OPTIONAL_HEADER32>)
				return Get32();
			else
				return Get64();
		}

	private:
		Image* m_image;
	};

	class Image
	{
	public:
		Image(const char* path);
		~Image() = default;
		/*
		* @brief Checks if the PE image is valid
		* @param none
		* @return True if the PE image is valid, false otherwise
		*/
		[[nodiscard]] __forceinline bool IsValid() const noexcept { return m_valid; }
		/*
		* @brief Checks if the PE image is a 32-bit image
		* @param none
		* @return True if the PE image is 32-bit, false otherwise
		*/
		[[nodiscard]] __forceinline bool IsPE32() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
		/*
		* @brief Checks if the PE image is a 64-bit image
		* @param none
		* @return True if the PE image is 64-bit, false otherwise
		*/
		[[nodiscard]] __forceinline bool IsPE64() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

		// Accessors
		DosHeader _DOS() noexcept { return DosHeader(this); }
		NtHeaders _NT() noexcept { return NtHeaders(this); }
		OptionalHeader _OPTIONAL() noexcept { return OptionalHeader(this); }

		// PE Image data
		std::vector<BYTE>& Data() noexcept { return m_data; }

	private:

		// Members
		std::vector<BYTE> m_data;
		bool m_valid = false;
		WORD m_magic = 0;

		bool Validate() noexcept;

		// Friends
		friend class DosHeader;
		friend class NtHeaders;
		friend class OptionalHeader;
	};

} // namespace PE