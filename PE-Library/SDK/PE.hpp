#pragma once

/* PE.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

#include <vector>
#include <thread>

typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef long				LONG;
typedef unsigned __int64	ULONGLONG;

constexpr WORD	IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
constexpr WORD	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b; // PE32
constexpr WORD	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b; // PE32+ (64-bit)
constexpr WORD	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

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

namespace PE
{
	class Image; // Forward declaration
	class DosHeader
	{
	public:
		DosHeader(Image* image) : m_image(image) {}
		[[nodiscard]] PIMAGE_DOS_HEADER Get() noexcept;

	private:
		Image* m_image;
	};

	class NtHeaders
	{
	public:
		NtHeaders(Image* image) : m_image(image) {}
		[[nodiscard]] PIMAGE_NT_HEADERS32 Get32() noexcept;
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
		[[nodiscard]] PIMAGE_OPTIONAL_HEADER32 Get32() noexcept;
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

		// Validation
		[[nodiscard]] __forceinline bool IsValid() const noexcept { return m_valid; }
		[[nodiscard]] __forceinline bool IsPE32() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
		[[nodiscard]] __forceinline bool IsPE64() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

		// Accessors
		DosHeader _DOS() noexcept { return DosHeader(this); }
		NtHeaders _NT() noexcept { return NtHeaders(this); }
		OptionalHeader _OPTIONAL() noexcept { return OptionalHeader(this); }

		// PE Image data
		std::vector<BYTE>& Data() noexcept { return m_data; }

	private:

		// Cute members
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