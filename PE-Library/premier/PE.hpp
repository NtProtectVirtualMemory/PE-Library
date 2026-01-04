#pragma once

/* PE.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

#include <vector>
#include <string_view>
#include <cstring>
#include <cstdio>

// Typedefs

typedef unsigned long       DWORD;
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef long				LONG;
typedef unsigned __int64	ULONGLONG;

#if ( defined(__midl) && (501 < __midl) )

typedef [public] __int3264 INT_PTR, * PINT_PTR;
typedef [public] unsigned __int3264 UINT_PTR, * PUINT_PTR;

typedef [public] __int3264 LONG_PTR, * PLONG_PTR;
typedef [public] unsigned __int3264 ULONG_PTR, * PULONG_PTR;

#else  // midl64

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

#ifndef _UINTPTR_T_DEFINED
#define _UINTPTR_T_DEFINED
#ifdef _WIN64
typedef unsigned __int64  uintptr_t;
#else
typedef unsigned int uintptr_t;
#endif
#endif

// Constants

constexpr WORD	IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr WORD	IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
constexpr DWORD IMAGE_NT_SIGNATURE = 0x00004550; // PE\0\0
constexpr WORD	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b; // PE32
constexpr WORD	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b; // PE32+ (64-bit)
constexpr WORD	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;

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
	IMAGE_OPTIONAL_HEADER64 Optional;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 Optional;
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
     FIELD_OFFSET( IMAGE_NT_HEADERS, Optional ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))

namespace PE
{
	class Image;

	/*
	* @brief Do not instantiate this class directly. Use Image::DosHeader() instead!
	*/
	class _DosHeader
	{
	public:
		_DosHeader(Image* image) : m_image(image) {}
		[[nodiscard]] const IMAGE_DOS_HEADER* Get() const noexcept;

	private:
		Image* m_image;
		friend class Image;
		[[nodiscard]] bool Validate(const std::vector<BYTE>& data) const noexcept;
	};

	/*
	* @brief Do not instantiate this class directly. Use Image::NtHeaders() instead!
	*/
	class _NtHeaders
	{
	private:
		Image* m_image;
		friend class Image;
		[[nodiscard]] const IMAGE_NT_HEADERS32* Get32() const noexcept;
		[[nodiscard]] const IMAGE_NT_HEADERS64* Get64() const noexcept;
		[[nodiscard]] bool Validate(const std::vector<BYTE>& data) const noexcept;

	public:
		_NtHeaders(Image* image) : m_image(image) {}

		template<typename T>
		[[nodiscard]] inline const T* Get() const noexcept
		{
			static_assert(std::is_same_v<T, IMAGE_NT_HEADERS32> ||
				std::is_same_v<T, IMAGE_NT_HEADERS64>,
				"T must be IMAGE_NT_HEADERS32 or IMAGE_NT_HEADERS64");

			if constexpr (std::is_same_v<T, IMAGE_NT_HEADERS32>)
				return Get32();
			else
				return Get64();
		}
	};

	/*
	* @brief Do not instantiate this class directly. Use Image::OptionalHeader() instead!
	*/
	class _OptionalHeader
	{
	private:
		Image* m_image;
		friend class Image;
		[[nodiscard]] const IMAGE_OPTIONAL_HEADER32* Get32() const noexcept;
		[[nodiscard]] const IMAGE_OPTIONAL_HEADER64* Get64() const noexcept;
		[[nodiscard]] bool Validate(const std::vector<BYTE>& data) const noexcept;

	public:
		_OptionalHeader(Image* image) : m_image(image) {}

		template<typename T>
		[[nodiscard]] inline const T* Get() const noexcept
		{
			static_assert(std::is_same_v<T, IMAGE_OPTIONAL_HEADER32> ||
				std::is_same_v<T, IMAGE_OPTIONAL_HEADER64>,
				"T must be IMAGE_OPTIONAL_HEADER32 or IMAGE_OPTIONAL_HEADER64");

			if constexpr (std::is_same_v<T, IMAGE_OPTIONAL_HEADER32>)
				return Get32();
			else
				return Get64();
		}
	};

	/*
	* @brief Do not instantiate this class directly. Use Image::Sections() instead!
	*/
	class _Sections
	{
	private:
		Image* m_image;
		WORD m_number_of_sections = 0;
		const IMAGE_SECTION_HEADER* m_sections = nullptr;
		friend class Image;
		[[nodiscard]] bool Validate(const std::vector<BYTE>& data) noexcept;

	public:
		_Sections(Image* image);

		[[nodiscard]] std::vector<std::string_view> List() const noexcept;
		[[nodiscard]] const IMAGE_SECTION_HEADER* Get(const char* name) const noexcept;
	};

	/*
	* @brief Represents a PE image
	*/
	class Image
	{
	public:
		Image(const char* path);
		~Image() = default;

		[[nodiscard]] __forceinline constexpr bool IsValid() const noexcept { return m_valid; }
		[[nodiscard]] __forceinline constexpr bool IsPE32() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
		[[nodiscard]] __forceinline constexpr bool IsPE64() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

		_Sections		Sections() noexcept { return _Sections(this); }
		_DosHeader		DosHeader() noexcept { return _DosHeader(this); }
		_NtHeaders	    NtHeaders() noexcept { return _NtHeaders(this); }
		_OptionalHeader OptionalHeader() noexcept { return _OptionalHeader(this); }

		const std::vector<BYTE>& Data() const noexcept { return m_data; }

	private:
		std::vector<BYTE> m_data;
		bool m_valid = false;
		WORD m_magic = 0;

		inline bool ValidateImage() noexcept
		{
			if (m_data.empty())
				return false;

			if (!DosHeader().Validate(m_data))
				return false;

			if (!NtHeaders().Validate(m_data))
				return false;

			if (!OptionalHeader().Validate(m_data))
				return false;

			auto dos = DosHeader().Get();
			if (dos)
			{
				size_t optional_offset = dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
				if (optional_offset + sizeof(WORD) <= m_data.size())
				{
					m_magic = *reinterpret_cast<const WORD*>(m_data.data() + optional_offset);
				}
			}

			if (!Sections().Validate(m_data))
				return false;

			m_valid = true;
			return true;
		}
	};

	// DOS HEADER

	inline const IMAGE_DOS_HEADER* PE::_DosHeader::Get() const noexcept
	{
		if (!m_image || m_image->Data().empty())
			return nullptr;

		return reinterpret_cast<const IMAGE_DOS_HEADER*>(m_image->Data().data());
	}


	// NT HEADERS

	inline const IMAGE_NT_HEADERS32* PE::_NtHeaders::Get32() const noexcept
	{
		if (!m_image)
			return nullptr;

		auto dos_header = m_image->DosHeader().Get();
		if (!dos_header || m_image->Data().empty())
			return nullptr;

		return reinterpret_cast<const IMAGE_NT_HEADERS32*>(m_image->Data().data() + dos_header->e_lfanew);
	}

	inline const IMAGE_NT_HEADERS64* PE::_NtHeaders::Get64() const noexcept
	{
		if (!m_image)
			return nullptr;

		auto dos_header = m_image->DosHeader().Get();
		if (!dos_header || m_image->Data().empty())
			return nullptr;

		return reinterpret_cast<const IMAGE_NT_HEADERS64*>(m_image->Data().data() + dos_header->e_lfanew);
	}


	// OPTIONAL HEADER

	inline const IMAGE_OPTIONAL_HEADER32* PE::_OptionalHeader::Get32() const noexcept
	{
		if (!m_image)
			return nullptr;

		auto nt_headers = m_image->NtHeaders().Get<IMAGE_NT_HEADERS32>();
		return nt_headers ? &nt_headers->Optional : nullptr;
	}

	inline const IMAGE_OPTIONAL_HEADER64* PE::_OptionalHeader::Get64() const noexcept
	{
		if (!m_image)
			return nullptr;

		auto nt_headers = m_image->NtHeaders().Get<IMAGE_NT_HEADERS64>();
		return nt_headers ? &nt_headers->Optional : nullptr;
	}

	// SECTIONS

	inline std::vector<std::string_view> PE::_Sections::List() const noexcept
	{
		std::vector<std::string_view> section_names;
		section_names.reserve(m_number_of_sections);

		for (size_t i = 0; i < m_number_of_sections; ++i)
		{
			size_t name_len = 0;
			for (size_t j = 0; j < IMAGE_SIZEOF_SHORT_NAME && m_sections[i].Name[j] != '\0'; ++j)
				name_len++;

			section_names.emplace_back(reinterpret_cast<const char*>(m_sections[i].Name), name_len);
		}

		return section_names;
	}

	inline const IMAGE_SECTION_HEADER* PE::_Sections::Get(const char* name) const noexcept
	{
		for (size_t i = 0; i < m_number_of_sections; ++i)
		{
			if (_stricmp(reinterpret_cast<const char*>(m_sections[i].Name), name) == 0) // Not the best way to do it (Should use std::strncmp)
			{
				return &m_sections[i];
			}
		}

		return nullptr;
	}

} // namespace PE