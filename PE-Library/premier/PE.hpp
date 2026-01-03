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

// Constants

constexpr WORD	IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr WORD	IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
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
	class Image;

	/*
	* @brief Represents the DOS header of a PE image
	*/
	class DosHeader
	{
	private:
		// Members
		Image* m_image;

	public:
		DosHeader(Image* image) : m_image(image) {}
		/*
		* @brief Retrieves the DOS header
		* @return A pointer to the DOS header, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_DOS_HEADER Get() const noexcept;
	};

	/*
	* @brief Represents the NT headers of a PE image
	*/
	class NtHeaders
	{
	private:
		// Members
		Image* m_image;

		// Private methods
		[[nodiscard]] PIMAGE_NT_HEADERS32 Get32() const noexcept;
		[[nodiscard]] PIMAGE_NT_HEADERS64 Get64() const noexcept;

	public:
		NtHeaders(Image* image) : m_image(image) {}

		/*
		* @brief Retrieves the NT headers based on the specified type
		* @return A pointer to the NT headers of type T
		*/
		template<typename T>
		[[nodiscard]] T* Get() const noexcept
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
	* @brief Represents the Optional headers of a PE image
	*/
	class OptionalHeader
	{
	private:

		// Members
		Image* m_image;

		// Private methods
		[[nodiscard]] PIMAGE_OPTIONAL_HEADER32 Get32() const noexcept;
		[[nodiscard]] PIMAGE_OPTIONAL_HEADER64 Get64() const noexcept;

	public:
		OptionalHeader(Image* image) : m_image(image) {}

		/*
		* @brief Retrieves the Optional headers based on the specified type
		* @return A pointer to the Optional headers of type T
		*/
		template<typename T>
		[[nodiscard]] T* Get() const noexcept
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
	* @brief Represents a PE image
	*/
	class Image
	{
	public:
		Image(const char* path);
		~Image() = default;

		/*
		* @brief Checks if the PE image is valid
		* @return True if the PE image is valid, false otherwise
		*/
		[[nodiscard]] __forceinline constexpr bool IsValid() const noexcept { return m_valid; }

		/*
		* @brief Checks if the PE image is a 32-bit image
		* @return True if the PE image is 32-bit, false otherwise
		*/
		[[nodiscard]] __forceinline constexpr bool IsPE32() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }

		/*
		* @brief Checks if the PE image is a 64-bit image
		* @return True if the PE image is 64-bit, false otherwise
		*/
		[[nodiscard]] __forceinline constexpr bool IsPE64() const noexcept { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

		DosHeader _DOS() noexcept { return DosHeader(this); }
		NtHeaders _NT() noexcept { return NtHeaders(this); }
		OptionalHeader _OPTIONAL() noexcept { return OptionalHeader(this); }

		std::vector<BYTE>& Data() noexcept { return m_data; }

	private:

		// Members
		std::vector<BYTE> m_data;
		bool m_valid = false;
		WORD m_magic = 0;

		// Friends
		friend class DosHeader;
		friend class NtHeaders;
		friend class OptionalHeader;

		// Private methods
		bool Validate() noexcept
		{
			if (m_data.size() < sizeof(IMAGE_DOS_HEADER))
			{
				return false;
			}

			auto dos_header = _DOS().Get();
			if (!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
			{
				return false;
			}

			if (m_data.size() < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) // Was crim here?
			{
				return false;
			}

			m_valid = true;
			return true;
		}

	};

	/*
	* @brief Represents the sections in the PE image
	*/
	class Sections
	{
	private:
		// Members
		Image* m_image;
		WORD m_number_of_sections = 0;
		PIMAGE_SECTION_HEADER m_sections = nullptr;

	public:
		Sections(Image* image) : m_image(image)
		{
			if (!m_image || !m_image->IsValid())
			{
				return;
			}
			if (m_image->IsPE64())
			{
				auto nt_headers = m_image->_NT().Get<IMAGE_NT_HEADERS64>();
				if (!nt_headers)
				{
					return;
				}
				m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
				m_sections = IMAGE_FIRST_SECTION(nt_headers);
			}
			else if (m_image->IsPE32())
			{
				auto nt_headers = m_image->_NT().Get<IMAGE_NT_HEADERS32>();
				if (!nt_headers)
				{
					return;
				}
				m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
				m_sections = IMAGE_FIRST_SECTION(nt_headers);
			}
		}

		/*
		* @brief Retrieves the names of all sections
		* @return A vector containing the names of all sections
		*/
		[[nodiscard]] inline std::vector<std::string_view> List() const noexcept
		{
			std::vector<std::string_view> section_names;
			for (size_t i = 0; i < m_number_of_sections; ++i)
			{
				section_names.emplace_back(reinterpret_cast<const char*>(m_sections[i].Name), IMAGE_SIZEOF_SHORT_NAME);
			}

			return section_names;
		}

		/*
		* @brief Retrieves section header based on the specified name
		* @param name The name of the section to retrieve
		* @return A pointer to the section header, or nullptr if not found
		*/
		[[nodiscard]] PIMAGE_SECTION_HEADER Get(const char* name) const noexcept
		{
			for (size_t i = 0; i < m_number_of_sections; ++i)
			{
				if (_stricmp(reinterpret_cast<char*>(m_sections[i].Name), name) == 0)
				{
					return &m_sections[i];
				}
			}

			return nullptr;
		}
	};

	/*
	* @brief Represents the directories in the PE image
	*/
	class Directories
	{
	private:

	public:

	};

	// DOS Header

	inline PIMAGE_DOS_HEADER PE::DosHeader::Get() const noexcept
	{
		if (!m_image || m_image->Data().empty())
		{
			return nullptr;
		}

		return reinterpret_cast<PIMAGE_DOS_HEADER>(m_image->Data().data());
	}

	// NT Headers

	inline PIMAGE_NT_HEADERS32 PE::NtHeaders::Get32() const noexcept
	{
		if (!m_image)
		{
			return nullptr;
		}

		auto dos_header = m_image->_DOS().Get();
		if (!dos_header || m_image->Data().empty())
		{
			return nullptr;
		}

		return reinterpret_cast<PIMAGE_NT_HEADERS32>(m_image->Data().data() + dos_header->e_lfanew);
	}

	inline PIMAGE_NT_HEADERS64 PE::NtHeaders::Get64() const noexcept
	{
		if (!m_image)
		{
			return nullptr;
		}

		auto dos_header = m_image->_DOS().Get();
		if (!dos_header || m_image->Data().empty())
		{
			return nullptr;
		}

		return reinterpret_cast<PIMAGE_NT_HEADERS64>(m_image->Data().data() + dos_header->e_lfanew);
	}

	// Optional Header
	inline PIMAGE_OPTIONAL_HEADER32 PE::OptionalHeader::Get32() const noexcept
	{
		if (!m_image)
		{
			return nullptr;
		}

		auto nt_headers = m_image->_NT().Get<IMAGE_NT_HEADERS32>();
		return nt_headers ? &nt_headers->OptionalHeader : nullptr;
	}

	inline PIMAGE_OPTIONAL_HEADER64 PE::OptionalHeader::Get64() const noexcept
	{
		if (!m_image)
		{
			return nullptr;
		}

		auto nt_headers = m_image->_NT().Get<IMAGE_NT_HEADERS64>();
		return nt_headers ? &nt_headers->OptionalHeader : nullptr;
	}

} // namespace PE