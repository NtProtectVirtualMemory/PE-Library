#pragma once

#include <vector>
#include <cstdint>
#include <string_view>

constexpr std::uint32_t	IMAGE_NT_SIGNATURE = 0x4550; // PE\0\0
constexpr std::uint16_t	IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
constexpr std::uint16_t	IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b; // PE32
constexpr std::uint16_t	IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b; // PE32+ (64-bit)
constexpr std::uint16_t	IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
constexpr std::uint16_t	IMAGE_SIZEOF_SHORT_NAME = 8;
constexpr std::uint32_t IMAGE_ORDINAL_FLAG32 = 0x80000000;
constexpr std::uint64_t IMAGE_ORDINAL_FLAG64 = 0x8000000000000000ULL;

constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_SECURITY = 4;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_BASERELOC = 5;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_TLS = 9;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_IAT = 12;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
constexpr std::uint16_t IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

constexpr std::uint16_t IMAGE_DEBUG_TYPE_UNKNOWN = 0;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_COFF = 1;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_CODEVIEW = 2;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_FPO = 3;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_MISC = 4;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_EXCEPTION = 5;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_FIXUP = 6;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_OMAP_TO_SRC = 7;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_OMAP_FROM_SRC = 8;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_BORLAND = 9;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_RESERVED10 = 10;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_BBT = IMAGE_DEBUG_TYPE_RESERVED10;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_CLSID = 11;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_VC_FEATURE = 12;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_POGO = 13;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_ILTCG = 14;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_MPX = 15;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_REPRO = 16;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_SPGO = 18;
constexpr std::uint16_t IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS = 20;

constexpr std::uint16_t IMAGE_REL_BASED_ABSOLUTE = 0;   // Padding (skip)
constexpr std::uint16_t IMAGE_REL_BASED_HIGH = 1;   // High 16 bits
constexpr std::uint16_t IMAGE_REL_BASED_LOW = 2;   // Low 16 bits
constexpr std::uint16_t IMAGE_REL_BASED_HIGHLOW = 3;   // Full 32-bit (x86)
constexpr std::uint16_t IMAGE_REL_BASED_HIGHADJ = 4;   // High 16 + adjust
constexpr std::uint16_t IMAGE_REL_BASED_DIR64 = 10;  // Full 64-bit (x64)

constexpr std::uint16_t RT_CURSOR = 1;
constexpr std::uint16_t RT_BITMAP = 2;
constexpr std::uint16_t RT_ICON = 3;
constexpr std::uint16_t RT_MENU = 4;
constexpr std::uint16_t RT_DIALOG = 5;
constexpr std::uint16_t RT_STRING = 6;
constexpr std::uint16_t RT_FONTDIR = 7;
constexpr std::uint16_t RT_FONT = 8;
constexpr std::uint16_t RT_ACCELERATOR = 9;
constexpr std::uint16_t RT_RCDATA = 10;
constexpr std::uint16_t RT_MESSAGETABLE = 11;
constexpr std::uint16_t RT_GROUP_CURSOR = 12;
constexpr std::uint16_t RT_GROUP_ICON = 14;
constexpr std::uint16_t RT_VERSION = 16;
constexpr std::uint16_t RT_MANIFEST = 24;

namespace PE
{
	struct ImageDosHeader
	{
		std::uint16_t   e_magic;                     // Magic number
		std::uint16_t   e_cblp;                      // Bytes on last page of file
		std::uint16_t   e_cp;                        // Pages in file
		std::uint16_t   e_crlc;                      // Relocations
		std::uint16_t   e_cparhdr;                   // Size of header in paragraphs
		std::uint16_t   e_minalloc;                  // Minimum extra paragraphs needed
		std::uint16_t   e_maxalloc;                  // Maximum extra paragraphs needed
		std::uint16_t   e_ss;                        // Initial (relative) SS value
		std::uint16_t   e_sp;                        // Initial SP value
		std::uint16_t   e_csum;                      // Checksum
		std::uint16_t   e_ip;                        // Initial IP value
		std::uint16_t   e_cs;                        // Initial (relative) CS value
		std::uint16_t   e_lfarlc;                    // File address of relocation table
		std::uint16_t   e_ovno;                      // Overlay number
		std::uint16_t   e_res[4];                    // Reserved words
		std::uint16_t   e_oemid;                     // OEM identifier (for e_oeminfo)
		std::uint16_t   e_oeminfo;                   // OEM information; e_oemid specific
		std::uint16_t   e_res2[10];                  // Reserved words
		std::uint32_t   e_lfanew;                    // File address of new exe header
	};

	// The Structures below correspond to NT Headers

	struct ImageDataDirectory
	{
		std::uint32_t VirtualAddress;
		std::uint32_t Size;
	};

	struct ImageOptionalHeader32 {
		//
		// Standard fields.
		//

		std::uint16_t    Magic;
		std::uint8_t     MajorLinkerVersion;
		std::uint8_t     MinorLinkerVersion;
		std::uint32_t    SizeOfCode;
		std::uint32_t    SizeOfInitializedData;
		std::uint32_t    SizeOfUninitializedData;
		std::uint32_t    AddressOfEntryPoint;
		std::uint32_t    BaseOfCode;
		std::uint32_t    BaseOfData;

		//
		// NT additional fields.
		//

		std::uint32_t    ImageBase;
		std::uint32_t    SectionAlignment;
		std::uint32_t    FileAlignment;
		std::uint16_t    MajorOperatingSystemVersion;
		std::uint16_t    MinorOperatingSystemVersion;
		std::uint16_t    MajorImageVersion;
		std::uint16_t    MinorImageVersion;
		std::uint16_t    MajorSubsystemVersion;
		std::uint16_t    MinorSubsystemVersion;
		std::uint32_t    Win32VersionValue;
		std::uint32_t    SizeOfImage;
		std::uint32_t    SizeOfHeaders;
		std::uint32_t    CheckSum;
		std::uint16_t    Subsystem;
		std::uint16_t    DllCharacteristics;
		std::uint32_t    SizeOfStackReserve;
		std::uint32_t    SizeOfStackCommit;
		std::uint32_t    SizeOfHeapReserve;
		std::uint32_t    SizeOfHeapCommit;
		std::uint32_t    LoaderFlags;
		std::uint32_t    NumberOfRvaAndSizes;
		ImageDataDirectory    DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	};

	struct ImageOptionalHeader64
	{
		std::uint16_t    Magic;
		std::uint8_t     MajorLinkerVersion;
		std::uint8_t     MinorLinkerVersion;
		std::uint32_t    SizeOfCode;
		std::uint32_t    SizeOfInitializedData;
		std::uint32_t    SizeOfUninitializedData;
		std::uint32_t    AddressOfEntryPoint;
		std::uint32_t    BaseOfCode;
		std::uint64_t    ImageBase;
		std::uint32_t    SectionAlignment;
		std::uint32_t    FileAlignment;
		std::uint16_t    MajorOperatingSystemVersion;
		std::uint16_t    MinorOperatingSystemVersion;
		std::uint16_t    MajorImageVersion;
		std::uint16_t    MinorImageVersion;
		std::uint16_t    MajorSubsystemVersion;
		std::uint16_t    MinorSubsystemVersion;
		std::uint32_t    Win32VersionValue;
		std::uint32_t    SizeOfImage;
		std::uint32_t    SizeOfHeaders;
		std::uint32_t    CheckSum;
		std::uint16_t    Subsystem;
		std::uint16_t    DllCharacteristics;
		std::uint64_t    SizeOfStackReserve;
		std::uint64_t    SizeOfStackCommit;
		std::uint64_t    SizeOfHeapReserve;
		std::uint64_t    SizeOfHeapCommit;
		std::uint32_t    LoaderFlags;
		std::uint32_t    NumberOfRvaAndSizes;
		ImageDataDirectory DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
	};

	struct ImageFileHeader
	{
		std::uint16_t    Machine;
		std::uint16_t    NumberOfSections;
		std::uint32_t    TimeDateStamp;
		std::uint32_t    PointerToSymbolTable;
		std::uint32_t    NumberOfSymbols;
		std::uint16_t    SizeOfOptionalHeader;
		std::uint16_t    Characteristics;
	};

	struct ImageNtHeaders32
	{
		std::uint32_t		  Signature;
		ImageFileHeader		  FileHeader;
		ImageOptionalHeader32 OptionalHeader;
	};

	struct ImageNtHeaders64
	{
		std::uint32_t			Signature;
		ImageFileHeader			FileHeader;
		ImageOptionalHeader64	OptionalHeader;
	};

	//The Structures below correspond the class Imports

	struct ImageImportDescriptor {
		union {
			std::uint32_t Characteristics;
			std::uint32_t OriginalFirstThunk;
		};
		std::uint32_t TimeDateStamp;
		std::uint32_t ForwarderChain;
		std::uint32_t Name;
		std::uint32_t FirstThunk;
	};

	struct ImageThunkData64 {
		union {
			std::uint64_t ForwarderString;
			std::uint64_t Function;
			std::uint64_t Ordinal;
			std::uint64_t AddressOfData;
		} u1;
	};

	struct ImageThunkData32 {
		union {
			std::uint32_t ForwarderString;
			std::uint32_t Function;
			std::uint32_t Ordinal;
			std::uint32_t AddressOfData;
		} u1;
	};

	typedef struct ImageImportByName {
		std::uint16_t    Hint;
		char    Name[1];
	} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

	struct ImportFunction
	{
		std::string_view name;
		std::uint16_t hint;
		std::uint16_t ordinal;
		bool is_ordinal;
	};

	struct ImportEntry
	{
		std::string_view dll_name;
		std::vector<ImportFunction> functions;
	};

	// The Structures below correspond the class Exports

	struct ImageExportDirectory {
		std::uint32_t Characteristics;
		std::uint32_t TimeDateStamp;
		std::uint16_t MajorVersion;
		std::uint16_t MinorVersion;
		std::uint32_t Name;
		std::uint32_t Base;
		std::uint32_t NumberOfFunctions;
		std::uint32_t NumberOfNames;
		std::uint32_t AddressOfFunctions;
		std::uint32_t AddressOfNames;
		std::uint32_t AddressOfNameOrdinals;
	};

	struct ExportFunction
	{
		std::string_view name;
		std::uint32_t rva;
		std::uint64_t va;
		std::uint32_t file_offset;
		std::uint16_t ordinal;
		bool is_forwarded;
		std::string_view forward_name;
	};

	// The Structures below correspond the class Relocations

	struct ImageBaseRelocation {
		std::uint32_t VirtualAddress;
		std::uint32_t SizeOfBlock;
	};

	struct RelocationEntry
	{
		std::uint32_t rva;
		std::uint16_t type;
		std::uint32_t file_offset;
	};

	struct RelocationBlock
	{
		std::uint32_t page_rva;
		std::vector<RelocationEntry> entries;
	};


	// The Structures below correspond the class TLS

	struct ImageTlsDirectory64 {
		std::uint64_t StartAddressOfRawData;
		std::uint64_t EndAddressOfRawData;
		std::uint64_t AddressOfIndex;
		std::uint64_t AddressOfCallBacks;    // VA to null-terminated callback array
		std::uint32_t SizeOfZeroFill;
		std::uint32_t Characteristics;
	};

	struct ImageTlsDirectory32 {
		std::uint32_t StartAddressOfRawData;
		std::uint32_t EndAddressOfRawData;
		std::uint32_t AddressOfIndex;
		std::uint32_t AddressOfCallBacks;    // VA to null-terminated callback array
		std::uint32_t SizeOfZeroFill;
		std::uint32_t Characteristics;
	};

	struct TLSCallback
	{
		std::uint64_t va;
		std::uint32_t rva;
		std::uint32_t file_offset;
	};

	struct TLSInfo
	{
		std::uint64_t raw_data_start_va;
		std::uint64_t raw_data_end_va;
		std::uint64_t index_va;
		std::uint64_t callbacks_va;
		std::uint32_t zero_fill_size;
		std::uint32_t characteristics;
		std::uint32_t raw_data_size;
	};

	// The Structures below correspond the class Resources

	struct ImageResourceDirectory {
		std::uint32_t Characteristics;
		std::uint32_t TimeDateStamp;
		std::uint16_t MajorVersion;
		std::uint16_t MinorVersion;
		std::uint16_t NumberOfNamedEntries;
		std::uint16_t NumberOfIdEntries;
	};

	struct ImageResourceDirectoryEntry {
		union {
			struct {
				std::uint32_t NameOffset : 31;
				std::uint32_t NameIsString : 1;
			};
			std::uint32_t Name;
			std::uint16_t Id;
		};
		union {
			std::uint32_t OffsetToData;
			struct {
				std::uint32_t OffsetToDirectory : 31;
				std::uint32_t DataIsDirectory : 1;
			};
		};
	};

	struct ImageResourceDataEntry {
		std::uint32_t   OffsetToData;   // RVA to actual resource data
		std::uint32_t   Size;
		std::uint32_t   CodePage;
		std::uint32_t   Reserved;
	};


	struct ResourceEntry
	{
		std::uint16_t type_id;
		std::string_view type_name;
		std::uint16_t resource_id;
		std::string_view resource_name;
		std::uint16_t language_id;
		std::uint32_t data_rva;
		std::uint32_t data_size;
		std::uint32_t file_offset;
		std::uint32_t code_page;
	};

	struct VersionInfo
	{
		std::uint16_t major;
		std::uint16_t minor;
		std::uint16_t build;
		std::uint16_t revision;
		std::uint16_t product_major;
		std::uint16_t product_minor;
		std::uint16_t product_build;
		std::uint16_t product_revision;
		std::uint32_t file_flags;
		std::uint32_t file_os;
		std::uint32_t file_type;
	};

	// Debug

	struct ImageDebugDirectory {
		std::uint32_t   Characteristics;
		std::uint32_t   TimeDateStamp;
		std::uint16_t   MajorVersion;
		std::uint16_t   MinorVersion;
		std::uint32_t   Type;
		std::uint32_t   SizeOfData;
		std::uint32_t   AddressOfRawData;
		std::uint32_t   PointerToRawData;
	};

	struct DebugEntry
	{
		std::uint16_t type;
		std::uint32_t size;
		std::uint32_t address_rva;
		std::uint32_t address_offset;
	};

	// The Structures below correspond the class RichHeader

	struct RichEntry
	{
		std::uint16_t product_id;
		std::uint16_t build_id;
		std::uint32_t use_count;
	};

	// The Structures below correspond the class ImageSections

	struct ImageSectionHeader
	{
		std::uint8_t  Name[8];
		union
		{
			std::uint32_t   PhysicalAddress;
			std::uint32_t   VirtualSize;
		} Misc;
		std::uint32_t   VirtualAddress;
		std::uint32_t   SizeOfRawData;
		std::uint32_t   PointerToRawData;
		std::uint32_t   PointerToRelocations;
		std::uint32_t   PointerToLinenumbers;
		std::uint16_t   NumberOfRelocations;
		std::uint16_t   NumberOfLinenumbers;
		std::uint32_t   Characteristics;
	};
}

// Defines
#ifndef FIELD_OFFSET
#define FIELD_OFFSET(type, field) ((std::uint32_t)(std::uint32_t*)&(((type *)0)->field))
#endif

#define IMAGE_FIRST_SECTION(ntheader) \
    ((PE::ImageSectionHeader*) \
        ((const uint8_t*)(ntheader) + \
         sizeof(std::uint32_t) + \
         sizeof(PE::ImageFileHeader) + \
         (ntheader)->FileHeader.SizeOfOptionalHeader))