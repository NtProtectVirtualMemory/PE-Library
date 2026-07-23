#include <cstdio>
#include <fstream>
#include <thread>
#include <vector>

#include "pe-lib/defs.hpp"
#include "pe-lib/image.hpp"
#include "pe-lib/rich.hpp"
#include "pe-lib/sections.hpp"
#include "pe-lib/directories.hpp"

template <typename Rep, typename Period>
__forceinline static void wait(std::chrono::duration<Rep, Period> duration) noexcept
{
	std::this_thread::sleep_for(duration);
}

static bool ReadFile(const char* path, std::vector<std::uint8_t>& out)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file)
	{
		return false;
	}

	std::streamsize size = file.tellg();
	if (size <= 0)
	{
		return false;
	}

	file.seekg(0, std::ios::beg);

	out.resize(static_cast<size_t>(size));
	if (!file.read(reinterpret_cast<char*>(out.data()), size))
	{
		return false;
	}

	return true;
}

int main(int argc, char* argv[]) {

	if (argc < 2)
	{
		printf("Usage: %s <path_to_pe_file>\n", argv[0]);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	std::vector<std::uint8_t> bytes;
	if (!ReadFile(argv[1], bytes))
	{
		printf("Failed to read file: %s\n", argv[1]);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	PE::Image image(std::move(bytes));
	PE::ImageSections pe_sections(&image);
	PE::Utils pe_utils(&image);

	// - PE::Image

	printf("IsValid():             %s\n", image.IsValid() ? "true" : "false");
	printf("GetValidationIssues(): 0x%08X\n", static_cast<std::uint32_t>(image.GetValidationIssues()));

	printf("\n");

	auto* dos_header = image.GetDOSHeader();
	printf("GetDOSHeader():        %s\n", dos_header ? "non-null" : "null");
	if (dos_header)
	{
		printf("  e_magic:  0x%04X\n", dos_header->e_magic);
		printf("  e_lfanew: 0x%08X\n", dos_header->e_lfanew);
	}
	printf("\n");

	if (image.IsPE32())
	{
		printf(" -> PE32\n");
		auto* nt32 = image.GetNTHeaders<PE::ImageNtHeaders32>();
		printf("GetNTHeaders<32>():        %s\n", nt32 ? "non-null" : "null");

		auto* opt32 = image.GetOptionalHeader<PE::ImageOptionalHeader32>();
		printf("GetOptionalHeader<32>():   %s\n", opt32 ? "non-null" : "null");
		if (opt32)
		{
			printf("  ImageBase:      0x%08X\n", opt32->ImageBase);
			printf("  AddressOfEntry: 0x%08X\n", opt32->AddressOfEntryPoint);
		}
	}
	else if (image.IsPE64())
	{
		printf(" -> PE64\n");
		auto* nt64 = image.GetNTHeaders<PE::ImageNtHeaders64>();
		printf("GetNTHeaders<64>():        %s\n", nt64 ? "non-null" : "null");

		auto* opt64 = image.GetOptionalHeader<PE::ImageOptionalHeader64>();
		printf("GetOptionalHeader<64>():   %s\n", opt64 ? "non-null" : "null");
		if (opt64)
		{
			printf("  ImageBase:      0x%016llX\n", static_cast<unsigned long long>(opt64->ImageBase));
			printf("  AddressOfEntry: 0x%08X\n", opt64->AddressOfEntryPoint);
		}
	}
	else
	{
		printf("GetNTHeaders<>() & GetOptionalHeader<>(): skipped\n");
	}

	printf("\n\nData().size():         %zu bytes\n\n", image.Data().size());

	// - PE::ImageSections

	printf("* Sections [%d]: \n", pe_sections.Count());
	for (const auto& section : pe_sections.GetAll())
	{
		printf("  %s: VA=0x%08X, Size=0x%08X\n",
			section->Name,
			section->VirtualAddress,
			section->Misc.VirtualSize
		);
	}
	printf("\n");

	bool added = pe_sections.AddSection(".test1", { 0x67, 0x69 }, IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
	printf("AddSection(\".test1\"): %s\n\n", added ? "true" : "false");

	printf("* Sections [%d]: \n", pe_sections.Count());
	for (const auto& section : pe_sections.GetAll())
	{
		printf("  %s: VA=0x%08X, Size=0x%08X\n",
			section->Name,
			section->VirtualAddress,
			section->Misc.VirtualSize
		);
	}
	printf("\n");

	printf("* Validation Issues: \n");
	auto issues = image.GetValidationIssues();
	printf("      BadDOSSignature:       %s\n", HasIssue(issues, ValidationIssue::BadDOSSignature) ? "set" : "-");
	printf("      ELfanewOOB:            %s\n", HasIssue(issues, ValidationIssue::ELfanewOOB) ? "set" : "-");
	printf("      BadNTSignature:        %s\n", HasIssue(issues, ValidationIssue::BadNTSignature) ? "set" : "-");
	printf("      BadSectionCount:       %s\n", HasIssue(issues, ValidationIssue::BadSectionCount) ? "set" : "-");
	printf("      OptionalHeaderOOB:     %s\n", HasIssue(issues, ValidationIssue::OptionalHeaderOOB) ? "set" : "-");
	printf("      SectionTableOOB:       %s\n", HasIssue(issues, ValidationIssue::SectionTableOOB) ? "set" : "-");
	printf("      BadOptionalMagic:      %s\n", HasIssue(issues, ValidationIssue::BadOptionalMagic) ? "set" : "-");
	printf("      BadOptionalHeaderSize: %s\n", HasIssue(issues, ValidationIssue::BadOptionalHeaderSize) ? "set" : "-");

	printf("\n\n");

	system("pause");
	return EXIT_SUCCESS;
}