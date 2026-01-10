#include <cstdio>
#include <thread>

#include "PE.hpp"

// Only here for the example (feel free to skid)
template <typename Rep, typename Period>
__forceinline static void wait(std::chrono::duration<Rep, Period> duration) noexcept
{
	std::this_thread::sleep_for(duration);
}

// Example usage

int main(int argc, char* argv[]) {

	if (argc < 2)
	{
		printf("Usage: %s <path_to_pe_file>\n", argv[0]);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	const char* file_path = argv[1];

	// Loading the PE file
	PE::Image image(file_path);

	// Check if the PE file is valid
	if (image.IsValid())
	{
		printf("Successfully loaded PE file: %s\n\n", file_path);

		// Determine if it's PE32 or PE32+
		if (image.IsPE32())
		{
			printf("The file is PE32 (32-bit)\n");

			// Get headers
			auto nt_headers = image.NtHeaders().Get<IMAGE_NT_HEADERS32>();
			auto optional_headers = image.OptionalHeader().Get<IMAGE_OPTIONAL_HEADER32>();

			// Display some stuff from both headers
			printf("NT Headers Signature: 0x%X\n", nt_headers->Signature);
			printf("Optional Header ImageBase: 0x%X\n\n", optional_headers->ImageBase);
		}
		else if (image.IsPE64())
		{
			printf("The file is PE32+ (64-bit)\n");

			// Get headers
			auto nt_headers = image.NtHeaders().Get<IMAGE_NT_HEADERS64>();
			auto optional_headers = image.OptionalHeader().Get<IMAGE_OPTIONAL_HEADER64>();

			// Display something from both headers
			printf("NT Headers Signature: 0x%X\n", nt_headers->Signature);
			printf("Optional Header ImageBase: 0x%llX\n\n", optional_headers->ImageBase);
		}
		else
		{
			printf("The file is a valid PE but neither PE32 nor PE32+.\n");
		}
	}
	else
	{
		printf("Mane wtf it failed to load or validate the PE file: %s\n", file_path);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	// Get the DOS header
	auto dos_header = image.DosHeader().Get();
	if (dos_header)
	{
		printf("DOS Header e_magic: 0x%X\n", dos_header->e_magic);
		printf("DOS Header e_lfanew: 0x%X\n", dos_header->e_lfanew);
	}
	else
	{
		printf("Couldn't retrieve DOS header.\n");
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	printf("Sections validated successfully.\n\n");

	// Get a section by name (e.g., ".data")
	auto section_header = image.Sections().GetByName(".data");
	if (section_header)
	{
		printf("* .data section:\n");
		printf("     Virtual Address: 0x%X\n", section_header->VirtualAddress);
		printf("     Size of Raw Data: 0x%X\n", section_header->SizeOfRawData);
	}
	else
	{
		// Im making this non fatal for a crash, because not all PE's have it
		printf("Couldn't find .data section.\n");
	}

	// Display all sections
	printf("\n");
	auto section_names = image.Sections().List();
	for (const auto& name : section_names)
	{
		printf("* Section: %.*s\n", static_cast<int>(IMAGE_SIZEOF_SHORT_NAME), name.data());
	}

	// Display imports (IAT)
	printf("\nDisplaying IAT\n");
	if (image.Imports().Present())
	{
		printf("Number of imported DLLs: %zu\n\n", image.Imports().GetModuleCount());

		auto all_imports = image.Imports().GetAllImports();
		for (const auto& entry : all_imports)
		{
			printf("[%s] (%zu fn per Dll)\n", entry.dll_name.data(), entry.functions.size());

			for (const auto& func : entry.functions)
			{
				if (func.is_ordinal)
				{
					printf("    [Ordinal] %u\n", func.ordinal);
				}
				else
				{
					printf("    [%04X] %s\n", func.hint, func.name.data());
				}
			}

			printf("\n");
		}
	}
	else
	{
		printf("No imports found.\n");
	}

	printf("\nDisplaying Exports\n");
	if (image.Exports().Present())
	{
		printf("Module name: %s\n", image.Exports().ModuleName().data());
		printf("Export count: %zu\n\n", image.Exports().Count());

		auto all_exports = image.Exports().All();
		for (const auto& exp : all_exports)
		{
			if (exp.is_forwarded)
			{
				printf("  [%04X] %s -> %s (forwarded)\n",
					exp.ordinal,
					exp.name.empty() ? "(no name)" : exp.name.data(),
					exp.forward_name.data());
			}
			else
			{
				printf("  [%04X] %s @ RVA: 0x%08X | VA: 0x%llX | File: 0x%08X\n",
					exp.ordinal,
					exp.name.empty() ? "(no name)" : exp.name.data(),
					exp.rva,
					exp.va,
					exp.file_offset);
			}
		}

		printf("\nTrying to Lookup by Name\n");
		auto found = image.Exports().ByName("DllMain");
		if (!found.name.empty())
		{
			printf("Found DllMain @ RVA: 0x%08X\n", found.rva);
		}
		else
		{
			printf("DllMain not found\n");
		}
	}
	else
	{
		printf("No exports found (No Worries, this is normal)\n");
	}

	// Display Relocations
	printf("\nDisplaying Relocations\n");
	if (image.Relocations().Present())
	{
		printf("Total relocation entries: %zu\n\n", image.Relocations().Count());

		auto blocks = image.Relocations().GetBlocks();
		printf("Number of relocation blocks: %zu\n\n", blocks.size());

		// Show first few blocks
		size_t blocks_to_show = blocks.size() > 5 ? 5 : blocks.size();
		for (size_t i = 0; i < blocks_to_show; ++i)
		{
			const auto& block = blocks[i];
			printf("  Block @ Page RVA: 0x%08X (%zu entries)\n", block.page_rva, block.entries.size());

			// Show first few entries per block
			size_t entries_to_show = block.entries.size() > 3 ? 3 : block.entries.size();
			for (size_t j = 0; j < entries_to_show; ++j)
			{
				const auto& entry = block.entries[j];
				printf("    RVA: 0x%08X | Type: %s | File: 0x%08X\n",
					entry.rva,
					PE::_Relocations::TypeToString(entry.type).data(),
					entry.file_offset);
			}

			if (block.entries.size() > 3)
			{
				printf("    ... and %zu more entries\n", block.entries.size() - 3);
			}
		}

		if (blocks.size() > 5)
		{
			printf("\n  ... and %zu more blocks\n", blocks.size() - 5);
		}
	}
	else
	{
		printf("No relocations found.\n");
	}

	// Display TLS
	printf("\nDisplaying TLS\n");
	if (image.TLS().Present())
	{
		auto tls_info = image.TLS().GetInfo();

		printf("TLS Directory:\n");
		printf("  Raw Data Start VA:  0x%llX\n", tls_info.raw_data_start_va);
		printf("  Raw Data End VA:    0x%llX\n", tls_info.raw_data_end_va);
		printf("  Raw Data Size:      0x%X\n", tls_info.raw_data_size);
		printf("  Index VA:           0x%llX\n", tls_info.index_va);
		printf("  Callbacks VA:       0x%llX\n", tls_info.callbacks_va);
		printf("  Zero Fill Size:     0x%X\n", tls_info.zero_fill_size);
		printf("  Characteristics:    0x%X\n", tls_info.characteristics);

		if (image.TLS().HasCallbacks())
		{
			auto callbacks = image.TLS().GetCallbacks();
			printf("\n  TLS Callbacks (%zu):\n", callbacks.size());

			for (const auto& cb : callbacks)
			{
				printf("    VA: 0x%llX | RVA: 0x%08X | File: 0x%08X\n",
					cb.va, cb.rva, cb.file_offset);
			}
		}
		else
		{
			printf("\n  No TLS callbacks registered.\n");
		}
	}
	else
	{
		printf("No TLS directory found.\n");
	}

	// Display Resources
	printf("\nDisplaying Resources\n");
	if (image.Resources().Present())
	{
		printf("Total resource entries: %zu\n\n", image.Resources().Count());

		auto type_ids = image.Resources().GetTypeIds();
		printf("Resource types present: ");
		for (size_t i = 0; i < type_ids.size(); ++i)
		{
			printf("%s (%u)", PE::_Resources::TypeToString(type_ids[i]).data(), type_ids[i]);
			if (i < type_ids.size() - 1)
				printf(", ");
		}
		printf("\n\n");

		auto all_resources = image.Resources().GetAll();
		for (const auto& res : all_resources)
		{
			const char* type_str = res.type_name.empty()
				? PE::_Resources::TypeToString(res.type_id).data()
				: res.type_name.c_str();

			printf("  [%s] ID: %u | Lang: 0x%04X | Size: 0x%X | RVA: 0x%08X\n",
				type_str,
				res.resource_id,
				res.language_id,
				res.data_size,
				res.data_rva);
		}

		// Try to get version info
		auto version = image.Resources().GetVersionInfo();
		if (version.has_value())
		{
			printf("\n  Version Info:\n");
			printf("    File Version:    %u.%u.%u.%u\n",
				version->major, version->minor, version->build, version->revision);
			printf("    Product Version: %u.%u.%u.%u\n",
				version->product_major, version->product_minor,
				version->product_build, version->product_revision);
			printf("    File OS:         0x%08X\n", version->file_os);
			printf("    File Type:       0x%08X\n", version->file_type);
		}

		// Try to get manifest
		auto manifest = image.Resources().GetManifest();
		if (!manifest.empty())
		{
			printf("\n  Manifest present (%zu bytes)\n", manifest.size());

			// Show first 200 chars of manifest
			size_t preview_len = manifest.size() > 200 ? 200 : manifest.size();
			printf("  Preview: %.200s", manifest.data());
			if (manifest.size() > 200)
			{
				printf("...\n");
			}
			else
			{
				printf("\n");
			}
		}
	}
	else
	{
		printf("No resources found.\n");
	}

	printf("\nDisplaying Rich Header\n");
	if (image.RichHeader().Present())
	{
		printf("Rich Header found!\n");
		printf("  Offset:   0x%08X\n", image.RichHeader().GetRawOffset());
		printf("  Size:     0x%08X (Rich Structure)\n", image.RichHeader().GetRawSize(false));
		printf("  Size:     0x%08X (DOS Stub region)\n", image.RichHeader().GetRawSize(true));
		printf("  Checksum: 0x%08X\n", image.RichHeader().GetChecksum());
		printf("  Valid:    %s\n\n", image.RichHeader().ValidateChecksum() ? "Yes" : "No");

		auto entries = image.RichHeader().GetEntries();
		printf("  Tool entries (%zu):\n", entries.size());

		for (const auto& entry : entries)
		{
			printf("    [%s] Build: %u | Count: %u\n",
				PE::_RichHeader::ProductIdToString(entry.product_id).data(),
				entry.build_id,
				entry.use_count);
		}
	}
	else
	{
		printf("No Rich Header found (may be stripped or non-MSVC build).\n");
	}

	// Getting strings
	auto ascii_strings = image.Utils().GetAsciiStrings(3);
	auto unicode_strings = image.Utils().GetUnicodeStrings(5);

	printf("\n* Found %zu ASCII strings (min length 3):\n\n", ascii_strings.size());
	for (const auto& str : ascii_strings)
	{
		printf("  %.*s\n", static_cast<int>(str.size()), str.data());
	}

	printf("\n* Found %zu Unicode strings (min length 5):\n\n", unicode_strings.size());
	for (const auto& str : unicode_strings)
	{
		printf("  %.*S\n", static_cast<int>(str.size()), str.data());
	}

	// Get all debug entries
	printf("\nDisplaying Debug Entries\n");
	std::vector<DebugEntry> debug_entries = image.Debug().GetAll();

	if (!debug_entries.empty())
	{
		printf("Total debug entries: %zu\n\n", debug_entries.size());
		for (const auto& dbg : debug_entries)
		{
			printf("  Type: %s (%u) | Size: 0x%X | File Offset: 0x%X | RVA: 0x%X\n",
				image.Debug().TypeToString(dbg.type).data(),
				dbg.type,
				dbg.size,
				dbg.address_offset,
				dbg.address_rva);
		}
	}
	else
	{
		printf("No debug entries found.\n");
	}

	// Save image
	if (image.SaveImage(file_path))
	{
		printf(" - Image saved successfully to: %s\n", file_path);
	}
	else
	{
		printf(" - Failed to save image to: %s\n", file_path);
	}

	// Identify packer (if any)
	printf("\nIdentifying Packer\n");
	PackerInfo packer_info = image.Packer().IdentifyPacker();

	if (packer_info.packed)
	{
		printf(" - Packer detected: %s\n", packer_info.name.data());
		printf(" - Entropy Score: %.2f\n", packer_info.entropy_score);
		printf(" - Detection Method: %s\n", packer_info.detection_method.data());
		printf(" - Confidence Level: %u%%\n", static_cast<unsigned int>(packer_info.confidence));
	}
	else
	{
		printf(" - No packer detected.\n");
	}

	printf("\n");
	system("pause");
	return EXIT_SUCCESS;
}