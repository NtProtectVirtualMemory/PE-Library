#include <fstream>
#include "PE.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
	if (Size < 64 || Size > 50'000'000) {
		return 0;
	}

	try {
		PE::Image pe_image(Data, Size);

		if (pe_image.IsValid())
		{
			// DOS Header
			(void)pe_image.DosHeader().Get();

			// NT Headers
			if (pe_image.IsPE64()) {
				(void)pe_image.NtHeaders().Get<IMAGE_NT_HEADERS64>();
				(void)pe_image.OptionalHeader().Get<IMAGE_OPTIONAL_HEADER64>();
			}
			else if (pe_image.IsPE32()) {
				(void)pe_image.NtHeaders().Get<IMAGE_NT_HEADERS32>();
				(void)pe_image.OptionalHeader().Get<IMAGE_OPTIONAL_HEADER32>();
			}

			// Sections
			(void)pe_image.Sections().Count();
			(void)pe_image.Sections().List();
			(void)pe_image.Sections().GetAll();
			(void)pe_image.Sections().GetByName(".text");
			(void)pe_image.Sections().GetByIndex(0);

			// Data Directory
			for (WORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
				(void)pe_image.DataDirectory().Get(i);
				(void)pe_image.DataDirectory().Exists(i);
			}

			// Imports
			if (pe_image.Imports().Present()) {
				(void)pe_image.Imports().GetImportedModules();
				(void)pe_image.Imports().GetAllImports();
				(void)pe_image.Imports().GetDescriptors();
				(void)pe_image.Imports().GetModuleCount();
				(void)pe_image.Imports().FunctionFromModule("kernel32.dll");
			}

			// Exports
			if (pe_image.Exports().Present()) {
				(void)pe_image.Exports().ModuleName();
				(void)pe_image.Exports().All();
				(void)pe_image.Exports().ByName("DllMain");
				(void)pe_image.Exports().ByOrdinal(1);
				(void)pe_image.Exports().Count();
				(void)pe_image.Exports().GetDescriptor();
			}

			// Relocations
			if (pe_image.Relocations().Present()) {
				(void)pe_image.Relocations().GetBlocks();
				(void)pe_image.Relocations().GetAllEntries();
				(void)pe_image.Relocations().Count();
				(void)pe_image.Relocations().GetRawTable();
			}

			// TLS
			if (pe_image.TLS().Present()) {
				(void)pe_image.TLS().GetInfo();
				(void)pe_image.TLS().GetCallbacks();
				(void)pe_image.TLS().HasCallbacks();
				(void)pe_image.TLS().CallbackCount();
				if (pe_image.IsPE64()) {
					(void)pe_image.TLS().GetDirectory<IMAGE_TLS_DIRECTORY64>();
				}
				else {
					(void)pe_image.TLS().GetDirectory<IMAGE_TLS_DIRECTORY32>();
				}
			}

			// Resources
			if (pe_image.Resources().Present()) {
				(void)pe_image.Resources().GetAll();
				(void)pe_image.Resources().GetTypeIds();
				(void)pe_image.Resources().Count();
				(void)pe_image.Resources().GetVersionInfo();
				(void)pe_image.Resources().GetManifest();
				(void)pe_image.Resources().GetRootDirectory();
				(void)pe_image.Resources().GetByType(RT_MANIFEST);
			}

			// Rich Header
			if (pe_image.RichHeader().Present()) {
				(void)pe_image.RichHeader().GetEntries();
				(void)pe_image.RichHeader().GetChecksum();
				(void)pe_image.RichHeader().ValidateChecksum();
				(void)pe_image.RichHeader().GetRawOffset();
				(void)pe_image.RichHeader().GetRawSize(true);
				(void)pe_image.RichHeader().GetRawSize(false);
			}

			// Debug
			if (pe_image.Debug().Present()) {
				(void)pe_image.Debug().GetAll();
				(void)pe_image.Debug().GetByType(IMAGE_DEBUG_TYPE_CODEVIEW);
				(void)pe_image.Debug().TypeToString(IMAGE_DEBUG_TYPE_CODEVIEW);
			}

			// Utils
			(void)pe_image.Utils().RvaToOffset(0x1000);
			(void)pe_image.Utils().VaToRva(0x10001000);
			(void)pe_image.Utils().OffsetToRva(0x400);
			(void)pe_image.Utils().GetAsciiStrings(4);
			(void)pe_image.Utils().GetUnicodeStrings(4);

			// Data access
			(void)pe_image.Data();
			(void)pe_image.MutableData();

			// Packer detection
			(void)pe_image.Packer().IdentifyPacker();
		}

		// Still call some functions even if invalid
		(void)pe_image.IsPE32();
		(void)pe_image.IsPE64();
	}
	catch (...) {

	}

	return 0;
}