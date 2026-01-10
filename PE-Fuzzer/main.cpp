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
			pe_image.DosHeader().Get();

			// NT Headers
			if (pe_image.IsPE64()) {
				pe_image.NtHeaders().Get<IMAGE_NT_HEADERS64>();
				pe_image.OptionalHeader().Get<IMAGE_OPTIONAL_HEADER64>();
			}
			else if (pe_image.IsPE32()) {
				pe_image.NtHeaders().Get<IMAGE_NT_HEADERS32>();
				pe_image.OptionalHeader().Get<IMAGE_OPTIONAL_HEADER32>();
			}

			// Sections
			pe_image.Sections().Count();
			pe_image.Sections().List();
			pe_image.Sections().GetAll();
			pe_image.Sections().GetByName(".text");
			pe_image.Sections().GetByIndex(0);

			// Data Directory
			for (WORD i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
				pe_image.DataDirectory().Get(i);
				pe_image.DataDirectory().Exists(i);
			}

			// Imports
			if (pe_image.Imports().Present()) {
				pe_image.Imports().GetImportedModules();
				pe_image.Imports().GetAllImports();
				pe_image.Imports().GetDescriptors();
				pe_image.Imports().GetModuleCount();
				pe_image.Imports().FunctionFromModule("kernel32.dll");
			}

			// Exports
			if (pe_image.Exports().Present()) {
				pe_image.Exports().ModuleName();
				pe_image.Exports().All();
				pe_image.Exports().ByName("DllMain");
				pe_image.Exports().ByOrdinal(1);
				pe_image.Exports().Count();
				pe_image.Exports().GetDescriptor();
			}

			// Relocations
			if (pe_image.Relocations().Present()) {
				pe_image.Relocations().GetBlocks();
				pe_image.Relocations().GetAllEntries();
				pe_image.Relocations().Count();
				pe_image.Relocations().GetRawTable();
			}

			// TLS
			if (pe_image.TLS().Present()) {
				pe_image.TLS().GetInfo();
				pe_image.TLS().GetCallbacks();
				pe_image.TLS().HasCallbacks();
				pe_image.TLS().CallbackCount();
				if (pe_image.IsPE64()) {
					pe_image.TLS().GetDirectory<IMAGE_TLS_DIRECTORY64>();
				}
				else {
					pe_image.TLS().GetDirectory<IMAGE_TLS_DIRECTORY32>();
				}
			}

			// Resources
			if (pe_image.Resources().Present()) {
				pe_image.Resources().GetAll();
				pe_image.Resources().GetTypeIds();
				pe_image.Resources().Count();
				pe_image.Resources().GetVersionInfo();
				pe_image.Resources().GetManifest();
				pe_image.Resources().GetRootDirectory();
				pe_image.Resources().GetByType(RT_MANIFEST);
			}

			// Rich Header
			if (pe_image.RichHeader().Present()) {
				pe_image.RichHeader().GetEntries();
				pe_image.RichHeader().GetChecksum();
				pe_image.RichHeader().ValidateChecksum();
				pe_image.RichHeader().GetRawOffset();
				pe_image.RichHeader().GetRawSize(true);
				pe_image.RichHeader().GetRawSize(false);
			}

			// Debug
			if (pe_image.Debug().Present()) {
				pe_image.Debug().GetAll();
				pe_image.Debug().GetByType(IMAGE_DEBUG_TYPE_CODEVIEW);
				pe_image.Debug().TypeToString(IMAGE_DEBUG_TYPE_CODEVIEW);
			}

			// Utils
			pe_image.Utils().RvaToOffset(0x1000);
			pe_image.Utils().VaToRva(0x10001000);
			pe_image.Utils().OffsetToRva(0x400);
			pe_image.Utils().GetAsciiStrings(4);
			pe_image.Utils().GetUnicodeStrings(4);

			// Data access
			pe_image.Data();
			pe_image.MutableData();
		}

		// Still call some functions even if invalid
		pe_image.IsPE32();
		pe_image.IsPE64();
	}
	catch (...) {

	}

	return 0;
}