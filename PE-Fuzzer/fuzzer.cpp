
#include "image.hpp"
#include "rich.hpp"
#include "sections.hpp"
#include "directories.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	if (size < 64 || size > 50'000'000) {
		return 0;
	}

	try {

		PE::Image pe_image(data, size);

		// DataDirectory
		PE::DataDirectory data_directory(&pe_image);
		for (std::uint16_t i = 0; i < 16; ++i) {
			(void)data_directory.Exists(i);
			(void)data_directory.Get(i);
		}

		(void)data_directory.GetDirectory <PE::ImageImportDescriptor> (IMAGE_DIRECTORY_ENTRY_IMPORT);

		// Imports
		PE::Imports imports(&pe_image);
		(void)imports.Present();
		(void)imports.GetImportedModules();
		(void)imports.GetAllImports();
		(void)imports.FunctionFromModule("kernel32.dll");
		(void)imports.GetDescriptors();
		(void)imports.GetModuleCount();

		// Exports
		PE::Exports exports(&pe_image);
		(void)exports.Present();
		(void)exports.ModuleName();
		(void)exports.All();
		(void)exports.ByName("DllMain");
		(void)exports.ByOrdinal(1);
		(void)exports.Count();
		(void)exports.GetDescriptor();

		// Relocations
		PE::Relocations relocations(&pe_image);
		(void)relocations.Present();
		(void)relocations.GetBlocks();
		(void)relocations.GetAllEntries();
		(void)relocations.Count();
		(void)relocations.GetRawTable();
		(void)PE::Relocations::TypeToString(3);

		// TLS
		PE::TLS tls(&pe_image);
		(void)tls.Present();
		(void)tls.GetInfo();
		(void)tls.GetCallbacks();
		(void)tls.HasCallbacks();
		(void)tls.CallbackCount();
		(void)tls.GetDirectory<PE::ImageTlsDirectory32>();
		(void)tls.GetDirectory<PE::ImageTlsDirectory64>();

		// Resources
		PE::Resources resources(&pe_image);
		(void)resources.Present();
		(void)resources.GetAll();
		(void)resources.GetByType(1);
		(void)resources.GetTypeIds();
		(void)resources.Count();
		(void)resources.GetVersionInfo();
		(void)resources.GetManifest();
		if (auto entries = resources.GetAll(); !entries.empty()) {
			(void)resources.GetResourceData(entries[0]);
		}
		(void)resources.GetRootDirectory();
		(void)PE::Resources::TypeToString(1);

		// Debug
		PE::Debug debug(&pe_image);
		(void)debug.Present();
		(void)debug.GetAll();
		(void)debug.GetByType(1);
		(void)debug.TypeToString(1);

	}
	catch (...) {

	}

	return 0;
}