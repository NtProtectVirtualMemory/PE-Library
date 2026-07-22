#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// Import directory: descriptors, module list, thunk walking, name lookup.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::Imports imports(&image);

		fuzz::Consume(imports.Present());
		fuzz::Consume(imports.GetImportedModules());
		fuzz::Consume(imports.GetAllImports());
		fuzz::Consume(imports.GetDescriptors());
		fuzz::Consume(imports.GetModuleCount());

		const fuzz::ParamName dll(data, size, 0);
		fuzz::Consume(imports.FunctionFromModule(dll.value));
		fuzz::Consume(imports.FunctionFromModule("kernel32.dll"));
	}
	catch (...)
	{
	}

	return 0;
}
