#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// Base relocation directory: block iteration and entry decoding.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::Relocations relocations(&image);

		fuzz::Consume(relocations.Present());
		fuzz::Consume(relocations.GetBlocks());
		fuzz::Consume(relocations.GetAllEntries());
		fuzz::Consume(relocations.Count());
		if (const auto* table = relocations.GetRawTable())
			fuzz::ConsumeObject(*table);

		fuzz::Consume(PE::Relocations::TypeToString(fuzz::ParamU16(data, size, 0)));
	}
	catch (...)
	{
	}

	return 0;
}
