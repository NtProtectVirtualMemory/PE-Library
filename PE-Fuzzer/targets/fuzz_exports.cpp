#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// Export directory: name/ordinal tables, forwarders, lookups.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::Exports exports(&image);

		fuzz::Consume(exports.Present());
		fuzz::Consume(exports.ModuleName());
		fuzz::Consume(exports.All());
		fuzz::Consume(exports.Count());
		if (const auto* descriptor = exports.GetDescriptor())
			fuzz::ConsumeObject(*descriptor);

		fuzz::Consume(exports.ByOrdinal(fuzz::ParamU16(data, size, 0)));

		const fuzz::ParamName name(data, size, 2);
		fuzz::Consume(exports.ByName(name.value));
		fuzz::Consume(exports.ByName("DllMain"));
	}
	catch (...)
	{
	}

	return 0;
}
