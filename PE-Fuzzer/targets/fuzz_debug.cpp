#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// Debug directory: entry enumeration and type lookup.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::Debug debug(&image);

		fuzz::Consume(debug.Present());
		fuzz::Consume(debug.GetAll());
		fuzz::Consume(debug.GetByType(fuzz::ParamU16(data, size, 0)));
		fuzz::Consume(debug.TypeToString(fuzz::ParamU16(data, size, 1)));
	}
	catch (...)
	{
	}

	return 0;
}
