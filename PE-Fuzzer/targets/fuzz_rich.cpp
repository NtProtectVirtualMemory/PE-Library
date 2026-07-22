#include "common.hpp"
#include "image.hpp"
#include "rich.hpp"

// Rich header: location, checksum validation, entry decoding.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::RichHeader rich(&image);

		fuzz::Consume(rich.GetChecksum());
		fuzz::Consume(rich.GetRawOffset());
		fuzz::Consume(rich.GetEntries());
		fuzz::Consume(rich.GetRawSize(true));
		fuzz::Consume(rich.GetRawSize(false));

		fuzz::Consume(PE::RichHeader::ProductIdToString(fuzz::ParamU16(data, size, 0)));
	}
	catch (...)
	{
	}

	return 0;
}
