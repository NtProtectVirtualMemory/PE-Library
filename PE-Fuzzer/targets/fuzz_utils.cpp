#include "common.hpp"
#include "image.hpp"

// Utils: RVA/VA/offset conversions, string extraction, pattern scanning.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::Utils utils(&image);

		fuzz::Consume(utils.RvaToOffset(fuzz::ParamU32(data, size, 0)));
		fuzz::Consume(utils.OffsetToRva(fuzz::ParamU32(data, size, 1)));
		fuzz::Consume(utils.VaToRva(fuzz::ParamU64(data, size, 1)));

		// Round-trip through a real in-file offset, not just noise.
		const auto offset = static_cast<std::uint32_t>(fuzz::ParamU32(data, size, 4) % size);
		fuzz::Consume(utils.RvaToOffset(utils.OffsetToRva(offset)));

		const std::uint32_t min_length = 4 + fuzz::ParamU8(data, size, 20) % 12;
		fuzz::Consume(utils.GetAsciiStrings(min_length));
		fuzz::Consume(utils.GetUnicodeStrings(min_length));

		// PatternScan compares strlen(pattern) to strlen(mask), so pattern
		// bytes must be non-zero and both buffers NUL-terminated.
		char pattern[9]{};
		char mask[9]{};
		const std::size_t length = 4 + fuzz::ParamU8(data, size, 21) % 5;
		for (std::size_t i = 0; i < length; ++i)
		{
			const std::uint8_t byte = fuzz::ParamU8(data, size, 24 + i);
			pattern[i] = static_cast<char>(byte ? byte : 0x90);
			mask[i] = (byte & 1) ? 'x' : '?';
		}

		uintptr_t found = 0;
		fuzz::Consume(utils.PatternScan(pattern, mask, &found));
		fuzz::Consume(found);
	}
	catch (...)
	{
	}

	return 0;
}
