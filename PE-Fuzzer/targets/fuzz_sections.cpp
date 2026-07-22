#include "common.hpp"
#include "image.hpp"
#include "sections.hpp"

#include <algorithm>

// Section table: validation, lookups, and the AddSection mutation path.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::ImageSections sections(&image);

		fuzz::Consume(sections.IsValid());
		fuzz::Consume(sections.Count());

		for (const auto* header : sections.GetAll())
			if (header)
				fuzz::ConsumeObject(*header);

		fuzz::Consume(sections.GetByName(".text"));
		const fuzz::ParamName name(data, size, 0);
		fuzz::Consume(sections.GetByName(name.value));
		if (const auto* header = sections.GetByIndex(fuzz::ParamU8(data, size, 16)))
			fuzz::ConsumeObject(*header);

		std::uint32_t aligned = 0;
		fuzz::Consume(sections.AlignUp(fuzz::ParamU32(data, size, 5), fuzz::ParamU32(data, size, 6), aligned));
		fuzz::Consume(aligned);

		// Mutation path: append a section built from input bytes, then
		// reparse the section table on the modified image.
		const std::size_t content_size = fuzz::ParamU16(data, size, 14) % 512;
		const std::vector<std::uint8_t> content(data, data + (std::min)(content_size, size));
		const bool added = sections.AddSection(name.value, content, fuzz::ParamU32(data, size, 8));
		fuzz::Consume(added);

		if (added)
		{
			PE::ImageSections reparsed(&image);
			fuzz::Consume(reparsed.IsValid());
			fuzz::Consume(reparsed.Count());
			for (const auto* header : reparsed.GetAll())
				if (header)
					fuzz::ConsumeObject(*header);
		}
	}
	catch (...)
	{
	}

	return 0;
}
