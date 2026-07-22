#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// Image construction, header validation, and the data directory table.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		fuzz::Consume(image.IsValid());
		fuzz::Consume(image.IsPE32());
		fuzz::Consume(image.IsPE64());

		if (image.IsValid())
			fuzz::ConsumeObject(*image.GetDOSHeader());

		if (const auto* nt = image.GetNTHeaders<PE::ImageNtHeaders32>())
			fuzz::ConsumeObject(*nt);
		if (const auto* nt = image.GetNTHeaders<PE::ImageNtHeaders64>())
			fuzz::ConsumeObject(*nt);
		if (const auto* opt = image.GetOptionalHeader<PE::ImageOptionalHeader32>())
			fuzz::ConsumeObject(*opt);
		if (const auto* opt = image.GetOptionalHeader<PE::ImageOptionalHeader64>())
			fuzz::ConsumeObject(*opt);

		PE::DataDirectory directory(&image);
		for (std::uint16_t i = 0; i < 16; ++i)
		{
			fuzz::Consume(directory.Present(i));
			if (const auto* entry = directory.Get(i))
				fuzz::ConsumeObject(*entry);
		}

		// Out-of-range indices exist
		const std::uint16_t index = fuzz::ParamU16(data, size, 0);
		fuzz::Consume(directory.Present(index));
		fuzz::Consume(directory.Get(index));

		if (const auto* import_dir = directory.GetDirectory<PE::ImageImportDescriptor>(IMAGE_DIRECTORY_ENTRY_IMPORT))
			fuzz::ConsumeObject(*import_dir);
	}
	catch (...)
	{
	}

	return 0;
}
