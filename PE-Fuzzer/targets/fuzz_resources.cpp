#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// Resource directory: tree traversal, version info, manifest, data blobs.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::Resources resources(&image);

		fuzz::Consume(resources.Present());

		const auto entries = resources.GetAll();
		fuzz::Consume(entries);
		fuzz::Consume(resources.GetByType(fuzz::ParamU8(data, size, 0)));
		fuzz::Consume(resources.GetTypeIds());
		fuzz::Consume(resources.Count());

		if (const auto version = resources.GetVersionInfo())
			fuzz::Consume(*version);
		fuzz::Consume(resources.GetManifest());

		if (!entries.empty())
		{
			const auto& entry = entries[fuzz::ParamU16(data, size, 1) % entries.size()];
			fuzz::Consume(resources.GetResourceData(entry));
		}

		if (const auto* root = resources.GetRootDirectory())
			fuzz::ConsumeObject(*root);

		fuzz::Consume(PE::Resources::TypeToString(fuzz::ParamU8(data, size, 6)));
	}
	catch (...)
	{
	}

	return 0;
}
