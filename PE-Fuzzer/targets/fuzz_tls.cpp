#include "common.hpp"
#include "image.hpp"
#include "directories.hpp"

// TLS directory: 32/64-bit variants and callback array walking.

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size)
{
	if (!fuzz::InputInRange(size))
		return 0;

	try
	{
		PE::Image image(data, size);
		PE::TLS tls(&image);

		fuzz::Consume(tls.Present());
		fuzz::Consume(tls.GetInfo());
		fuzz::Consume(tls.GetCallbacks());
		fuzz::Consume(tls.HasCallbacks());
		fuzz::Consume(tls.CallbackCount());

		if (const auto* dir32 = tls.GetDirectory<PE::ImageTlsDirectory32>())
			fuzz::ConsumeObject(*dir32);
		if (const auto* dir64 = tls.GetDirectory<PE::ImageTlsDirectory64>())
			fuzz::ConsumeObject(*dir64);
	}
	catch (...)
	{
	}

	return 0;
}
