#include <cstdio>
#include <thread>

#include "PE.hpp"

// Only here for the example (feel free to skid)
template <typename Rep, typename Period>
__forceinline static void wait(std::chrono::duration<Rep, Period> duration) noexcept
{
	std::this_thread::sleep_for(duration);
}

// Example usage

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: %s <path to PE file>\n", argv[0]);
		wait(std::chrono::seconds(3));
		return 1;
	}

	const char* file_path = argv[1];

	// Loading the PE file
	PE::Image image(file_path);

	// Check if the PE file is valid
	if (image.IsValid())
	{
		printf("Successfully loaded PE file: %s\n\n", file_path);

		// Determine if it's PE32 or PE32+
		if (image.IsPE32())
		{
			printf("The file is PE32 (32-bit)\n");

			// Get headers
			auto nt_headers = image._NT().Get<IMAGE_NT_HEADERS32>();
			auto optional_headers = image._OPTIONAL().Get<IMAGE_OPTIONAL_HEADER32>();

			// Display some stuff from both headers
			printf("NT Headers Signature: 0x%X\n", nt_headers->Signature);
			printf("Optional Header ImageBase: 0x%X\n\n", optional_headers->ImageBase);

		}
		else if (image.IsPE64())
		{
			printf("The file is PE32+ (64-bit)\n");

			// Get headers
			auto nt_headers = image._NT().Get<IMAGE_NT_HEADERS64>();
			auto optional_headers = image._OPTIONAL().Get<IMAGE_OPTIONAL_HEADER64>();

			// Display something from both headers
			printf("NT Headers Signature: 0x%X\n", nt_headers->Signature);
			printf("Optional Header ImageBase: 0x%llX\n\n", optional_headers->ImageBase);
		}
		else
		{
			printf("The file is a valid PE but neither PE32 nor PE32+.\n");

		}
	}
	else
	{
		printf("Mane wtf it failed to load or validate the PE file: %s\n", file_path);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	// Get the DOS header
	auto dos_header = image._DOS().Get();
	if (dos_header)
	{
		printf("DOS Header e_magic: 0x%X\n", dos_header->e_magic);
		printf("DOS Header e_lfanew: 0x%X\n", dos_header->e_lfanew);
	}
	else
	{
		printf("Couldn't retrieve DOS header.\n");
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	// Get a section by name (e.g., ".data")
	PE::Sections text_section(&image);
	auto section_header = text_section.Get(".data");
	if (section_header)
	{
		printf("* .data section:\n");
		printf("     Virtual Address: 0x%X\n", section_header->VirtualAddress);
		printf("     Size of Raw Data: 0x%X\n", section_header->SizeOfRawData);
	}
	else
	{
		printf("Couldn't find .data section.\n");
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	// Or display all sections

	printf("\n");
	PE::Sections sections(&image);
	auto section_names = sections.List();

	for (const auto& name : section_names)
	{
		printf("* Section: %.*s\n", IMAGE_SIZEOF_SHORT_NAME, name.data());
	}
	printf("\n");

	system("pause");
	return EXIT_SUCCESS;
}