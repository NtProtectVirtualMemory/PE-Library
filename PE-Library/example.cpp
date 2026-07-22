#include <cstdio>
#include <fstream>
#include <thread>
#include <vector>

#include "pe-lib/image.hpp"
#include "pe-lib/rich.hpp"
#include "pe-lib/sections.hpp"
#include "pe-lib/directories.hpp"

template <typename Rep, typename Period>
__forceinline static void wait(std::chrono::duration<Rep, Period> duration) noexcept
{
	std::this_thread::sleep_for(duration);
}

static bool ReadFile(const char* path, std::vector<std::uint8_t>& out)
{
	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (!file)
	{
		return false;
	}

	std::streamsize size = file.tellg();
	if (size <= 0)
	{
		return false;
	}

	file.seekg(0, std::ios::beg);

	out.resize(static_cast<size_t>(size));
	if (!file.read(reinterpret_cast<char*>(out.data()), size))
	{
		return false;
	}

	return true;
}

int main(int argc, char* argv[]) {

	if (argc < 2)
	{
		printf("Usage: %s <path_to_pe_file>\n", argv[0]);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	std::vector<std::uint8_t> bytes;
	if (!ReadFile(argv[1], bytes))
	{
		printf("Failed to read file: %s\n", argv[1]);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	PE::Image image(std::move(bytes));
	PE::ImageSections pe_sections(&image);

	// Examples go here :thinking:

	printf("\n\n");
	system("pause");
	return EXIT_SUCCESS;
}