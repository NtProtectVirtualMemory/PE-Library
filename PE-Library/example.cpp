#include <cstdio>
#include <thread>

#include "premier/image.hpp"
// #include "premier/rich.hpp"
// #include "premier/sections.hpp"
// #include "premier/directories.hpp"

template <typename Rep, typename Period>
__forceinline static void wait(std::chrono::duration<Rep, Period> duration) noexcept
{
	std::this_thread::sleep_for(duration);
}

int main(int argc, char* argv[]) {

	if (argc < 2)
	{
		printf("Usage: %s <path_to_pe_file>\n", argv[0]);
		wait(std::chrono::seconds(3));
		return EXIT_FAILURE;
	}

	// Examples go here :thinking:

	printf("\n\n");
	system("pause");
	return EXIT_SUCCESS;
}