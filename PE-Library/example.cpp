#include <cstdio>
#include <thread>
#include "PE.hpp"

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("Usage: %s <path to PE file>\n", argv[0]);
		return 1;
	}

	const char* file_path = argv[1];
	PE::Image image(file_path);

	if (image.IsPEFile()) {
		printf("The file is a valid PE file.\n");
	}
	else {
		printf("The file is NOT a valid PE file.\n");
	}

	std::this_thread::sleep_for(std::chrono::seconds(5));
	return 0;
}