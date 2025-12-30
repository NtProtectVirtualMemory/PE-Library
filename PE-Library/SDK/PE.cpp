#include "PE.hpp"

/* PE.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

// @brief Normal string constructor
PE::Image::Image(const char* path)
{
	FILE* file = nullptr;
	fopen_s(&file, path, "rb");

	if (!file) {
		return;
	}

	// Get file size
	fseek(file, 0, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	// Load entire file into m_data
	m_data.resize(file_size);
	fread(m_data.data(), 1, file_size, file);
	fclose(file);

	if (IsPEFile())
	{
		m_valid = true;
	}

	return;
}

// @brief Destructor
PE::Image::~Image()
{
	// Destructor logic (i'll think about it)
}

// @brief Checks if the loaded file is a valid PE file
// @param none
// @return true if the file is a valid PE file, false otherwis
bool PE::Image::IsPEFile() noexcept
{
	if (m_data.size() < sizeof(IMAGE_DOS_HEADER))
	{
		return false;
	}

	PIMAGE_DOS_HEADER dos_header = GetDOSHeader();
	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}
	return true;
}
