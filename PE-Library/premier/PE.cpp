#include "PE.hpp"

/* PE.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

// Image constructor
PE::Image::Image(const char* path)
{
	FILE* file = nullptr;
	fopen_s(&file, path, "rb");

	if (!file)
		return;

	fseek(file, 0, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	m_data.resize(file_size); // Allocate memory for the entire file
	fread(m_data.data(), 1, file_size, file);
	fclose(file);

	if (Validate())
	{
		auto nt_headers = _NT().Get<IMAGE_NT_HEADERS32>();
		if (nt_headers)
		{
			m_magic = nt_headers->OptionalHeader.Magic;
		}
	}
}

