#include "PE.hpp"

/* PE.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/


/*
* @brief Constructs a PE::Image object from a file
* @param Path to the file
* @return none
*/
PE::Image::Image(const char* path)
{
	FILE* file = nullptr;
	fopen_s(&file, path, "rb");

	if (!file)
		return;

	fseek(file, 0, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	m_data.resize(file_size);
	fread(m_data.data(), 1, file_size, file);
	fclose(file);

	if (Validate())
	{
		auto nt_headers = _NT().Get32();
		if (nt_headers)
			m_magic = nt_headers->OptionalHeader.Magic;
	}
}

bool PE::Image::Validate() noexcept
{
	if (m_data.size() < sizeof(IMAGE_DOS_HEADER))
		return false;

	auto dos_header = _DOS().Get();
	if (!dos_header || dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	if (m_data.size() < dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS32)) // Was crim here?
		return false;

	m_valid = true;
	return true;
}

PIMAGE_DOS_HEADER PE::DosHeader::Get() noexcept
{
	if (!m_image || m_image->Data().empty())
		return nullptr;
	
	return reinterpret_cast<PIMAGE_DOS_HEADER>(m_image->Data().data());
}

PIMAGE_NT_HEADERS32 PE::NtHeaders::Get32() noexcept
{
	if (!m_image)
		return nullptr;

	auto dos_header = m_image->_DOS().Get();
	if (!dos_header || m_image->Data().empty())
		return nullptr;

	return reinterpret_cast<PIMAGE_NT_HEADERS32>(m_image->Data().data() + dos_header->e_lfanew);
}

PIMAGE_NT_HEADERS64 PE::NtHeaders::Get64() noexcept
{
	if (!m_image)
		return nullptr;

	auto dos_header = m_image->_DOS().Get();
	if (!dos_header || m_image->Data().empty())
		return nullptr;

	return reinterpret_cast<PIMAGE_NT_HEADERS64>(m_image->Data().data() + dos_header->e_lfanew);
}

PIMAGE_OPTIONAL_HEADER32 PE::OptionalHeader::Get32() noexcept
{
	if (!m_image)
		return nullptr;

	auto nt_headers = m_image->_NT().Get32();
	return nt_headers ? &nt_headers->OptionalHeader : nullptr;
}

PIMAGE_OPTIONAL_HEADER64 PE::OptionalHeader::Get64() noexcept
{
	if (!m_image)
		return nullptr;

	auto nt_headers = m_image->_NT().Get64();
	return nt_headers ? &nt_headers->OptionalHeader : nullptr;
}
