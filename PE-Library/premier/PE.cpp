#include "PE.hpp"

/* PE.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

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

	ValidateImage();
}

// DOS HEADER

bool PE::_DosHeader::Validate(const std::vector<BYTE>& data) const noexcept
{
	if (data.size() < sizeof(IMAGE_DOS_HEADER))
		return false;

	auto dos_header = Get();
	if (!dos_header)
		return false;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		return false;

	if (dos_header->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)))
		return false;

	if (dos_header->e_lfanew >= static_cast<LONG>(data.size()))
		return false;

	if (static_cast<size_t>(dos_header->e_lfanew) + sizeof(DWORD) > data.size())
		return false;

	return true;
}

// NT HEADERS

bool PE::_NtHeaders::Validate(const std::vector<BYTE>& data) const noexcept
{
	if (!m_image)
		return false;

	auto dos_header = m_image->DosHeader().Get();
	if (!dos_header)
		return false;

	size_t nt_offset = dos_header->e_lfanew;

	if (nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) > data.size())
		return false;

	auto signature = *reinterpret_cast<const DWORD*>(data.data() + nt_offset);
	if (signature != IMAGE_NT_SIGNATURE)
		return false;

	const IMAGE_FILE_HEADER* file_header =
		reinterpret_cast<const IMAGE_FILE_HEADER*>(data.data() + nt_offset + sizeof(DWORD));

	if (file_header->NumberOfSections == 0 || file_header->NumberOfSections > 96)
		return false;

	if (file_header->SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32) &&
		file_header->SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64))
		return false;

	if (nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + file_header->SizeOfOptionalHeader > data.size())
		return false;

	return true;
}

// OPTIONAL HEADER 

bool PE::_OptionalHeader::Validate(const std::vector<BYTE>& data) const noexcept
{
	if (!m_image)
		return false;

	auto dos_header = m_image->DosHeader().Get();
	if (!dos_header)
		return false;

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	if (optional_offset + sizeof(WORD) > data.size())
		return false;

	WORD magic = *reinterpret_cast<const WORD*>(data.data() + optional_offset);

	if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return false;

	size_t optional_header_size = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?
		sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64);

	if (optional_offset + optional_header_size > data.size())
		return false;

	return true;
}

// SECTIONS 

PE::_Sections::_Sections(Image* image) : m_image(image)
{
	if (!m_image || !m_image->IsValid())
		return;

	if (m_image->IsPE64())
	{
		auto nt_headers = m_image->NtHeaders().Get<IMAGE_NT_HEADERS64>();
		if (!nt_headers)
			return;

		m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
		m_sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt_headers));
	}
	else if (m_image->IsPE32())
	{
		auto nt_headers = m_image->NtHeaders().Get<IMAGE_NT_HEADERS32>();
		if (!nt_headers)
			return;

		m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
		m_sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(IMAGE_FIRST_SECTION(nt_headers));
	}
}

bool PE::_Sections::Validate(const std::vector<BYTE>& data) noexcept
{
	/*
	* Will implement later
	*/
	return true;
}