
/* image_impl.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#include "image.hpp"

PE::Image::Image(const char* path)
{
	FILE* file = nullptr;
	fopen_s(&file, path, "rb");

	if (!file)
	{
		return;
	}

	fseek(file, 0, SEEK_END);
	size_t file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	m_data.resize(file_size);
	fread(m_data.data(), 1, file_size, file);
	fclose(file);

	if (ValidateImage())
	{
		m_valid = true;
	}
}

PE::Image::Image(const std::vector<uint8_t> data)
	: m_data(data)
{
	if (ValidateImage())
	{
		m_valid = true;
	}
}

PE::Image::Image(const std::uint8_t * data, size_t size) 
	: m_data(data, data + size)
{
	if (ValidateImage())
	{
		m_valid = true;
	}
}

bool PE::Image::ValidateDOS() const noexcept
{
	if (m_data.size() < sizeof(ImageDosHeader))
	{
		return false;
	}

	auto dos_header = GetDOSHeader();
	if (!dos_header)
	{
		return false;
	}

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return false;
	}

	if (dos_header->e_lfanew < static_cast<std::uint32_t>(sizeof(ImageDosHeader)))
	{
		return false;
	}

	if (dos_header->e_lfanew >= static_cast<std::uint32_t>(m_data.size()))
	{
		return false;
	}

	if (static_cast<size_t>(dos_header->e_lfanew) + sizeof(std::uint32_t) > m_data.size())
	{
		return false;
	}

	return true;
}

bool PE::Image::ValidateNT() const noexcept
{
	auto dos_header = GetDOSHeader();
	if (!dos_header)
	{
		return false;
	}

	size_t nt_offset = dos_header->e_lfanew;

	if (nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader) > m_data.size())
	{
		return false;
	}

	auto signature = *reinterpret_cast<const std::uint32_t*>(m_data.data() + nt_offset);
	if (signature != IMAGE_NT_SIGNATURE)
	{
		return false;
	}

	const ImageFileHeader* file_header =
		reinterpret_cast<const ImageFileHeader*>(m_data.data() + nt_offset + sizeof(std::uint32_t));

	if (file_header->NumberOfSections == 0 || file_header->NumberOfSections > 96)
	{
		return false;
	}

	if (file_header->SizeOfOptionalHeader != sizeof(ImageOptionalHeader32) &&
		file_header->SizeOfOptionalHeader != sizeof(ImageOptionalHeader64))
	{
		return false;
	}

	if (nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader) + file_header->SizeOfOptionalHeader > m_data.size())
	{
		return false;
	}

	return true;
}


bool PE::Image::ValidateOptional() const noexcept
{
	auto dos_header = GetDOSHeader();
	if (!dos_header)
	{
		return false;
	}

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader);

	if (optional_offset + sizeof(std::uint16_t) > m_data.size())
	{
		return false;
	}

	std::uint16_t magic = *reinterpret_cast<const std::uint16_t*>(m_data.data() + optional_offset);
	if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		return false;
	}

	size_t optional_header_size = (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) ?
		sizeof(ImageOptionalHeader32) : sizeof(ImageOptionalHeader64);

	if (optional_offset + optional_header_size > m_data.size())
	{
		return false;
	}

	return true;
}

bool PE::Image::ValidateImage() noexcept
{
	if (m_data.empty())
	{
		return false;
	}

	if (!ValidateDOS())
	{
		return false;
	}

	if (!ValidateNT())
	{
		return false;
	}

	if (!ValidateOptional())
	{
		return false;
	}

	auto dos_header = GetDOSHeader();
	if (dos_header)
	{
		size_t optional_offset = dos_header->e_lfanew + sizeof(std::uint32_t) + sizeof(ImageFileHeader);
		if (optional_offset + sizeof(std::uint16_t) <= m_data.size())
		{
			m_magic = *reinterpret_cast<const std::uint16_t*>(m_data.data() + optional_offset);
		}
	}

	return true;
}

/*
bool PE::ImageUtils::StripPDBInfo() const noexcept
{
	if (!m_image)
	{
		return false;
	}

	auto cv_data = m_image->Debug().GetByType(IMAGE_DEBUG_TYPE_CODEVIEW);
	if (cv_data.type == 0 || cv_data.address_offset == 0)
	{
		return false;
	}

	DWORD cv_offset = cv_data.address_offset;
	if (cv_offset + sizeof(DWORD) > m_image->Data().size())
	{
		return false;
	}

	BYTE* data = const_cast<BYTE*>(m_image->Data().data());
	DWORD signature = *reinterpret_cast<DWORD*>(data + cv_offset);

	if (signature == IMAGE_RSDS_SIGNATURE)
	{
		// Signature 4;
		// GUID		16;
		// Age		 4;
		DWORD pdb_offset = cv_offset + 4 + 16 + 4;
		if (pdb_offset >= m_image->Data().size())
		{
			return false;
		}

		size_t max_len = m_image->Data().size() - pdb_offset;
		char* pdb_path = reinterpret_cast<char*>(data + pdb_offset);
		size_t path_len = strnlen(pdb_path, max_len);

		std::memset(pdb_path, 0, path_len);

		return true;
	}

	return false;
}
*/

bool PE::ImageUtils::PatternScan(const char* pattern, const char* mask, uintptr_t* out) const noexcept
{
	size_t str_len = strlen(mask);
	if (str_len != strlen(pattern))
		return false;

	for (size_t i = 0; i < m_image->Data().size() - str_len; ++i)
	{
		bool found = true;
		for (size_t j = 0; j < str_len; ++j)
		{
			if (mask[j] == 'x' && pattern[j] != m_image->Data()[i + j])
			{
				found = false;
				break;
			}
		}
		if (found)
		{
			if (out != nullptr)
			{
				*out = reinterpret_cast<uintptr_t>(m_image->Data().data() + i);
			}
			return true;
		}
	}

	return false;
}

std::uint32_t PE::ImageUtils::RvaToOffset(std::uint32_t rva) const noexcept
{
	if (!m_image)
		return 0;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
	{
		return 0;
	}

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader);

	if (optional_offset + sizeof(std::uint16_t) > m_image->Data().size())
	{
		return 0;
	}

	std::uint16_t magic = *reinterpret_cast<const std::uint16_t*>(m_image->Data().data() + optional_offset);

	const ImageFileHeader* file_header =
		reinterpret_cast<const ImageFileHeader*>(m_image->Data().data() + nt_offset + sizeof(std::uint32_t));

	size_t sections_offset = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		sections_offset = nt_offset + sizeof(ImageNtHeaders64);
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		sections_offset = nt_offset + sizeof(ImageNtHeaders32);
	}
	else
	{
		return 0;
	}

	const ImageSectionHeader* sections =
		reinterpret_cast<const ImageSectionHeader*>(m_image->Data().data() + sections_offset);

	std::uint16_t num_sections = file_header->NumberOfSections;

	for (std::uint16_t i = 0; i < num_sections; ++i)
	{
		std::uint32_t section_start = sections[i].VirtualAddress;
		std::uint32_t section_end = section_start + sections[i].Misc.VirtualSize;

		if (rva >= section_start && rva < section_end)
		{
			return sections[i].PointerToRawData + (rva - section_start);
		}
	}

	return 0;
}

std::uint32_t PE::ImageUtils::VaToRva(std::uint64_t va) const noexcept
{
	if (!m_image)
		return 0;

	std::uint64_t image_base = 0;
	if (m_image->IsPE64())
	{
		auto opt = m_image->GetOptionalHeader<ImageOptionalHeader64>();
		if (opt)
		{
			image_base = opt->ImageBase;
		}
	}
	else if (m_image->IsPE32())
	{
		auto opt = m_image->GetOptionalHeader<ImageOptionalHeader32>();
		if (opt)
		{
			image_base = opt->ImageBase;
		}
	}

	if (va < image_base)
	{
		return 0;
	}

	return static_cast<std::uint32_t>(va - image_base);
}

std::uint32_t PE::ImageUtils::OffsetToRva(std::uint32_t file_offset) const noexcept
{
	if (!m_image)
	{
		return 0;
	}

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
		return 0;

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader);

	if (optional_offset + sizeof(std::uint16_t) > m_image->Data().size())
	{
		return 0;
	}

	std::uint16_t magic = *reinterpret_cast<const std::uint16_t*>(m_image->Data().data() + optional_offset);

	const ImageFileHeader* file_header =
		reinterpret_cast<const ImageFileHeader*>(m_image->Data().data() + nt_offset + sizeof(std::uint32_t));

	size_t sections_offset = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		sections_offset = nt_offset + sizeof(ImageNtHeaders64);
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		sections_offset = nt_offset + sizeof(ImageNtHeaders32);
	}
	else
	{
		return 0;
	}

	const ImageSectionHeader* sections =
		reinterpret_cast<const ImageSectionHeader*>(m_image->Data().data() + sections_offset);

	std::uint16_t num_sections = file_header->NumberOfSections;

	for (std::uint16_t i = 0; i < num_sections; ++i)
	{
		std::uint32_t section_raw_start = sections[i].PointerToRawData;
		std::uint32_t section_raw_end = section_raw_start + sections[i].SizeOfRawData;

		if (file_offset >= section_raw_start && file_offset < section_raw_end)
		{
			return sections[i].VirtualAddress + (file_offset - section_raw_start);
		}
	}

	return 0;
}

std::vector<std::string_view> PE::ImageUtils::GetAsciiStrings(std::uint32_t min_length) const noexcept
{
	std::vector<std::string_view> strings;

	if (!m_image || m_image->Data().empty())
	{
		return strings;
	}

	const uint8_t* data = m_image->Data().data();
	const size_t size = m_image->Data().size();

	for (size_t i = 0; i < size; ++i)
	{
		if (data[i] >= 0x20 && data[i] <= 0x7E)
		{
			const size_t start = i;
			while (i < size && data[i] >= 0x20 && data[i] <= 0x7E)
				++i;

			const size_t len = i - start;
			if (len >= min_length)
			{
				strings.emplace_back(reinterpret_cast<const char*>(data + start), len);
			}
			--i; // Skip to next byte to avoid false Unicode detection
		}
	}

	return strings;
}

std::vector<std::wstring_view> PE::ImageUtils::GetUnicodeStrings(std::uint32_t min_length) const noexcept
{
	std::vector<std::wstring_view> strings;

	if (!m_image || m_image->Data().empty())
	{
		return strings;
	}

	const uint8_t* data = m_image->Data().data();
	const size_t size = m_image->Data().size();

	for (size_t i = 0; i + 1 < size; ++i)
	{
		if (data[i] >= 0x20 && data[i] <= 0x7E && data[i + 1] == 0x00)
		{
			const size_t start = i;
			while (i + 1 < size &&
				data[i] >= 0x20 && data[i] <= 0x7E &&
				data[i + 1] == 0x00)
			{
				i += 2;
			}

			const size_t wchar_count = (i - start) / 2;
			if (wchar_count >= min_length)
			{
				strings.emplace_back(
					reinterpret_cast<const wchar_t*>(data + start),
					wchar_count
				);
			}
			--i;
		}
	}

	return strings;
}