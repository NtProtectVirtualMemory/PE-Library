
/* sections_impl.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#include "image.hpp"
#include "sections.hpp"

PE::ImageSections::ImageSections(Image* image) : m_image(image)
{
	if (!m_image || !m_image->IsValid())
		return;

	if (m_image->IsPE64())
	{
		auto nt_headers = m_image->GetNTHeaders<ImageNtHeaders64>();
		if (!nt_headers)
			return;

		m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
		m_sections = reinterpret_cast<const ImageSectionHeader*>(IMAGE_FIRST_SECTION(nt_headers));
	}
	else if (m_image->IsPE32())
	{
		auto nt_headers = m_image->GetNTHeaders<ImageNtHeaders64>();
		if (!nt_headers)
			return;

		m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
		m_sections = reinterpret_cast<const ImageSectionHeader*>(IMAGE_FIRST_SECTION(nt_headers));
	}

	if (ValidateSections(m_image->Data()))
	{
		m_valid = true;
	}
}

bool PE::ImageSections::ValidateSections(const std::vector<std::uint8_t>& data) noexcept
{
	if (!m_image)
		return false;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
		return false;

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader);

	if (optional_offset + sizeof(std::uint16_t) > data.size())
		return false;

	std::uint16_t magic = *reinterpret_cast<const std::uint16_t*>(data.data() + optional_offset);

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
		return false;
	}

	const ImageFileHeader* file_header =
		reinterpret_cast<const ImageFileHeader*>(data.data() + nt_offset + sizeof(std::uint32_t));

	std::uint16_t num_sections = file_header->NumberOfSections;
	if (num_sections == 0 || num_sections > 96)
		return false;

	size_t sections_size = num_sections * sizeof(ImageSectionHeader);
	if (sections_offset + sections_size > data.size())
		return false;

	const ImageSectionHeader* sections =
		reinterpret_cast<const ImageSectionHeader*>(data.data() + sections_offset);

	for (std::uint16_t i = 0; i < num_sections; ++i)
	{
		const ImageSectionHeader& section = sections[i];

		if (section.PointerToRawData != 0 && section.SizeOfRawData > 0)
		{
			size_t end = static_cast<size_t>(section.PointerToRawData) + section.SizeOfRawData;
			if (end > data.size())
			{
				return false;
			}

		}
	}

	return true;
}

const std::vector<const PE::ImageSectionHeader*> PE::ImageSections::GetAll() const noexcept
{
	if (m_number_of_sections > 0)
	{
		std::vector<const PE::ImageSectionHeader*> sections;
		sections.reserve(m_number_of_sections);
		for (size_t i = 0; i < m_number_of_sections; ++i)
		{
			sections.push_back(&m_sections[i]);
		}

		return sections;
	}

	return {};
}

const PE::ImageSectionHeader* PE::ImageSections::GetByName(const char* name) const noexcept
{
	for (size_t i = 0; i < m_number_of_sections; ++i)
	{
		if (_strnicmp(reinterpret_cast<const char*>(m_sections[i].Name), name, IMAGE_SIZEOF_SHORT_NAME) == 0)
		{
			return &m_sections[i];
		}
	}

	return nullptr;
}

const PE::ImageSectionHeader* PE::ImageSections::GetByIndex(size_t index) const noexcept
{
	if (index < m_number_of_sections)
	{
		return &m_sections[index];
	}
	return nullptr;
}
