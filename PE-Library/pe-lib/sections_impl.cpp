#include "image.hpp"
#include "sections.hpp"
#include <windows.h>
#include <algorithm>

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

		// IMAGE_FIRST_SECTION points directly after the optional header.
		// This gives us the first IMAGE_SECTION_HEADER entry in the section table.
		m_sections = reinterpret_cast<const ImageSectionHeader*>(IMAGE_FIRST_SECTION(nt_headers));
	}
	else if (m_image->IsPE32())
	{
		auto nt_headers = m_image->GetNTHeaders<ImageNtHeaders32>();
		if (!nt_headers)
			return;

		m_number_of_sections = nt_headers->FileHeader.NumberOfSections;
		m_sections = reinterpret_cast<const ImageSectionHeader*>(IMAGE_FIRST_SECTION(nt_headers));
	}
	else
	{
		m_sections = nullptr;
		m_number_of_sections = 0;
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

	// The first field of IMAGE_OPTIONAL_HEADER tells us whether this is PE32 or PE32 + .
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

	// A PE can theoretically have more sections... 
	// But its unlikely you'll encounter this
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
			// Make sure that the section's raw data points
			// inside the loaded buffer
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
		// Section names are fixed 8-byte fields and are not guaranteed to be null terminated!!
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

template <typename NtHeaders_T>
bool PE::ImageSections::AddSection_T(
	const std::string_view& name,
	const std::vector<std::uint8_t>& content,
	std::uint32_t characteristics) noexcept
{
	if (content.size() > (std::numeric_limits<std::uint32_t>::max)())
		return false;

	std::vector<std::uint8_t>& image_data = m_image->Data();
	if (image_data.size() < sizeof(ImageDosHeader))
		return false;

	std::uint8_t* image_base = image_data.data();
	auto dos_header = reinterpret_cast<const ImageDosHeader*>(image_base);

	if (static_cast<size_t>(dos_header->e_lfanew) + sizeof(NtHeaders_T) > image_data.size())
		return false;

	auto nt_headers = reinterpret_cast<NtHeaders_T*>(image_base + dos_header->e_lfanew);

	if (nt_headers->FileHeader.NumberOfSections == 0)
		return false;

	if (nt_headers->FileHeader.NumberOfSections >= 96)
		return false;

	auto sections = reinterpret_cast<ImageSectionHeader*>(IMAGE_FIRST_SECTION(nt_headers));

	std::uint8_t* section_table = reinterpret_cast<std::uint8_t*>(sections);

	// Where the new section header would end if appended :thinking:
	std::uint8_t* new_entry_end = section_table
		+ (static_cast<size_t>(nt_headers->FileHeader.NumberOfSections) + 1) * sizeof(ImageSectionHeader);

	std::uint32_t size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;
	std::uint8_t* headers_end = image_base + size_of_headers;

	// NOTE:
	//	Section headers are found inside SizeOfHeaders
	//	If there is no room, adding another section requires moving headers
	//	! THIS IS CURRENTLY NOT SUPPORTED !
	if (new_entry_end > headers_end)
		return false;

	ImageSectionHeader new_section = {};
	size_t name_len = (std::min)(name.size(), static_cast<size_t>(IMAGE_SIZEOF_SHORT_NAME));
	std::memcpy(new_section.Name, name.data(), name_len);

	std::uint32_t file_alignment = nt_headers->OptionalHeader.FileAlignment;
	std::uint32_t section_alignment = nt_headers->OptionalHeader.SectionAlignment;

	std::uint32_t max_raw_end = 0;
	std::uint32_t max_va_end = 0;
	for (std::uint32_t idx = 0; idx < nt_headers->FileHeader.NumberOfSections; ++idx)
	{
		std::uint32_t raw_end = sections[idx].PointerToRawData + sections[idx].SizeOfRawData;
		std::uint32_t va_end = sections[idx].VirtualAddress + sections[idx].Misc.VirtualSize;
		max_raw_end = (std::max)(max_raw_end, raw_end);
		max_va_end = (std::max)(max_va_end, va_end);
	}

	std::uint32_t raw_ptr, raw_size, virtual_addr;
	if (!AlignUp(max_raw_end, file_alignment, raw_ptr))
		return false;

	// Raw section size is stored aligned, even though 
	// VirtualSize contains the unpadded content size
	if (!AlignUp(static_cast<std::uint32_t>(content.size()), file_alignment, raw_size))
		return false;

	if (!AlignUp(max_va_end, section_alignment, virtual_addr))
		return false;

	new_section.PointerToRawData = raw_ptr;
	new_section.SizeOfRawData = raw_size;
	new_section.VirtualAddress = virtual_addr;
	new_section.Misc.VirtualSize = static_cast<std::uint32_t>(content.size()); // VirtualSize represents the real amount of data, not the padded size
	new_section.Characteristics = characteristics;

	std::uint64_t new_size = static_cast<std::uint64_t>(new_section.PointerToRawData) + new_section.SizeOfRawData;
	if (new_size > (std::numeric_limits<size_t>::max)())
		return false;

	image_data.resize(static_cast<size_t>(new_size));
	std::memcpy(image_data.data() + new_section.PointerToRawData, content.data(), content.size());

	// Recalculate pointers because resize() may have moved the vector buffer
	auto new_dos_header = reinterpret_cast<const ImageDosHeader*>(image_data.data());
	auto new_nt_headers = reinterpret_cast<NtHeaders_T*>(image_data.data() + new_dos_header->e_lfanew);
	auto new_sections = reinterpret_cast<ImageSectionHeader*>(IMAGE_FIRST_SECTION(new_nt_headers));

	new_sections[new_nt_headers->FileHeader.NumberOfSections] = new_section;
	new_nt_headers->FileHeader.NumberOfSections++;

	// SizeOfImage is the end of the highest virtual 
	// section rounded up/down to SectionAlignment.
	std::uint32_t end_va = new_section.VirtualAddress + new_section.Misc.VirtualSize;
	std::uint32_t aligned_size_of_image;
	if (!AlignUp(end_va, section_alignment, aligned_size_of_image))
		return false;
	new_nt_headers->OptionalHeader.SizeOfImage = aligned_size_of_image;

	m_number_of_sections = new_nt_headers->FileHeader.NumberOfSections;
	m_sections = reinterpret_cast<const ImageSectionHeader*>(new_sections);

	return true;
}

bool PE::ImageSections::AddSection(
	const std::string_view& name,
	const std::vector<uint8_t> content,
	std::uint32_t characteristics) noexcept
{
	if (!m_image || !m_image->IsValid() || name.empty() || content.empty())
		return false;

	if (m_image->IsPE64())
		return AddSection_T<ImageNtHeaders64>(name, content, characteristics);

	if (m_image->IsPE32())
		return AddSection_T<ImageNtHeaders32>(name, content, characteristics);

	return false;
}
