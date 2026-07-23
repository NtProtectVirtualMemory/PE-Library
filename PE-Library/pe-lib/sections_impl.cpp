#include "image.hpp"
#include "sections.hpp"
#include <windows.h>
#include <algorithm>

/*
* @brief Computes how many ImageSectionHeader entries actually fit in [table_offset, buffer_size],
* given what the file claims and a hard cap.
* @returns 0 if the table starts past EOF, or if reported_count/buffer size contains garbage
*/
static std::uint32_t ClampSectionCount(
	size_t buffer_size,
	size_t table_offset,
	std::uint32_t reported_count,
	std::uint32_t max_cap) noexcept
{
	if (table_offset > buffer_size)
		return 0; // table starts past EOF

	size_t max_that_fit = (buffer_size - table_offset) / sizeof(PE::ImageSectionHeader);

	return static_cast<std::uint32_t>(
		(std::min<size_t>)({
			static_cast<size_t>(reported_count),
			max_that_fit,
			static_cast<size_t>(max_cap)
			}));
}

template <typename NtHeaders_T>
void PE::ImageSections::BuildSections() noexcept
{
	auto nt_headers = m_image->GetNTHeaders<NtHeaders_T>();
	if (!nt_headers)
		return;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
		return;

	const auto& data = m_image->Data();

	// ! FileHeader.SizeOfOptionalHeader can be spoofed !
	// Get the offset from the fixed struct size for this magic instead of using IMAGE_FIRST_SECTION.
	size_t nt_offset = dos_header->e_lfanew;
	size_t sections_offset = nt_offset + sizeof(NtHeaders_T);

	if (sections_offset > data.size())
		return; // table starts past EOF

	std::uint16_t reported_sections = nt_headers->FileHeader.NumberOfSections;
	std::uint32_t usable = ClampSectionCount(data.size(), sections_offset, reported_sections, 96);

	if (usable == 0)
		return; // reported 0, or maybe nothing fits :thinking:

	m_sections = reinterpret_cast<const ImageSectionHeader*>(data.data() + sections_offset);
	m_number_of_sections = static_cast<uint16_t>(usable);
	m_valid = true;
}

PE::ImageSections::ImageSections(Image* image) : m_image(image)
{
	if (!m_image)
		return;

	if (m_image->IsPE64())
	{
		BuildSections<ImageNtHeaders64>();
	}
	else if (m_image->IsPE32())
	{
		BuildSections<ImageNtHeaders32>();
	}
}

const std::vector<const PE::ImageSectionHeader*> PE::ImageSections::GetAll() const noexcept
{
	std::vector<const PE::ImageSectionHeader*> sections;
	if (m_number_of_sections == 0)
		return sections;

	sections.reserve(m_number_of_sections);
	for (size_t i = 0; i < m_number_of_sections; ++i)
	{
		sections.push_back(&m_sections[i]);
	}

	return sections;
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

	if (dos_header->e_lfanew < 0)
		return false;

	size_t nt_offset = static_cast<size_t>(dos_header->e_lfanew);

	if (nt_offset > image_data.size() ||
		image_data.size() - nt_offset < sizeof(NtHeaders_T))
	{
		return false;
	}

	auto nt_headers =
		reinterpret_cast<NtHeaders_T*>(image_base + nt_offset);

	if (nt_headers->FileHeader.NumberOfSections == 0)
		return false;

	if (nt_headers->FileHeader.NumberOfSections >= 96)
		return false;

	size_t table_offset = nt_offset + sizeof(NtHeaders_T);
	if (table_offset > image_data.size())
		return false;

	auto sections = reinterpret_cast<ImageSectionHeader*>(image_base + table_offset);
	std::uint8_t* section_table = reinterpret_cast<std::uint8_t*>(sections);
	std::uint32_t usable_sections = ClampSectionCount(image_data.size(), table_offset, nt_headers->FileHeader.NumberOfSections, 95);

	if (usable_sections == 0)
		return false;

	std::uint8_t* new_entry_end = section_table
		+ (static_cast<size_t>(usable_sections) + 1) * sizeof(ImageSectionHeader);

	std::uint32_t size_of_headers = nt_headers->OptionalHeader.SizeOfHeaders;
	if (size_of_headers > image_data.size())
		return false;

	std::uint8_t* headers_end = image_base + size_of_headers;

	// NOTE:
	//	Section headers are found inside SizeOfHeaders
	//	If there is no room, adding another section requires moving headers
	std::uint32_t header_extension = 0;
	if (new_entry_end > headers_end)
	{
		std::uint32_t needed_size = static_cast<std::uint32_t>(new_entry_end - image_base);
		std::uint32_t file_alignment = nt_headers->OptionalHeader.FileAlignment;
		if (!AlignUp(needed_size, file_alignment, size_of_headers))
			return false;

		header_extension = size_of_headers - nt_headers->OptionalHeader.SizeOfHeaders;
	}

	ImageSectionHeader new_section = {};
	size_t name_len = (std::min)(name.size(), static_cast<size_t>(IMAGE_SIZEOF_SHORT_NAME));
	std::memcpy(new_section.Name, name.data(), name_len);

	std::uint32_t file_alignment = nt_headers->OptionalHeader.FileAlignment;
	std::uint32_t section_alignment = nt_headers->OptionalHeader.SectionAlignment;

	std::uint32_t max_raw_end = 0;
	std::uint32_t max_va_end = 0;
	for (std::uint32_t idx = 0; idx < usable_sections; ++idx)
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

	// VirtualSize represents the real amount of data!
	new_section.Misc.VirtualSize = static_cast<std::uint32_t>(content.size());

	new_section.Characteristics = characteristics;

	std::uint64_t new_size = static_cast<std::uint64_t>(new_section.PointerToRawData) + new_section.SizeOfRawData;
	if (new_size > (std::numeric_limits<size_t>::max)())
		return false;

	// Finally added support for this :praying:
	if (header_extension > 0)
	{
		size_t old_size = image_data.size();
		image_data.resize(old_size + header_extension);

		if (max_raw_end > old_size)
			return false;

		size_t to_move = old_size - max_raw_end;
		if (to_move)
		{
			std::memmove(
				image_data.data() + max_raw_end + header_extension,
				image_data.data() + max_raw_end,
				to_move);
		}

		image_base = image_data.data();
		dos_header = reinterpret_cast<const ImageDosHeader*>(image_base);
		nt_headers = reinterpret_cast<NtHeaders_T*>(image_base + dos_header->e_lfanew);
		sections = reinterpret_cast<ImageSectionHeader*>(image_base + nt_offset + sizeof(NtHeaders_T));

		for (std::uint32_t idx = 0; idx < usable_sections; ++idx)
		{
			sections[idx].PointerToRawData += header_extension;
		}

		new_section.PointerToRawData += header_extension;
		nt_headers->OptionalHeader.SizeOfHeaders = size_of_headers;
	}
	else
	{
		image_data.resize(static_cast<size_t>(new_size));
	}

	if (raw_ptr + content.size() > image_data.size()) return false;
	std::memcpy(image_data.data() + raw_ptr, content.data(), content.size());

	// Recalculate pointers because resize() may have moved the buffer
	auto new_dos_header = reinterpret_cast<const ImageDosHeader*>(image_data.data());
	auto new_nt_headers = reinterpret_cast<NtHeaders_T*>(image_data.data() + new_dos_header->e_lfanew);

	size_t new_nt_offset = static_cast<size_t>(new_dos_header->e_lfanew);
	auto new_sections = reinterpret_cast<ImageSectionHeader*>(image_data.data() + new_nt_offset + sizeof(NtHeaders_T));

	new_sections[usable_sections] = new_section;
	new_nt_headers->FileHeader.NumberOfSections = static_cast<uint16_t>(usable_sections + 1);

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