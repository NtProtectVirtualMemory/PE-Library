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

// UTILS

inline DWORD PE::_Utils::RvaToOffset(DWORD rva) const noexcept
{
	if (!m_image)
		return 0;

	auto dos_header = m_image->DosHeader().Get();
	if (!dos_header)
		return 0;

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	if (optional_offset + sizeof(WORD) > m_image->Data().size())
		return 0;

	WORD magic = *reinterpret_cast<const WORD*>(m_image->Data().data() + optional_offset);

	const IMAGE_FILE_HEADER* file_header =
		reinterpret_cast<const IMAGE_FILE_HEADER*>(m_image->Data().data() + nt_offset + sizeof(DWORD));

	size_t sections_offset = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS64);
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS32);
	}
	else
	{
		return 0;
	}

	const IMAGE_SECTION_HEADER* sections =
		reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_image->Data().data() + sections_offset);

	WORD num_sections = file_header->NumberOfSections;

	for (WORD i = 0; i < num_sections; ++i)
	{
		DWORD section_start = sections[i].VirtualAddress;
		DWORD section_end = section_start + sections[i].Misc.VirtualSize;

		if (rva >= section_start && rva < section_end)
		{
			return sections[i].PointerToRawData + (rva - section_start);
		}
	}

	return 0;
}

DWORD PE::_Utils::VaToRva(ULONGLONG va) const noexcept
{
	if (!m_image)
		return 0;

	ULONGLONG image_base = 0;
	if (m_image->IsPE64())
	{
		auto opt = m_image->OptionalHeader().Get<IMAGE_OPTIONAL_HEADER64>();
		if (opt)
			image_base = opt->ImageBase;
	}
	else if (m_image->IsPE32())
	{
		auto opt = m_image->OptionalHeader().Get<IMAGE_OPTIONAL_HEADER32>();
		if (opt)
			image_base = opt->ImageBase;
	}

	if (va < image_base)
		return 0;

	return static_cast<DWORD>(va - image_base);
}

DWORD PE::_Utils::OffsetToRva(DWORD file_offset) const noexcept
{
	if (!m_image)
		return 0;

	auto dos_header = m_image->DosHeader().Get();
	if (!dos_header)
		return 0;

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	if (optional_offset + sizeof(WORD) > m_image->Data().size())
		return 0;

	WORD magic = *reinterpret_cast<const WORD*>(m_image->Data().data() + optional_offset);

	const IMAGE_FILE_HEADER* file_header =
		reinterpret_cast<const IMAGE_FILE_HEADER*>(m_image->Data().data() + nt_offset + sizeof(DWORD));

	size_t sections_offset = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS64);
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS32);
	}
	else
	{
		return 0;
	}

	const IMAGE_SECTION_HEADER* sections =
		reinterpret_cast<const IMAGE_SECTION_HEADER*>(m_image->Data().data() + sections_offset);

	WORD num_sections = file_header->NumberOfSections;

	for (WORD i = 0; i < num_sections; ++i)
	{
		DWORD section_raw_start = sections[i].PointerToRawData;
		DWORD section_raw_end = section_raw_start + sections[i].SizeOfRawData;

		if (file_offset >= section_raw_start && file_offset < section_raw_end)
		{
			return sections[i].VirtualAddress + (file_offset - section_raw_start);
		}
	}

	return 0;
}

std::vector<std::string_view> PE::_Utils::GetAsciiStrings(DWORD min_length) const noexcept
{
	std::vector<std::string_view> strings;

	if (!m_image || m_image->Data().empty())
		return strings;

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

std::vector<std::wstring_view> PE::_Utils::GetUnicodeStrings(DWORD min_length) const noexcept
{
	std::vector<std::wstring_view> strings;

	if (!m_image || m_image->Data().empty())
		return strings;

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

	size_t sections_offset = 0;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS64);
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		sections_offset = nt_offset + sizeof(IMAGE_NT_HEADERS32);
	}
	else
	{
		return false;
	}

	const IMAGE_FILE_HEADER* file_header =
		reinterpret_cast<const IMAGE_FILE_HEADER*>(data.data() + nt_offset + sizeof(DWORD));

	WORD num_sections = file_header->NumberOfSections;
	if (num_sections == 0 || num_sections > 96)
		return false;

	size_t sections_size = num_sections * sizeof(IMAGE_SECTION_HEADER);
	if (sections_offset + sections_size > data.size())
		return false;

	const IMAGE_SECTION_HEADER* sections =
		reinterpret_cast<const IMAGE_SECTION_HEADER*>(data.data() + sections_offset);

	for (WORD i = 0; i < num_sections; ++i)
	{
		const IMAGE_SECTION_HEADER& section = sections[i];

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

// DATA DIRECTORY


inline const IMAGE_DATA_DIRECTORY* PE::_DataDirectory::Get(WORD index) const noexcept
{
	if (!m_image || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		return nullptr;

	auto dos_header = m_image->DosHeader().Get();
	if (!dos_header)
		return nullptr;

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);

	if (optional_offset + sizeof(WORD) > m_image->Data().size())
		return nullptr;

	WORD magic = *reinterpret_cast<const WORD*>(m_image->Data().data() + optional_offset);

	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		auto optional = m_image->OptionalHeader().Get<IMAGE_OPTIONAL_HEADER64>();
		if (!optional || index >= optional->NumberOfRvaAndSizes)
			return nullptr;
		return &optional->DataDirectory[index];
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		auto optional = m_image->OptionalHeader().Get<IMAGE_OPTIONAL_HEADER32>();
		if (!optional || index >= optional->NumberOfRvaAndSizes)
			return nullptr;
		return &optional->DataDirectory[index];
	}

	return nullptr;
}

template<typename T>
inline const T* PE::_DataDirectory::GetData(WORD index) const noexcept
{
	if (!m_image)
		return nullptr;

	auto dir = Get(index);
	if (!dir || dir->VirtualAddress == 0)
		return nullptr;

	DWORD offset = m_image->Utils().RvaToOffset(dir->VirtualAddress);
	if (offset == 0)
		return nullptr;

	if (offset + sizeof(T) > m_image->Data().size())
		return nullptr;

	return reinterpret_cast<const T*>(m_image->Data().data() + offset);
}

// IMPORT ADDRESS TABLE

std::vector<std::string_view> PE::_Imports::GetImportedModules() const noexcept
{
	std::vector<std::string_view> dlls;

	auto desc = GetDescriptors();
	if (!desc)
		return dlls;

	while (desc->Name != 0)
	{
		DWORD name_offset = m_image->Utils().RvaToOffset(desc->Name);
		if (name_offset != 0 && name_offset < m_image->Data().size())
		{
			const char* name = reinterpret_cast<const char*>(m_image->Data().data() + name_offset);
			dlls.emplace_back(name);
		}
		desc++;
	}

	return dlls;
}

std::vector<ImportFunction> PE::_Imports::FunctionFromModule(const char* dll_name) const noexcept
{
	std::vector<ImportFunction> functions;

	auto desc = GetDescriptors();
	if (!desc || !dll_name)
		return functions;

	while (desc->Name != 0)
	{
		DWORD name_offset = m_image->Utils().RvaToOffset(desc->Name);
		if (name_offset == 0 || name_offset >= m_image->Data().size())
		{
			desc++;
			continue;
		}

		const char* current_dll = reinterpret_cast<const char*>(m_image->Data().data() + name_offset);

		if (_stricmp(current_dll, dll_name) != 0)
		{
			desc++;
			continue;
		}

		DWORD thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
		DWORD thunk_offset = m_image->Utils().RvaToOffset(thunk_rva);

		if (thunk_offset == 0)
			return functions;

		if (m_image->IsPE64())
		{
			auto thunk = reinterpret_cast<const IMAGE_THUNK_DATA64*>(
				m_image->Data().data() + thunk_offset);

			while (thunk->u1.AddressOfData != 0)
			{
				ImportFunction func{};

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				{
					func.is_ordinal = true;
					func.ordinal = static_cast<WORD>(thunk->u1.Ordinal & 0xFFFF);
					func.hint = 0;
				}
				else
				{
					DWORD hint_offset = m_image->Utils().RvaToOffset(
						static_cast<DWORD>(thunk->u1.AddressOfData));

					if (hint_offset != 0 && hint_offset < m_image->Data().size())
					{
						auto import_by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
							m_image->Data().data() + hint_offset);

						func.is_ordinal = false;
						func.ordinal = 0;
						func.hint = import_by_name->Hint;
						func.name = import_by_name->Name;
					}
				}

				functions.push_back(func);
				thunk++;
			}
		}
		else
		{
			auto thunk = reinterpret_cast<const IMAGE_THUNK_DATA32*>(
				m_image->Data().data() + thunk_offset);

			while (thunk->u1.AddressOfData != 0)
			{
				ImportFunction func{};

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					func.is_ordinal = true;
					func.ordinal = static_cast<WORD>(thunk->u1.Ordinal & 0xFFFF);
					func.hint = 0;
				}
				else
				{
					DWORD hint_offset = m_image->Utils().RvaToOffset(thunk->u1.AddressOfData);

					if (hint_offset != 0 && hint_offset < m_image->Data().size())
					{
						auto import_by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
							m_image->Data().data() + hint_offset);

						func.is_ordinal = false;
						func.ordinal = 0;
						func.hint = import_by_name->Hint;
						func.name = import_by_name->Name;
					}
				}

				functions.push_back(func);
				thunk++;
			}
		}

		return functions;
	}

	return functions;
}

// EXPORTS

std::vector<ExportFunction> PE::_Exports::All() const noexcept
{
	std::vector<ExportFunction> exports;

	auto exp_dir = GetDescriptor();
	if (!exp_dir)
		return exports;

	ULONGLONG image_base = 0;
	if (m_image->IsPE64())
	{
		auto opt = m_image->OptionalHeader().Get<IMAGE_OPTIONAL_HEADER64>();
		if (opt)
			image_base = opt->ImageBase;
	}
	else
	{
		auto opt = m_image->OptionalHeader().Get<IMAGE_OPTIONAL_HEADER32>();
		if (opt)
			image_base = opt->ImageBase;
	}

	auto dir_entry = m_image->DataDirectory().Get(IMAGE_DIRECTORY_ENTRY_EXPORT);
	DWORD export_dir_start = dir_entry ? dir_entry->VirtualAddress : 0;
	DWORD export_dir_end = dir_entry ? (dir_entry->VirtualAddress + dir_entry->Size) : 0;

	DWORD functions_offset = m_image->Utils().RvaToOffset(exp_dir->AddressOfFunctions);
	DWORD names_offset = m_image->Utils().RvaToOffset(exp_dir->AddressOfNames);
	DWORD ordinals_offset = m_image->Utils().RvaToOffset(exp_dir->AddressOfNameOrdinals);

	if (functions_offset == 0)
		return exports;

	const DWORD* functions = reinterpret_cast<const DWORD*>(
		m_image->Data().data() + functions_offset);

	const DWORD* names = nullptr;
	const WORD* ordinals = nullptr;

	if (names_offset != 0 && ordinals_offset != 0)
	{
		names = reinterpret_cast<const DWORD*>(m_image->Data().data() + names_offset);
		ordinals = reinterpret_cast<const WORD*>(m_image->Data().data() + ordinals_offset);
	}

	exports.reserve(exp_dir->NumberOfFunctions);

	for (DWORD i = 0; i < exp_dir->NumberOfFunctions; ++i)
	{
		DWORD func_rva = functions[i];

		if (func_rva == 0)
			continue;

		ExportFunction exp{};
		exp.rva = func_rva;
		exp.va = image_base + func_rva;
		exp.file_offset = m_image->Utils().RvaToOffset(func_rva);
		exp.ordinal = static_cast<WORD>(i + exp_dir->Base);

		if (func_rva >= export_dir_start && func_rva < export_dir_end)
		{
			exp.is_forwarded = true;
			DWORD forward_offset = m_image->Utils().RvaToOffset(func_rva);
			if (forward_offset != 0 && forward_offset < m_image->Data().size())
			{
				exp.forward_name = reinterpret_cast<const char*>(
					m_image->Data().data() + forward_offset);
			}
		}
		else
		{
			exp.is_forwarded = false;
		}

		if (names && ordinals)
		{
			for (DWORD j = 0; j < exp_dir->NumberOfNames; ++j)
			{
				if (ordinals[j] == i)
				{
					DWORD name_offset = m_image->Utils().RvaToOffset(names[j]);
					if (name_offset != 0 && name_offset < m_image->Data().size())
					{
						exp.name = reinterpret_cast<const char*>(
							m_image->Data().data() + name_offset);
					}
					break;
				}
			}
		}

		exports.push_back(exp);
	}

	return exports;
}

// RELOCATIONS

std::vector<RelocationBlock> PE::_Relocations::GetBlocks() const noexcept
{
	std::vector<RelocationBlock> blocks;

	if (!Present())
		return blocks;

	auto dir = m_image->DataDirectory().Get(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (!dir)
		return blocks;

	DWORD reloc_offset = m_image->Utils().RvaToOffset(dir->VirtualAddress);
	if (reloc_offset == 0)
		return blocks;

	const BYTE* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	DWORD total_size = dir->Size;
	DWORD processed = 0;

	while (processed < total_size)
	{
		if (reloc_offset + processed + sizeof(IMAGE_BASE_RELOCATION) > data_size)
			break;

		const IMAGE_BASE_RELOCATION* block =
			reinterpret_cast<const IMAGE_BASE_RELOCATION*>(data + reloc_offset + processed);

		if (block->SizeOfBlock == 0)
			break;

		if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
			break;

		RelocationBlock reloc_block{};
		reloc_block.page_rva = block->VirtualAddress;

		DWORD entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		const WORD* entries = reinterpret_cast<const WORD*>(
			data + reloc_offset + processed + sizeof(IMAGE_BASE_RELOCATION));

		reloc_block.entries.reserve(entry_count);

		for (DWORD i = 0; i < entry_count; ++i)
		{
			WORD entry = entries[i];
			WORD type = (entry >> 12) & 0x0F;
			WORD offset = entry & 0x0FFF;

			if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			RelocationEntry reloc_entry{};
			reloc_entry.type = type;
			reloc_entry.rva = block->VirtualAddress + offset;
			reloc_entry.file_offset = m_image->Utils().RvaToOffset(reloc_entry.rva);

			reloc_block.entries.push_back(reloc_entry);
		}

		blocks.push_back(std::move(reloc_block));
		processed += block->SizeOfBlock;
	}

	return blocks;
}

std::vector<RelocationEntry> PE::_Relocations::GetAllEntries() const noexcept
{
	std::vector<RelocationEntry> all_entries;

	auto blocks = GetBlocks();

	size_t total = 0;
	for (const auto& block : blocks)
		total += block.entries.size();

	all_entries.reserve(total);

	for (const auto& block : blocks)
	{
		for (const auto& entry : block.entries)
		{
			all_entries.push_back(entry);
		}
	}

	return all_entries;
}

// TLS


bool PE::_TLS::Present() const noexcept
{
	if (!m_image || !m_image->IsValid())
		return false;

	return m_image->DataDirectory().Exists(IMAGE_DIRECTORY_ENTRY_TLS);
}

const IMAGE_TLS_DIRECTORY32* PE::_TLS::GetDirectory32() const noexcept
{
	if (!Present() || !m_image->IsPE32())
		return nullptr;

	return m_image->DataDirectory().GetData<IMAGE_TLS_DIRECTORY32>(IMAGE_DIRECTORY_ENTRY_TLS);
}

const IMAGE_TLS_DIRECTORY64* PE::_TLS::GetDirectory64() const noexcept
{
	if (!Present() || !m_image->IsPE64())
		return nullptr;

	return m_image->DataDirectory().GetData<IMAGE_TLS_DIRECTORY64>(IMAGE_DIRECTORY_ENTRY_TLS);
}

template const IMAGE_TLS_DIRECTORY32* PE::_TLS::GetDirectory<IMAGE_TLS_DIRECTORY32>() const noexcept;
template const IMAGE_TLS_DIRECTORY64* PE::_TLS::GetDirectory<IMAGE_TLS_DIRECTORY64>() const noexcept;

TLSInfo PE::_TLS::GetInfo() const noexcept
{
	TLSInfo info{};

	if (!Present())
		return info;

	if (m_image->IsPE64())
	{
		auto tls = GetDirectory64();
		if (!tls)
			return info;

		info.raw_data_start_va = tls->StartAddressOfRawData;
		info.raw_data_end_va = tls->EndAddressOfRawData;
		info.index_va = tls->AddressOfIndex;
		info.callbacks_va = tls->AddressOfCallBacks;
		info.zero_fill_size = tls->SizeOfZeroFill;
		info.characteristics = tls->Characteristics;
		info.raw_data_size = static_cast<DWORD>(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
	}
	else if (m_image->IsPE32())
	{
		auto tls = GetDirectory32();
		if (!tls)
			return info;

		info.raw_data_start_va = tls->StartAddressOfRawData;
		info.raw_data_end_va = tls->EndAddressOfRawData;
		info.index_va = tls->AddressOfIndex;
		info.callbacks_va = tls->AddressOfCallBacks;
		info.zero_fill_size = tls->SizeOfZeroFill;
		info.characteristics = tls->Characteristics;
		info.raw_data_size = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
	}

	return info;
}

std::vector<TLSCallback> PE::_TLS::GetCallbacks() const noexcept
{
	std::vector<TLSCallback> callbacks;

	if (!Present())
		return callbacks;

	TLSInfo info = GetInfo();
	if (info.callbacks_va == 0)
		return callbacks;

	DWORD callbacks_rva = m_image->Utils().VaToRva(info.callbacks_va);
	if (callbacks_rva == 0)
		return callbacks;

	DWORD callbacks_offset = m_image->Utils().RvaToOffset(callbacks_rva);
	if (callbacks_offset == 0)
		return callbacks;

	const BYTE* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();

	if (m_image->IsPE64())
	{
		const ULONGLONG* callback_array = reinterpret_cast<const ULONGLONG*>(data + callbacks_offset);

		while (callbacks_offset < data_size)
		{
			ULONGLONG callback_va = *callback_array;
			if (callback_va == 0)
				break;

			TLSCallback cb{};
			cb.va = callback_va;
			cb.rva = m_image->Utils().VaToRva(callback_va);
			cb.file_offset = m_image->Utils().RvaToOffset(cb.rva);

			callbacks.push_back(cb);
			callback_array++;
			callbacks_offset += sizeof(ULONGLONG);
		}
	}
	else
	{
		const DWORD* callback_array = reinterpret_cast<const DWORD*>(data + callbacks_offset);

		while (callbacks_offset < data_size)
		{
			DWORD callback_va = *callback_array;
			if (callback_va == 0)
				break;

			TLSCallback cb{};
			cb.va = callback_va;
			cb.rva = m_image->Utils().VaToRva(callback_va);
			cb.file_offset = m_image->Utils().RvaToOffset(cb.rva);

			callbacks.push_back(cb);
			callback_array++;
			callbacks_offset += sizeof(DWORD);
		}
	}

	return callbacks;
}

bool PE::_TLS::HasCallbacks() const noexcept
{
	if (!Present())
		return false;

	TLSInfo info = GetInfo();
	if (info.callbacks_va == 0)
		return false;

	DWORD callbacks_rva = m_image->Utils().VaToRva(info.callbacks_va);
	if (callbacks_rva == 0)
		return false;

	DWORD callbacks_offset = m_image->Utils().RvaToOffset(callbacks_rva);
	if (callbacks_offset == 0 || callbacks_offset >= m_image->Data().size())
		return false;

	const BYTE* data = m_image->Data().data();

	if (m_image->IsPE64())
	{
		if (callbacks_offset + sizeof(ULONGLONG) > m_image->Data().size())
			return false;
		return *reinterpret_cast<const ULONGLONG*>(data + callbacks_offset) != 0;
	}
	else
	{
		if (callbacks_offset + sizeof(DWORD) > m_image->Data().size())
			return false;
		return *reinterpret_cast<const DWORD*>(data + callbacks_offset) != 0;
	}
}

// RESOURCES

std::vector<ResourceEntry> PE::_Resources::GetAll() const noexcept
{
	std::vector<ResourceEntry> entries;

	if (!Present())
		return entries;

	auto dir = m_image->DataDirectory().Get(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (!dir)
		return entries;

	DWORD resource_base_offset = m_image->Utils().RvaToOffset(dir->VirtualAddress);
	if (resource_base_offset == 0)
		return entries;

	const BYTE* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	const BYTE* resource_base = data + resource_base_offset;

	auto root_dir = GetRootDirectory();
	if (!root_dir)
		return entries;

	WORD total_entries_l1 = root_dir->NumberOfNamedEntries + root_dir->NumberOfIdEntries;
	const IMAGE_RESOURCE_DIRECTORY_ENTRY* entries_l1 =
		reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(root_dir + 1);

	for (WORD i = 0; i < total_entries_l1; ++i)
	{
		const IMAGE_RESOURCE_DIRECTORY_ENTRY& type_entry = entries_l1[i];

		WORD type_id = 0;
		std::string type_name;

		if (type_entry.NameIsString)
		{
			DWORD name_offset = type_entry.NameOffset;
			if (resource_base_offset + name_offset + sizeof(WORD) < data_size)
			{
				const WORD* name_ptr = reinterpret_cast<const WORD*>(resource_base + name_offset);
				WORD name_len = *name_ptr;
				const wchar_t* name_chars = reinterpret_cast<const wchar_t*>(name_ptr + 1);

				for (WORD c = 0; c < name_len && resource_base_offset + name_offset + 2 + c * 2 < data_size; ++c)
				{
					type_name += static_cast<char>(name_chars[c]);
				}
			}
		}
		else
		{
			type_id = static_cast<WORD>(type_entry.Id);
		}

		if (!type_entry.DataIsDirectory)
			continue;

		DWORD type_dir_offset = type_entry.OffsetToDirectory;
		if (resource_base_offset + type_dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > data_size)
			continue;

		const IMAGE_RESOURCE_DIRECTORY* type_dir =
			reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(resource_base + type_dir_offset);

		WORD total_entries_l2 = type_dir->NumberOfNamedEntries + type_dir->NumberOfIdEntries;
		const IMAGE_RESOURCE_DIRECTORY_ENTRY* entries_l2 =
			reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(type_dir + 1);

		for (WORD j = 0; j < total_entries_l2; ++j)
		{
			const IMAGE_RESOURCE_DIRECTORY_ENTRY& name_entry = entries_l2[j];

			WORD resource_id = 0;
			std::string resource_name;

			if (name_entry.NameIsString)
			{
				DWORD name_offset = name_entry.NameOffset;
				if (resource_base_offset + name_offset + sizeof(WORD) < data_size)
				{
					const WORD* name_ptr = reinterpret_cast<const WORD*>(resource_base + name_offset);
					WORD name_len = *name_ptr;
					const wchar_t* name_chars = reinterpret_cast<const wchar_t*>(name_ptr + 1);

					for (WORD c = 0; c < name_len && resource_base_offset + name_offset + 2 + c * 2 < data_size; ++c)
					{
						resource_name += static_cast<char>(name_chars[c]);
					}
				}
			}
			else
			{
				resource_id = static_cast<WORD>(name_entry.Id);
			}

			if (!name_entry.DataIsDirectory)
				continue;

			DWORD name_dir_offset = name_entry.OffsetToDirectory;
			if (resource_base_offset + name_dir_offset + sizeof(IMAGE_RESOURCE_DIRECTORY) > data_size)
				continue;

			const IMAGE_RESOURCE_DIRECTORY* name_dir =
				reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY*>(resource_base + name_dir_offset);

			WORD total_entries_l3 = name_dir->NumberOfNamedEntries + name_dir->NumberOfIdEntries;
			const IMAGE_RESOURCE_DIRECTORY_ENTRY* entries_l3 =
				reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(name_dir + 1);

			for (WORD k = 0; k < total_entries_l3; ++k)
			{
				const IMAGE_RESOURCE_DIRECTORY_ENTRY& lang_entry = entries_l3[k];

				if (lang_entry.DataIsDirectory)
					continue;

				DWORD data_entry_offset = lang_entry.OffsetToData;
				if (resource_base_offset + data_entry_offset + sizeof(IMAGE_RESOURCE_DATA_ENTRY) > data_size)
					continue;

				const IMAGE_RESOURCE_DATA_ENTRY* data_entry =
					reinterpret_cast<const IMAGE_RESOURCE_DATA_ENTRY*>(resource_base + data_entry_offset);

				ResourceEntry entry{};
				entry.type_id = type_id;
				entry.type_name = std::move(type_name);
				entry.resource_id = resource_id;
				entry.resource_name = std::move(resource_name);
				entry.language_id = static_cast<WORD>(lang_entry.Id);
				entry.data_rva = data_entry->OffsetToData;
				entry.data_size = data_entry->Size;
				entry.file_offset = m_image->Utils().RvaToOffset(data_entry->OffsetToData);
				entry.code_page = data_entry->CodePage;

				entries.push_back(std::move(entry));
			}
		}
	}

	return entries;
}

std::vector<WORD> PE::_Resources::GetTypeIds() const noexcept
{
	std::vector<WORD> types;

	if (!Present())
		return types;

	auto root_dir = GetRootDirectory();
	if (!root_dir)
		return types;

	auto dir = m_image->DataDirectory().Get(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	DWORD resource_base_offset = m_image->Utils().RvaToOffset(dir->VirtualAddress);

	WORD total_entries = root_dir->NumberOfNamedEntries + root_dir->NumberOfIdEntries;
	const IMAGE_RESOURCE_DIRECTORY_ENTRY* entries =
		reinterpret_cast<const IMAGE_RESOURCE_DIRECTORY_ENTRY*>(root_dir + 1);

	types.reserve(total_entries);

	for (WORD i = 0; i < total_entries; ++i)
	{
		if (!entries[i].NameIsString)
		{
			types.push_back(static_cast<WORD>(entries[i].Id));
		}
	}

	return types;
}

size_t PE::_Resources::Count() const noexcept
{
	return GetAll().size();
}

std::vector<BYTE> PE::_Resources::GetResourceData(const ResourceEntry& entry) const noexcept
{
	std::vector<BYTE> resource_data;

	if (entry.file_offset == 0 || entry.data_size == 0)
		return resource_data;

	if (entry.file_offset + entry.data_size > m_image->Data().size())
		return resource_data;

	resource_data.resize(entry.data_size);
	std::memcpy(resource_data.data(), m_image->Data().data() + entry.file_offset, entry.data_size);

	return resource_data;
}

std::string_view PE::_Resources::GetManifest() const noexcept
{
	if (!Present())
		return {};

	auto manifests = GetByType(RT_MANIFEST);
	if (manifests.empty())
		return {};

	const ResourceEntry& manifest = manifests[0];
	if (manifest.file_offset == 0 || manifest.data_size == 0)
		return {};

	if (manifest.file_offset + manifest.data_size > m_image->Data().size())
		return {};

	return std::string_view(
		reinterpret_cast<const char*>(m_image->Data().data() + manifest.file_offset),
		manifest.data_size);
}

std::optional<VersionInfo> PE::_Resources::GetVersionInfo() const noexcept
{
	if (!Present())
		return std::nullopt;

	auto versions = GetByType(RT_VERSION);
	if (versions.empty())
		return std::nullopt;

	const ResourceEntry& version_entry = versions[0];
	if (version_entry.file_offset == 0 || version_entry.data_size < 92)
		return std::nullopt;

	if (version_entry.file_offset + version_entry.data_size > m_image->Data().size())
		return std::nullopt;

	const BYTE* version_data = m_image->Data().data() + version_entry.file_offset;

	constexpr DWORD VS_FFI_SIGNATURE = 0xFEEF04BD; //Had to Research this //https://crashpad.chromium.org/doxygen/verrsrc_8h.html#a323849bf0740c974e68b19ae551e1a18
	const DWORD* search_ptr = reinterpret_cast<const DWORD*>(version_data);
	const DWORD* search_end = reinterpret_cast<const DWORD*>(version_data + version_entry.data_size - sizeof(DWORD) * 13);

	while (search_ptr < search_end)
	{
		if (*search_ptr == VS_FFI_SIGNATURE)
		{

			VersionInfo info{};

			DWORD file_version_ms = search_ptr[2];
			DWORD file_version_ls = search_ptr[3];
			DWORD product_version_ms = search_ptr[4];
			DWORD product_version_ls = search_ptr[5];

			info.major = static_cast<WORD>((file_version_ms >> 16) & 0xFFFF);
			info.minor = static_cast<WORD>(file_version_ms & 0xFFFF);
			info.build = static_cast<WORD>((file_version_ls >> 16) & 0xFFFF);
			info.revision = static_cast<WORD>(file_version_ls & 0xFFFF);

			info.product_major = static_cast<WORD>((product_version_ms >> 16) & 0xFFFF);
			info.product_minor = static_cast<WORD>(product_version_ms & 0xFFFF);
			info.product_build = static_cast<WORD>((product_version_ls >> 16) & 0xFFFF);
			info.product_revision = static_cast<WORD>(product_version_ls & 0xFFFF);

			info.file_flags = search_ptr[7];
			info.file_os = search_ptr[8];
			info.file_type = search_ptr[9];

			return info;
		}

		search_ptr++;
	}

	return std::nullopt;
}


// RICH HEADER


bool PE::_RichHeader::Present() const noexcept
{
	if (!m_image || !m_image->IsValid())
		return false;

	auto dos = m_image->DosHeader().Get();
	if (!dos)
		return false;

	const BYTE* data = m_image->Data().data();
	size_t nt_offset = dos->e_lfanew;

	if (nt_offset < sizeof(IMAGE_DOS_HEADER) + 8)
		return false;

	const DWORD* search = reinterpret_cast<const DWORD*>(data + nt_offset - sizeof(DWORD));
	const DWORD* search_end = reinterpret_cast<const DWORD*>(data + sizeof(IMAGE_DOS_HEADER));

	while (search > search_end)
	{
		if (*search == RICH_SIGNATURE)
			return true;
		search--;
	}

	return false;
}

DWORD PE::_RichHeader::GetRawOffset() const noexcept
{
	if (!Present())
	{
		return 0;
	}

	auto dos = m_image->DosHeader().Get();
	if (!dos)
	{
		return 0;
	}

	const BYTE* data = m_image->Data().data();
	size_t nt_offset = dos->e_lfanew;

	const DWORD* search =
		reinterpret_cast<const DWORD*>(data + nt_offset - sizeof(DWORD));
	const DWORD* search_end =
		reinterpret_cast<const DWORD*>(data + sizeof(IMAGE_DOS_HEADER));

	const DWORD* rich_ptr = nullptr;

	while (search > search_end)
	{
		if (*search == RICH_SIGNATURE)
		{
			rich_ptr = search;
			break;
		}
		--search;
	}

	if (!rich_ptr)
	{
		return 0;
	}

	DWORD checksum = *(rich_ptr + 1);

	const DWORD* scan = rich_ptr - 1;
	while (scan > search_end)
	{
		if ((*scan ^ checksum) == DANS_SIGNATURE)
		{
			return static_cast<DWORD>(
				reinterpret_cast<const BYTE*>(scan) - data);
		}
		--scan;
	}

	return 0;
}

DWORD PE::_RichHeader::GetRawSize(bool region_size) const noexcept
{
	auto dos = m_image->DosHeader().Get();
	if (!dos)
	{
		return 0;
	}

	const std::vector<BYTE>& image = m_image->Data();
	const BYTE* data = image.data();

	size_t nt_offset = dos->e_lfanew;
	if (nt_offset < sizeof(IMAGE_DOS_HEADER) || nt_offset > image.size())
	{
		return 0;
	}

	const DWORD* search =
		reinterpret_cast<const DWORD*>(data + nt_offset - sizeof(DWORD));
	const DWORD* search_end =
		reinterpret_cast<const DWORD*>(data + sizeof(IMAGE_DOS_HEADER));

	const DWORD* rich_ptr = nullptr;

	while (search > search_end)
	{
		if (*search == RICH_SIGNATURE)
		{
			rich_ptr = search;
			break;
		}
		--search;
	}

	if (!rich_ptr)
	{
		return 0;
	}

	DWORD checksum = *(rich_ptr + 1);

	const BYTE* rich_byte = reinterpret_cast<const BYTE*>(rich_ptr);
	const BYTE* dans_ptr = nullptr;

	for (size_t off = (rich_byte - data) - 4; off >= 4; --off)
	{
		DWORD v;
		memcpy(&v, data + off - 4, sizeof(DWORD));
		v ^= checksum;

		if (v == DANS_SIGNATURE)
		{
			dans_ptr = data + off - 4;
			break;
		}
	}

	if (!dans_ptr)
	{
		return 0;
	}

	DWORD dans_offset = static_cast<DWORD>(dans_ptr - data);

	DWORD rich_size =
		static_cast<DWORD>((rich_byte + 8) - dans_ptr);

	if (!region_size)
	{
		return rich_size;
	}

	return static_cast<DWORD>(nt_offset) - dans_offset;
}


DWORD PE::_RichHeader::GetChecksum() const noexcept
{
	if (!m_image || !m_image->IsValid())
		return 0;

	auto dos = m_image->DosHeader().Get();
	if (!dos)
		return 0;

	const BYTE* data = m_image->Data().data();
	size_t nt_offset = dos->e_lfanew;

	const DWORD* search = reinterpret_cast<const DWORD*>(data + nt_offset - sizeof(DWORD));
	const DWORD* search_end = reinterpret_cast<const DWORD*>(data + sizeof(IMAGE_DOS_HEADER));

	while (search > search_end)
	{
		if (*search == RICH_SIGNATURE)
		{
			return *(search + 1);
		}
		search--;
	}

	return 0;
}

std::vector<RichEntry> PE::_RichHeader::GetEntries() const noexcept
{
	std::vector<RichEntry> entries;

	if (!Present())
		return entries;

	DWORD start_offset = GetRawOffset();
	if (start_offset == 0)
		return entries;

	DWORD checksum = GetChecksum();
	if (checksum == 0)
		return entries;

	auto dos = m_image->DosHeader().Get();
	if (!dos)
		return entries;

	const BYTE* data = m_image->Data().data();
	size_t nt_offset = dos->e_lfanew;

	const DWORD* search = reinterpret_cast<const DWORD*>(data + nt_offset - sizeof(DWORD));
	const DWORD* search_end = reinterpret_cast<const DWORD*>(data + sizeof(IMAGE_DOS_HEADER));
	const DWORD* rich_ptr = nullptr;

	while (search > search_end)
	{
		if (*search == RICH_SIGNATURE)
		{
			rich_ptr = search;
			break;
		}
		search--;
	}

	if (!rich_ptr)
		return entries;

	const DWORD* entry_start = reinterpret_cast<const DWORD*>(data + start_offset + 16);
	const DWORD* entry_end = rich_ptr;

	while (entry_start + 1 < entry_end)
	{
		DWORD comp_id = entry_start[0] ^ checksum;
		DWORD count = entry_start[1] ^ checksum;

		RichEntry entry{};
		entry.build_id = static_cast<WORD>(comp_id & 0xFFFF);
		entry.product_id = static_cast<WORD>((comp_id >> 16) & 0xFFFF);
		entry.use_count = count;

		entries.push_back(entry);
		entry_start += 2;
	}

	return entries;
}

bool PE::_RichHeader::ValidateChecksum() const noexcept
{
	if (!Present())
		return false;

	DWORD stored_checksum = GetChecksum();
	if (stored_checksum == 0)
		return false;

	DWORD start_offset = GetRawOffset();
	if (start_offset == 0)
		return false;

	auto dos = m_image->DosHeader().Get();
	if (!dos)
		return false;

	const BYTE* data = m_image->Data().data();

	DWORD calc_checksum = start_offset;

	for (size_t i = 0; i < sizeof(IMAGE_DOS_HEADER); ++i)
	{
		if (i >= 0x3C && i < 0x40)
			continue;

		DWORD val = data[i];
		DWORD rot = i % 32;
		calc_checksum += (val << rot) | (val >> (32 - rot));
	}

	for (size_t i = sizeof(IMAGE_DOS_HEADER); i < start_offset; ++i)
	{
		DWORD val = data[i];
		DWORD rot = i % 32;
		calc_checksum += (val << rot) | (val >> (32 - rot));
	}

	auto entries = GetEntries();
	for (const auto& entry : entries)
	{
		DWORD comp_id = (static_cast<DWORD>(entry.product_id) << 16) | entry.build_id;
		DWORD rot = entry.use_count % 32; 
		calc_checksum += (comp_id << rot) | (comp_id >> (32 - rot));
	}

	return calc_checksum == stored_checksum;
}

std::string_view PE::_RichHeader::ProductIdToString(WORD product_id) noexcept
{

	switch (product_id)
	{
	case 0:
		return "Unknown";
	case 1:
		return "Import0";
	case 2:
		return "Linker510";
	case 3:
		return "Cvtomf510";
	case 4:
		return "Linker600";
	case 5:
		return "Cvtomf600";
	case 6:
		return "Cvtres500";
	case 7:
		return "Utc11_Basic";
	case 8:
		return "Utc11_C";
	case 9:
		return "Utc12_Basic";
	case 10:
		return "Utc12_C";
	case 11:
		return "Utc12_CPP";
	case 12:
		return "AliasObj60";
	case 13:
		return "VisualBasic60";
	case 14:
		return "Masm613";
	case 15:
		return "Masm710";
	case 16:
		return "Linker511";
	case 17:
		return "Cvtomf511";
	case 18:
		return "Masm614";
	case 19:
		return "Linker512";
	case 20:
		return "Cvtomf512";
	case 21:
		return "Utc12_C_Std";
	case 22:
		return "Utc12_CPP_Std";
	case 23:
		return "Utc12_C_Book";
	case 24:
		return "Utc12_CPP_Book";
	case 25:
		return "Implib700";
	case 26:
		return "Cvtomf700";
	case 27:
		return "Utc13_Basic";
	case 28:
		return "Utc13_C";
	case 29:
		return "Utc13_CPP";
	case 30:
		return "Linker610";
	case 31:
		return "Cvtomf610";
	case 32:
		return "Linker601";
	case 33:
		return "Cvtomf601";
	case 34:
		return "Utc12_1_Basic";
	case 35:
		return "Utc12_1_C";
	case 36:
		return "Utc12_1_CPP";
	case 37:
		return "Linker620";
	case 38:
		return "Cvtomf620";
	case 39:
		return "AliasObj70";
	case 40:
		return "Linker621";
	case 41:
		return "Cvtomf621";
	case 42:
		return "Masm615";
	case 43:
		return "Utc13_LTCG_C";
	case 44:
		return "Utc13_LTCG_CPP";
	case 45:
		return "Masm620";
	case 46:
		return "ILAsm100";
	case 47:
		return "Utc12_2_Basic";
	case 48:
		return "Utc12_2_C";
	case 49:
		return "Utc12_2_CPP";
	case 50:
		return "Utc12_2_C_Std";
	case 51:
		return "Utc12_2_CPP_Std";
	case 52:
		return "Utc12_2_C_Book";
	case 53:
		return "Utc12_2_CPP_Book";
	case 54:
		return "Implib622";
	case 55:
		return "Cvtomf622";
	case 56:
		return "Cvtres501";
	case 57:
		return "Utc13_C_Std";
	case 58:
		return "Utc13_CPP_Std";
	case 59:
		return "Cvtpgd1300";
	case 60:
		return "Linker622";
	case 61:
		return "Linker700";
	case 62:
		return "Export622";
	case 63:
		return "Export700";
	case 64:
		return "Masm700";
	case 65:
		return "Utc13_POGO_I_C";
	case 66:
		return "Utc13_POGO_I_CPP";
	case 67:
		return "Utc13_POGO_O_C";
	case 68:
		return "Utc13_POGO_O_CPP";
	case 69:
		return "Cvtres700";
	case 70:
		return "Cvtres710p";
	case 71:
		return "Linker710p";
	case 72:
		return "Cvtomf710p";
	case 73:
		return "Export710p";
	case 74:
		return "Implib710p";
	case 75:
		return "Masm710p";
	case 76:
		return "Utc1310p_C";
	case 77:
		return "Utc1310p_CPP";
	case 78:
		return "Utc1310p_C_Std";
	case 79:
		return "Utc1310p_CPP_Std";
	case 80:
		return "Utc1310p_LTCG_C";
	case 81:
		return "Utc1310p_LTCG_CPP";
	case 82:
		return "Utc1310p_POGO_I_C";
	case 83:
		return "Utc1310p_POGO_I_CPP";
	case 84:
		return "Utc1310p_POGO_O_C";
	case 85:
		return "Utc1310p_POGO_O_CPP";
	case 86:
		return "Linker624";
	case 87:
		return "Cvtomf624";
	case 88:
		return "Export624";
	case 89:
		return "Implib624";
	case 90:
		return "Linker710";
	case 91:
		return "Cvtomf710";
	case 92:
		return "Export710";
	case 93:
		return "Implib710";
	case 94:
		return "Cvtres710";
	case 95:
		return "Utc1310_C";
	case 96:
		return "Utc1310_CPP";
	case 97:
		return "Utc1310_C_Std";
	case 98:
		return "Utc1310_CPP_Std";
	case 99:
		return "Utc1310_LTCG_C";
	case 100:
		return "Utc1310_LTCG_CPP";
	case 101:
		return "Utc1310_POGO_I_C";
	case 102:
		return "Utc1310_POGO_I_CPP";
	case 103:
		return "Utc1310_POGO_O_C";
	case 104:
		return "Utc1310_POGO_O_CPP";
	case 105:
		return "AliasObj710";
	case 106:
		return "AliasObj710p";
	case 107:
		return "Cvtpgd1310";
	case 108:
		return "Cvtpgd1310p";
	case 109:
		return "Utc1400_C";
	case 110:
		return "Utc1400_CPP";
	case 111:
		return "Utc1400_C_Std";
	case 112:
		return "Utc1400_CPP_Std";
	case 113:
		return "Utc1400_LTCG_C";
	case 114:
		return "Utc1400_LTCG_CPP";
	case 115:
		return "Utc1400_POGO_I_C";
	case 116:
		return "Utc1400_POGO_I_CPP";
	case 117:
		return "Utc1400_POGO_O_C";
	case 118:
		return "Utc1400_POGO_O_CPP";
	case 119:
		return "Cvtpgd1400";
	case 120:
		return "Linker800";
	case 121:
		return "Cvtomf800";
	case 122:
		return "Export800";
	case 123:
		return "Implib800";
	case 124:
		return "Cvtres800";
	case 125:
		return "Masm800";
	case 126:
		return "AliasObj800";
	case 127:
		return "PhoenixPrerelease";
	case 128:
		return "Utc1400_CVTCIL_C";
	case 129:
		return "Utc1400_CVTCIL_CPP";
	case 130:
		return "Utc1400_LTCG_MSIL";
	case 131:
		return "Utc1500_C";
	case 132:
		return "Utc1500_CPP";
	case 133:
		return "Utc1500_C_Std";
	case 134:
		return "Utc1500_CPP_Std";
	case 135:
		return "Utc1500_CVTCIL_C";
	case 136:
		return "Utc1500_CVTCIL_CPP";
	case 137:
		return "Utc1500_LTCG_C";
	case 138:
		return "Utc1500_LTCG_CPP";
	case 139:
		return "Utc1500_LTCG_MSIL";
	case 140:
		return "Utc1500_POGO_I_C";
	case 141:
		return "Utc1500_POGO_I_CPP";
	case 142:
		return "Utc1500_POGO_O_C";
	case 143:
		return "Utc1500_POGO_O_CPP";
	case 144:
		return "Cvtpgd1500";
	case 145:
		return "Linker900";
	case 146:
		return "Export900";
	case 147:
		return "Implib900";
	case 148:
		return "Cvtres900";
	case 149:
		return "Masm900";
	case 150:
		return "AliasObj900";
	case 151:
		return "Resource900";
	case 152:
		return "AliasObj1000";
	case 154:
		return "Cvtres1000";
	case 155:
		return "Export1000";
	case 156:
		return "Implib1000";
	case 157:
		return "Linker1000";
	case 158:
		return "Masm1000";
	case 170:
		return "Utc1600_C";
	case 171:
		return "Utc1600_CPP";
	case 172:
		return "Utc1600_CVTCIL_C";
	case 173:
		return "Utc1600_CVTCIL_CPP";
	case 174:
		return "Utc1600_LTCG_C";
	case 175:
		return "Utc1600_LTCG_CPP";
	case 176:
		return "Utc1600_LTCG_MSIL";
	case 177:
		return "Utc1600_POGO_I_C";
	case 178:
		return "Utc1600_POGO_I_CPP";
	case 179:
		return "Utc1600_POGO_O_C";
	case 180:
		return "Utc1600_POGO_O_CPP";
	case 183:
		return "Linker1010";
	case 184:
		return "Export1010";
	case 185:
		return "Implib1010";
	case 186:
		return "Cvtres1010";
	case 187:
		return "Masm1010";
	case 188:
		return "AliasObj1010";
	case 199:
		return "AliasObj1100";
	case 201:
		return "Cvtres1100";
	case 202:
		return "Export1100";
	case 203:
		return "Implib1100";
	case 204:
		return "Linker1100";
	case 205:
		return "Masm1100";
	case 206:
		return "Utc1700_C";
	case 207:
		return "Utc1700_CPP";
	case 208:
		return "Utc1700_CVTCIL_C";
	case 209:
		return "Utc1700_CVTCIL_CPP";
	case 210:
		return "Utc1700_LTCG_C";
	case 211:
		return "Utc1700_LTCG_CPP";
	case 212:
		return "Utc1700_LTCG_MSIL";
	case 213:
		return "Utc1700_POGO_I_C";
	case 214:
		return "Utc1700_POGO_I_CPP";
	case 215:
		return "Utc1700_POGO_O_C";
	case 216:
		return "Utc1700_POGO_O_CPP";
	case 219:
		return "Cvtres1200";
	case 220:
		return "Export1200";
	case 221:
		return "Implib1200";
	case 222:
		return "Linker1200";
	case 223:
		return "Masm1200";
	case 224:
		return "AliasObj1200";
	case 237:
		return "Cvtres1210";
	case 238:
		return "Export1210";
	case 239:
		return "Implib1210";
	case 240:
		return "Linker1210";
	case 241:
		return "Masm1210";
	case 242:
		return "Utc1810_C";
	case 243:
		return "Utc1810_CPP";
	case 244:
		return "Utc1810_CVTCIL_C";
	case 245:
		return "Utc1810_CVTCIL_CPP";
	case 246:
		return "Utc1810_LTCG_C";
	case 247:
		return "Utc1810_LTCG_CPP";
	case 248:
		return "Utc1810_LTCG_MSIL";
	case 249:
		return "Utc1810_POGO_I_C";
	case 250:
		return "Utc1810_POGO_I_CPP";
	case 251:
		return "Utc1810_POGO_O_C";
	case 252:
		return "Utc1810_POGO_O_CPP";
	case 255:
		return "Cvtres1400";
	case 256:
		return "Export1400";
	case 257:
		return "Implib1400";
	case 258:
		return "Linker1400";
	case 259:
		return "Masm1400";
	case 260:
		return "Utc1900_C";
	case 261:
		return "Utc1900_CPP";
	case 262:
		return "Utc1900_CVTCIL_C";
	case 263:
		return "Utc1900_CVTCIL_CPP";
	case 264:
		return "Utc1900_LTCG_C";
	case 265:
		return "Utc1900_LTCG_CPP";
	case 266:
		return "Utc1900_LTCG_MSIL";
	case 267:
		return "Utc1900_POGO_I_C";
	case 268:
		return "Utc1900_POGO_I_CPP";
	case 269:
		return "Utc1900_POGO_O_C";
	case 270:
		return "Utc1900_POGO_O_CPP";
	default:
		return "Unknown";
	}
}