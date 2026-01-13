
/* directories_impl.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#include <string>
#include "directories.hpp"

const PE::ImageDataDirectory* PE::DataDirectory::Get(std::uint16_t index) const noexcept
{
	if (!m_image || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
	{
		return nullptr;
	}

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
	{
		return nullptr;
	}

	size_t nt_offset = dos_header->e_lfanew;
	size_t optional_offset = nt_offset + sizeof(std::uint32_t) + sizeof(ImageFileHeader);

	if (optional_offset + sizeof(std::uint16_t) > m_image->Data().size())
		return nullptr;

	std::uint16_t magic = *reinterpret_cast<const std::uint16_t*>(m_image->Data().data() + optional_offset);

	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		auto optional = m_image->GetOptionalHeader<ImageOptionalHeader64>();
		if (!optional || index >= optional->NumberOfRvaAndSizes)
		{
			return nullptr;
		}

		return &optional->DataDirectory[index];
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		auto optional = m_image->GetOptionalHeader<ImageOptionalHeader32>();
		if (!optional || index >= optional->NumberOfRvaAndSizes)
		{
			return nullptr;
		}

		return &optional->DataDirectory[index];
	}

	return nullptr;
}

bool PE::DataDirectory::Exists(std::uint16_t index) const noexcept
{
	auto dir = Get(index);
	return dir && dir->VirtualAddress != 0 && dir->Size != 0;
}

// Imports

PE::Imports::Imports(Image* image) : m_image(image)
{
	m_present = DataDirectory(m_image).Exists(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

std::vector<std::string_view> PE::Imports::GetImportedModules() const noexcept
{
	std::vector<std::string_view> dlls;

	auto desc = GetDescriptors();
	if (!desc)
		return dlls;

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	size_t desc_offset = reinterpret_cast<const std::uint8_t*>(desc) - data;

	while (desc_offset + sizeof(ImageImportDescriptor) <= data_size)
	{
		desc = reinterpret_cast<const ImageImportDescriptor*>(data + desc_offset);

		if (desc->Name == 0)
		{
			break;
		}

		std::uint32_t name_offset = ImageUtils(m_image).RvaToOffset(desc->Name);
		if (name_offset != 0 && name_offset < data_size)
		{
			const char* name = reinterpret_cast<const char*>(data + name_offset);

			size_t max_len = data_size - name_offset;
			size_t name_len = strnlen(name, max_len);

			if (name_len < max_len)
			{
				dlls.emplace_back(name);
			}
		}

		desc_offset += sizeof(ImageImportDescriptor);
	}

	return dlls;
}

std::vector<PE::ImportFunction> PE::Imports::FunctionFromModule(const char* dll_name) const noexcept
{
	std::vector<ImportFunction> functions;

	auto desc = GetDescriptors();
	if (!desc || !dll_name)
	{
		return functions;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	size_t desc_offset = reinterpret_cast<const std::uint8_t*>(desc) - data;

	while (desc_offset + sizeof(ImageImportDescriptor) <= data_size)
	{
		desc = reinterpret_cast<const ImageImportDescriptor*>(data + desc_offset);

		if (desc->Name == 0)
		{
			break;
		}

		std::uint32_t name_offset = ImageUtils(m_image).RvaToOffset(desc->Name);
		if (name_offset == 0 || name_offset >= data_size)
		{
			desc_offset += sizeof(ImageImportDescriptor);
			continue;
		}

		const char* current_dll = reinterpret_cast<const char*>(data + name_offset);

		size_t max_dll_len = data_size - name_offset;
		size_t dll_len = strnlen(current_dll, max_dll_len);
		if (dll_len >= max_dll_len)
		{
			desc_offset += sizeof(ImageImportDescriptor);
			continue;
		}

		if (_stricmp(current_dll, dll_name) != 0)
		{
			desc_offset += sizeof(ImageImportDescriptor);
			continue;
		}

		std::uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
		std::uint32_t thunk_offset = ImageUtils(m_image).RvaToOffset(thunk_rva);

		if (thunk_offset == 0)
		{
			break;
		}

		if (m_image->IsPE64())
		{
			while (thunk_offset + sizeof(ImageThunkData64) <= data_size)
			{
				auto thunk = reinterpret_cast<const ImageThunkData64*>(data + thunk_offset);

				if (thunk->u1.AddressOfData == 0)
				{
					break;
				}

				ImportFunction func{};

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
				{
					func.is_ordinal = true;
					func.ordinal = static_cast<std::uint16_t>(thunk->u1.Ordinal & 0xFFFF);
					func.hint = 0;
				}
				else
				{
					std::uint32_t hint_offset = ImageUtils(m_image).RvaToOffset(
						static_cast<std::uint32_t>(thunk->u1.AddressOfData));

					if (hint_offset != 0 && hint_offset + sizeof(ImageImportByName) <= data_size)
					{
						auto import_by_name = reinterpret_cast<const ImageImportByName*>(
							data + hint_offset);

						func.is_ordinal = false;
						func.ordinal = 0;
						func.hint = import_by_name->Hint;

						size_t name_start = hint_offset + offsetof(ImageImportByName, Name);
						size_t max_name_len = data_size - name_start;
						size_t name_len = strnlen(import_by_name->Name, max_name_len);

						if (name_len < max_name_len)
						{
							func.name = std::string_view(import_by_name->Name, name_len);
						}
					}
				}

				functions.push_back(func);
				thunk_offset += sizeof(ImageThunkData64);
			}
		}
		else
		{
			while (thunk_offset + sizeof(ImageThunkData32) <= data_size)
			{
				auto thunk = reinterpret_cast<const ImageThunkData32*>(data + thunk_offset);

				if (thunk->u1.AddressOfData == 0)
					break;

				ImportFunction func{};

				if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
				{
					func.is_ordinal = true;
					func.ordinal = static_cast<std::uint16_t>(thunk->u1.Ordinal & 0xFFFF);
					func.hint = 0;
				}
				else
				{
					std::uint32_t hint_offset = ImageUtils(m_image).RvaToOffset(thunk->u1.AddressOfData);

					if (hint_offset != 0 && hint_offset + sizeof(IMAGE_IMPORT_BY_NAME) <= data_size)
					{
						auto import_by_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
							data + hint_offset);

						func.is_ordinal = false;
						func.ordinal = 0;
						func.hint = import_by_name->Hint;

						size_t name_start = hint_offset + offsetof(IMAGE_IMPORT_BY_NAME, Name);
						size_t max_name_len = data_size - name_start;
						size_t name_len = strnlen(import_by_name->Name, max_name_len);
						if (name_len < max_name_len)
						{
							func.name = std::string_view(import_by_name->Name, name_len);
						}
					}
				}

				functions.push_back(func);
				thunk_offset += sizeof(ImageThunkData32);
			}
		}

		return functions;
	}

	return functions;
}

const PE::ImageImportDescriptor* PE::Imports::GetDescriptors() const noexcept
{
	if (!m_present)
	{
		return nullptr;
	}

	return DataDirectory(m_image).GetDirectory<ImageImportDescriptor>(IMAGE_DIRECTORY_ENTRY_IMPORT);
}

size_t PE::Imports::GetModuleCount() const noexcept
{
	if (!m_image)
		return 0;

	auto dir = DataDirectory(m_image).Get(IMAGE_DIRECTORY_ENTRY_IMPORT);
	if (!dir || dir->Size < sizeof(ImageImportDescriptor))
		return 0;

	std::uint32_t imports_offset = ImageUtils(m_image).RvaToOffset(dir->VirtualAddress);
	if (imports_offset == 0)
		return 0;

	const std::uint8_t* data = m_image->Data().data();
	const size_t data_size = m_image->Data().size();

	if (imports_offset >= data_size)
		return 0;

	size_t table_size = dir->Size;
	if (imports_offset + table_size > data_size)
		table_size = data_size - imports_offset;

	const size_t max_descriptors = table_size / sizeof(ImageImportDescriptor);
	const auto* desc = reinterpret_cast<const ImageImportDescriptor*>(data + imports_offset);

	size_t count = 0;
	for (size_t i = 0; i < max_descriptors; ++i, ++desc)
	{
		if (desc->Name == 0)
			break;

		count++;
	}

	return count;
}

std::vector<PE::ImportEntry> PE::Imports::GetAllImports() const noexcept
{
	std::vector<ImportEntry> entries;

	auto dll_names = GetImportedModules();
	entries.reserve(dll_names.size());

	for (const auto& dll : dll_names)
	{
		ImportEntry entry{};
		entry.dll_name = dll;
		entry.functions = FunctionFromModule(dll.data());
		entries.push_back(std::move(entry));
	}

	return entries;
}

// Exports

PE::Exports::Exports(Image* image) : m_image(image)
{
	m_present = DataDirectory(m_image).Exists(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

std::vector<PE::ExportFunction> PE::Exports::All() const noexcept
{
	std::vector<ExportFunction> exports;

	auto exp_dir = GetDescriptor();
	if (!exp_dir)
	{
		return exports;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();

	constexpr std::uint32_t MAX_EXPORTS = 65536;

	std::uint32_t num_functions = exp_dir->NumberOfFunctions;
	std::uint32_t num_names = exp_dir->NumberOfNames;

	if (num_functions > MAX_EXPORTS || num_names > MAX_EXPORTS)
		return exports;

	std::uint64_t image_base = 0;
	if (m_image->IsPE64())
	{
		auto opt = m_image->GetOptionalHeader<ImageOptionalHeader64>();
		if (opt)
		{
			image_base = opt->ImageBase;
		}
	}
	else
	{
		auto opt = m_image->GetOptionalHeader<ImageOptionalHeader32>();
		if (opt)
		{
			image_base = opt->ImageBase;
		}
	}

	auto dir_entry = DataDirectory(m_image).Get(IMAGE_DIRECTORY_ENTRY_EXPORT);
	std::uint32_t export_dir_start = dir_entry ? dir_entry->VirtualAddress : 0;
	std::uint32_t export_dir_end = dir_entry ? (dir_entry->VirtualAddress + dir_entry->Size) : 0;

	std::uint32_t functions_offset = ImageUtils(m_image).RvaToOffset(exp_dir->AddressOfFunctions);
	std::uint32_t names_offset = ImageUtils(m_image).RvaToOffset(exp_dir->AddressOfNames);
	std::uint32_t ordinals_offset = ImageUtils(m_image).RvaToOffset(exp_dir->AddressOfNameOrdinals);

	if (functions_offset == 0)
	{
		return exports;
	}

	if (functions_offset + static_cast<size_t>(num_functions) * sizeof(std::uint32_t) > data_size)
		return exports;

	const std::uint32_t* functions = reinterpret_cast<const std::uint32_t*>(data + functions_offset);

	const std::uint32_t* names = nullptr;
	const std::uint16_t* ordinals = nullptr;

	if (names_offset != 0 && ordinals_offset != 0)
	{
		if (names_offset + static_cast<size_t>(num_names) * sizeof(std::uint32_t) > data_size)
		{
			num_names = 0;
		}
		else if (ordinals_offset + static_cast<size_t>(num_names) * sizeof(std::uint16_t) > data_size)
		{
			num_names = 0;
		}
		else
		{
			names = reinterpret_cast<const std::uint32_t*>(data + names_offset);
			ordinals = reinterpret_cast<const std::uint16_t*>(data + ordinals_offset);
		}
	}

	std::vector<std::uint32_t> ordinal_to_name_idx(num_functions, std::uint32_t(-1));
	if (names && ordinals)
	{
		for (std::uint32_t j = 0; j < num_names; ++j)
		{
			std::uint16_t ord_idx = ordinals[j];
			if (ord_idx < num_functions)
			{
				ordinal_to_name_idx[ord_idx] = j;
			}
		}
	}

	exports.reserve(num_functions);

	for (std::uint32_t i = 0; i < num_functions; ++i)
	{
		std::uint32_t func_rva = functions[i];

		if (func_rva == 0)
		{
			continue;
		}

		ExportFunction exp{};
		exp.rva = func_rva;
		exp.va = image_base + func_rva;
		exp.file_offset = ImageUtils(m_image).RvaToOffset(func_rva);
		exp.ordinal = static_cast<std::uint16_t>(i + exp_dir->Base);

		if (func_rva >= export_dir_start && func_rva < export_dir_end)
		{
			exp.is_forwarded = true;
			std::uint32_t forward_offset = ImageUtils(m_image).RvaToOffset(func_rva);
			if (forward_offset != 0 && forward_offset < data_size)
			{
				exp.forward_name = reinterpret_cast<const char*>(data + forward_offset);
			}
		}
		else
		{
			exp.is_forwarded = false;
		}

		// This is now O(1) instead of O(n2)
		if (names && ordinal_to_name_idx[i] != std::uint32_t(-1))
		{
			std::uint32_t name_idx = ordinal_to_name_idx[i];
			std::uint32_t name_offset = ImageUtils(m_image).RvaToOffset(names[name_idx]);
			if (name_offset != 0 && name_offset < data_size)
			{
				exp.name = reinterpret_cast<const char*>(data + name_offset);
			}
		}

		exports.push_back(exp);
	}

	return exports;
}

const PE::ImageExportDirectory* PE::Exports::GetDescriptor() const noexcept
{
	if (!m_present)
	{
		return nullptr;
	}

	return DataDirectory(m_image).GetDirectory<ImageExportDirectory>(IMAGE_DIRECTORY_ENTRY_EXPORT);
}

std::string_view PE::Exports::ModuleName() const noexcept
{
	auto exp_dir = GetDescriptor();
	if (!exp_dir || exp_dir->Name == 0)
		return {};

	std::uint32_t name_offset = ImageUtils(m_image).RvaToOffset(exp_dir->Name);
	if (name_offset == 0 || name_offset >= m_image->Data().size())
		return {};

	return reinterpret_cast<const char*>(m_image->Data().data() + name_offset);
}

size_t PE::Exports::Count() const noexcept
{
	auto exp_dir = GetDescriptor();
	if (!exp_dir)
		return 0;

	return exp_dir->NumberOfFunctions;
}

PE::ExportFunction PE::Exports::ByName(const char* name) const noexcept
{
	ExportFunction empty{};

	if (!name)
		return empty;

	auto all = All();
	for (const auto& exp : all)
	{
		if (!exp.name.empty() && _stricmp(exp.name.data(), name) == 0)
		{
			return exp;
		}
	}

	return empty;
}

PE::ExportFunction PE::Exports::ByOrdinal(std::uint16_t ordinal) const noexcept
{
	ExportFunction empty{};

	auto all = All();
	for (const auto& exp : all)
	{
		if (exp.ordinal == ordinal)
		{
			return exp;
		}
	}

	return empty;
}

// Relocations

PE::Relocations::Relocations(Image* image) : m_image(image)
{
	m_present = DataDirectory(m_image).Exists(IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

std::vector<PE::RelocationBlock> PE::Relocations::GetBlocks() const noexcept
{
	std::vector<RelocationBlock> blocks;

	if (!m_present)
	{
		return blocks;
	}

	auto dir = DataDirectory(m_image).Get(IMAGE_DIRECTORY_ENTRY_BASERELOC);
	if (!dir)
	{
		return blocks;
	}

	std::uint32_t reloc_offset = ImageUtils(m_image).RvaToOffset(dir->VirtualAddress);
	if (reloc_offset == 0)
	{
		return blocks;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	std::uint32_t total_size = dir->Size;
	std::uint32_t processed = 0;

	while (processed < total_size)
	{
		if (reloc_offset + processed + sizeof(ImageBaseRelocation) > data_size)
		{
			break;
		}

		const ImageBaseRelocation* block =
			reinterpret_cast<const ImageBaseRelocation*>(data + reloc_offset + processed);

		std::uint32_t block_size = block->SizeOfBlock;
		if (block_size == 0)
		{
			break;
		}

		if (block_size < sizeof(ImageBaseRelocation))
		{
			break;
		}

		if (block_size % 4 != 0)
		{
			break;
		}

		if (reloc_offset + processed + block_size > data_size)
		{
			break;
		}

		RelocationBlock reloc_block{};
		reloc_block.page_rva = block->VirtualAddress;

		std::uint32_t entry_count = (block->SizeOfBlock - sizeof(ImageBaseRelocation)) / sizeof(std::uint16_t);
		if (entry_count > 65536) // ~ 256KB of entries, more than enough.
		{
			break;
		}

		const std::uint16_t* entries = reinterpret_cast<const std::uint16_t*>(
			data + reloc_offset + processed + sizeof(ImageBaseRelocation));

		reloc_block.entries.reserve(entry_count);

		for (std::uint32_t i = 0; i < entry_count; ++i)
		{
			std::uint16_t entry = entries[i];
			std::uint16_t type = (entry >> 12) & 0x0F;
			std::uint16_t offset = entry & 0x0FFF;

			if (type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			RelocationEntry reloc_entry{};
			reloc_entry.type = type;
			reloc_entry.rva = block->VirtualAddress + offset;

			std::uint32_t file_offset = ImageUtils(m_image).RvaToOffset(reloc_entry.rva);
			if (file_offset != 0)
			{
				reloc_entry.file_offset = file_offset;
			}

			reloc_block.entries.push_back(reloc_entry);
		}

		blocks.push_back(std::move(reloc_block));
		processed += block->SizeOfBlock;
	}

	return blocks;
}

std::vector<PE::RelocationEntry> PE::Relocations::GetAllEntries() const noexcept
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

const PE::ImageBaseRelocation* PE::Relocations::GetRawTable() const noexcept
{
	if (!m_present)
	{
		return nullptr;
	}

	return DataDirectory(m_image).GetDirectory<ImageBaseRelocation>(IMAGE_DIRECTORY_ENTRY_BASERELOC);
}

size_t PE::Relocations::Count() const noexcept
{
	size_t count = 0;
	auto blocks = GetBlocks();

	for (const auto& block : blocks)
		count += block.entries.size();

	return count;
}

std::string_view PE::Relocations::TypeToString(std::uint16_t type) noexcept
{
	switch (type)
	{
	case IMAGE_REL_BASED_ABSOLUTE:
		return "ABSOLUTE";
	case IMAGE_REL_BASED_HIGH:
		return "HIGH";
	case IMAGE_REL_BASED_LOW:
		return "LOW";
	case IMAGE_REL_BASED_HIGHLOW:
		return "HIGHLOW";
	case IMAGE_REL_BASED_HIGHADJ:
		return "HIGHADJ";
	case IMAGE_REL_BASED_DIR64:
		return "DIR64";
	default:
		return "UNKNOWN";
	}
}

// Resources

PE::Resources::Resources(Image* image) : m_image(image)
{
	m_present = DataDirectory(m_image).Exists(IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

std::vector<PE::ResourceEntry> PE::Resources::GetAll() const noexcept
{
	std::vector<ResourceEntry> entries;

	if (!m_present)
	{
		return entries;
	}

	auto dir = DataDirectory(m_image).Get(IMAGE_DIRECTORY_ENTRY_RESOURCE);
	if (!dir)
	{
		return entries;
	}

	std::uint32_t resource_base_offset = ImageUtils(m_image).RvaToOffset(dir->VirtualAddress);
	if (resource_base_offset == 0)
	{
		return entries;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	const std::uint8_t* resource_base = data + resource_base_offset;

	auto root_dir = GetRootDirectory();
	if (!root_dir)
	{
		return entries;
	}

	constexpr std::uint16_t MAX_RESOURCE_ENTRIES = 4096;

	std::uint16_t total_entries_l1 = root_dir->NumberOfNamedEntries + root_dir->NumberOfIdEntries;
	if (total_entries_l1 > MAX_RESOURCE_ENTRIES)
	{
		return entries;
	}

	const ImageResourceDirectoryEntry* entries_l1 =
		reinterpret_cast<const ImageResourceDirectoryEntry*>(root_dir + 1);

	size_t entries_l1_offset = reinterpret_cast<const std::uint8_t*>(entries_l1) - data;
	size_t entries_l1_size = static_cast<size_t>(total_entries_l1) * sizeof(ImageResourceDirectoryEntry);
	if (entries_l1_offset + entries_l1_size > data_size)
	{
		return entries;
	}

	for (std::uint16_t i = 0; i < total_entries_l1; ++i)
	{
		const ImageResourceDirectoryEntry& type_entry = entries_l1[i];

		std::uint16_t type_id = 0;
		std::string type_name;

		if (type_entry.NameIsString)
		{
			std::uint32_t name_offset = type_entry.NameOffset;
			if (resource_base_offset + name_offset + sizeof(std::uint16_t) < data_size)
			{
				const std::uint16_t* name_ptr = reinterpret_cast<const std::uint16_t*>(resource_base + name_offset);
				std::uint16_t name_len = *name_ptr;
				if (name_len > 256)
				{
					name_len = 256;
				}

				const wchar_t* name_chars = reinterpret_cast<const wchar_t*>(name_ptr + 1);
				for (std::uint16_t c = 0; c < name_len && resource_base_offset + name_offset + 2 + c * 2 < data_size; ++c)
				{
					type_name += static_cast<char>(name_chars[c]);
				}
			}
		}
		else
		{
			type_id = static_cast<std::uint16_t>(type_entry.Id);
		}

		if (!type_entry.DataIsDirectory)
		{
			continue;
		}

		std::uint32_t type_dir_offset = type_entry.OffsetToDirectory;
		if (resource_base_offset + type_dir_offset + sizeof(ImageResourceDirectory) > data_size)
		{
			continue;
		}

		const ImageResourceDirectory* type_dir =
			reinterpret_cast<const ImageResourceDirectory*>(resource_base + type_dir_offset);

		std::uint16_t total_entries_l2 = type_dir->NumberOfNamedEntries + type_dir->NumberOfIdEntries;
		if (total_entries_l2 > MAX_RESOURCE_ENTRIES)
		{
			continue;
		}

		const ImageResourceDirectoryEntry* entries_l2 =
			reinterpret_cast<const ImageResourceDirectoryEntry*>(type_dir + 1);

		size_t entries_l2_offset = reinterpret_cast<const std::uint8_t*>(entries_l2) - data;
		size_t entries_l2_size = static_cast<size_t>(total_entries_l2) * sizeof(ImageResourceDirectoryEntry);
		if (entries_l2_offset + entries_l2_size > data_size)
		{
			continue;
		}

		for (std::uint16_t j = 0; j < total_entries_l2; ++j)
		{
			const ImageResourceDirectoryEntry& name_entry = entries_l2[j];

			std::uint16_t resource_id = 0;
			std::string resource_name;

			if (name_entry.NameIsString)
			{
				std::uint32_t name_offset = name_entry.NameOffset;
				if (resource_base_offset + name_offset + sizeof(std::uint16_t) < data_size)
				{
					const std::uint16_t* name_ptr = reinterpret_cast<const std::uint16_t*>(resource_base + name_offset);
					std::uint16_t name_len = *name_ptr;
					if (name_len > 256)
					{
						name_len = 256;
					}

					const wchar_t* name_chars = reinterpret_cast<const wchar_t*>(name_ptr + 1);
					for (std::uint16_t c = 0; c < name_len && resource_base_offset + name_offset + 2 + c * 2 < data_size; ++c)
					{
						resource_name += static_cast<char>(name_chars[c]);
					}
				}
			}
			else
			{
				resource_id = static_cast<std::uint16_t>(name_entry.Id);
			}

			if (!name_entry.DataIsDirectory)
			{
				continue;
			}

			std::uint32_t name_dir_offset = name_entry.OffsetToDirectory;
			if (resource_base_offset + name_dir_offset + sizeof(ImageResourceDirectory) > data_size)
			{
				continue;
			}

			const ImageResourceDirectory* name_dir =
				reinterpret_cast<const ImageResourceDirectory*>(resource_base + name_dir_offset);

			std::uint16_t total_entries_l3 = name_dir->NumberOfNamedEntries + name_dir->NumberOfIdEntries;
			if (total_entries_l3 > MAX_RESOURCE_ENTRIES)
			{
				continue;
			}

			const ImageResourceDirectoryEntry* entries_l3 =
				reinterpret_cast<const ImageResourceDirectoryEntry*>(name_dir + 1);

			size_t entries_l3_offset = reinterpret_cast<const std::uint8_t*>(entries_l3) - data;
			size_t entries_l3_size = static_cast<size_t>(total_entries_l3) * sizeof(ImageResourceDirectoryEntry);
			if (entries_l3_offset + entries_l3_size > data_size)
			{
				continue;
			}

			for (std::uint16_t k = 0; k < total_entries_l3; ++k)
			{
				const ImageResourceDirectoryEntry& lang_entry = entries_l3[k];

				if (lang_entry.DataIsDirectory)
				{
					continue;
				}

				std::uint32_t data_entry_offset = lang_entry.OffsetToData;
				if (resource_base_offset + data_entry_offset + sizeof(ImageResourceDataEntry) > data_size)
				{
					continue;
				}

				const ImageResourceDataEntry* data_entry =
					reinterpret_cast<const ImageResourceDataEntry*>(resource_base + data_entry_offset);

				ResourceEntry entry{};
				entry.type_id = type_id;
				entry.type_name = type_name;
				entry.resource_id = resource_id;
				entry.resource_name = resource_name;
				entry.language_id = static_cast<std::uint16_t>(lang_entry.Id);
				entry.data_rva = data_entry->OffsetToData;
				entry.data_size = data_entry->Size;
				entry.file_offset = ImageUtils(m_image).RvaToOffset(data_entry->OffsetToData);
				entry.code_page = data_entry->CodePage;

				entries.push_back(std::move(entry));

				if (entries.size() > 65536)
					return entries;
			}
		}
	}

	return entries;
}

const PE::ImageResourceDirectory* PE::Resources::GetRootDirectory() const noexcept
{
	if (!m_present)
	{
		return nullptr;
	}

	return DataDirectory(m_image).GetDirectory<ImageResourceDirectory>(IMAGE_DIRECTORY_ENTRY_RESOURCE);
}

std::vector<PE::ResourceEntry> PE::Resources::GetByType(std::uint16_t type_id) const noexcept
{
	std::vector<ResourceEntry> filtered;

	auto all = GetAll();
	for (auto& entry : all)
	{
		if (entry.type_id == type_id)
		{
			filtered.push_back(std::move(entry));
		}
	}

	return filtered;
}

std::vector<std::uint16_t> PE::Resources::GetTypeIds() const noexcept
{
	std::vector<std::uint16_t> types;

	if (!m_present)
	{
		return types;
	}

	auto root_dir = GetRootDirectory();
	if (!root_dir)
	{
		return types;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();

	std::uint16_t total_entries = root_dir->NumberOfNamedEntries + root_dir->NumberOfIdEntries;
	const ImageResourceDirectoryEntry* entries =
		reinterpret_cast<const ImageResourceDirectoryEntry*>(root_dir + 1);

	size_t entries_offset = reinterpret_cast<const std::uint8_t*>(entries) - data;
	size_t entries_size = static_cast<size_t>(total_entries) * sizeof(ImageResourceDirectoryEntry);

	if (entries_offset + entries_size > data_size)
	{
		return types;
	}

	types.reserve(total_entries);

	for (std::uint16_t i = 0; i < total_entries; ++i)
	{
		if (!entries[i].NameIsString)
		{
			types.push_back(static_cast<std::uint16_t>(entries[i].Id));
		}
	}

	return types;
}

size_t PE::Resources::Count() const noexcept
{
	return GetAll().size();
}

std::vector<std::uint8_t> PE::Resources::GetResourceData(const ResourceEntry& entry) const noexcept
{
	std::vector<std::uint8_t> resource_data;

	if (entry.file_offset == 0 || entry.data_size == 0)
		return resource_data;

	if (entry.file_offset + entry.data_size > m_image->Data().size())
		return resource_data;

	resource_data.resize(entry.data_size);
	std::memcpy(resource_data.data(), m_image->Data().data() + entry.file_offset, entry.data_size);

	return resource_data;
}

std::string_view PE::Resources::GetManifest() const noexcept
{
	if (!m_present)
	{
		return {};
	}

	auto manifests = GetByType(RT_MANIFEST);
	if (manifests.empty())
	{
		return {};
	}

	const ResourceEntry& manifest = manifests[0];
	if (manifest.file_offset == 0 || manifest.data_size == 0)
		return {};

	if (manifest.file_offset + manifest.data_size > m_image->Data().size())
		return {};

	return std::string_view(
		reinterpret_cast<const char*>(m_image->Data().data() + manifest.file_offset),
		manifest.data_size);
}

std::optional<PE::VersionInfo> PE::Resources::GetVersionInfo() const noexcept
{
	if (!m_present)
	{
		return std::nullopt;
	}

	auto versions = GetByType(RT_VERSION);
	if (versions.empty())
	{
		return std::nullopt;
	}

	const ResourceEntry& version_entry = versions[0];
	if (version_entry.file_offset == 0 || version_entry.data_size < 92)
		return std::nullopt;

	if (version_entry.file_offset + version_entry.data_size > m_image->Data().size())
		return std::nullopt;

	const std::uint8_t* version_data = m_image->Data().data() + version_entry.file_offset;

	constexpr std::uint32_t VS_FFI_SIGNATURE = 0xFEEF04BD; // Had to Research this //https://crashpad.chromium.org/doxygen/verrsrc_8h.html#a323849bf0740c974e68b19ae551e1a18
	const std::uint32_t* search_ptr = reinterpret_cast<const std::uint32_t*>(version_data);
	const std::uint32_t* search_end = reinterpret_cast<const std::uint32_t*>(version_data + version_entry.data_size - sizeof(std::uint32_t) * 13);

	while (search_ptr < search_end)
	{
		if (*search_ptr == VS_FFI_SIGNATURE)
		{

			VersionInfo info{};

			std::uint32_t file_version_ms = search_ptr[2];
			std::uint32_t file_version_ls = search_ptr[3];
			std::uint32_t product_version_ms = search_ptr[4];
			std::uint32_t product_version_ls = search_ptr[5];

			info.major = static_cast<std::uint16_t>((file_version_ms >> 16) & 0xFFFF);
			info.minor = static_cast<std::uint16_t>(file_version_ms & 0xFFFF);
			info.build = static_cast<std::uint16_t>((file_version_ls >> 16) & 0xFFFF);
			info.revision = static_cast<std::uint16_t>(file_version_ls & 0xFFFF);

			info.product_major = static_cast<std::uint16_t>((product_version_ms >> 16) & 0xFFFF);
			info.product_minor = static_cast<std::uint16_t>(product_version_ms & 0xFFFF);
			info.product_build = static_cast<std::uint16_t>((product_version_ls >> 16) & 0xFFFF);
			info.product_revision = static_cast<std::uint16_t>(product_version_ls & 0xFFFF);

			info.file_flags = search_ptr[7];
			info.file_os = search_ptr[8];
			info.file_type = search_ptr[9];

			return info;
		}

		search_ptr++;
	}

	return std::nullopt;
}

std::string_view PE::Resources::TypeToString(std::uint16_t type_id) noexcept
{
	switch (type_id)
	{
	case RT_CURSOR:
		return "CURSOR";
	case RT_BITMAP:
		return "BITMAP";
	case RT_ICON:
		return "ICON";
	case RT_MENU:
		return "MENU";
	case RT_DIALOG:
		return "DIALOG";
	case RT_STRING:
		return "STRING";
	case RT_FONTDIR:
		return "FONTDIR";
	case RT_FONT:
		return "FONT";
	case RT_ACCELERATOR:
		return "ACCELERATOR";
	case RT_RCDATA:
		return "RCDATA";
	case RT_MESSAGETABLE:
		return "MESSAGETABLE";
	case RT_GROUP_CURSOR:
		return "GROUP_CURSOR";
	case RT_GROUP_ICON:
		return "GROUP_ICON";
	case RT_VERSION:
		return "VERSION";
	case RT_MANIFEST:
		return "MANIFEST";
	default:
		return "UNKNOWN";
	}
}

// TLS

PE::TLS::TLS(Image* image) : m_image(image)
{
	m_present = DataDirectory(m_image).Exists(IMAGE_DIRECTORY_ENTRY_TLS);
}

const PE::ImageTlsDirectory32* PE::TLS::GetDirectory32() const noexcept
{
	if (!Present() || !m_image->IsPE32())
		return nullptr;

	return DataDirectory(m_image).GetDirectory<ImageTlsDirectory32>(IMAGE_DIRECTORY_ENTRY_TLS);
}

const PE::ImageTlsDirectory64* PE::TLS::GetDirectory64() const noexcept
{
	if (!m_present || !m_image->IsPE64())
		return nullptr;

	return DataDirectory(m_image).GetDirectory<ImageTlsDirectory64>(IMAGE_DIRECTORY_ENTRY_TLS);
}

template const PE::ImageTlsDirectory32* PE::TLS::GetDirectory<PE::ImageTlsDirectory32>() const noexcept;
template const PE::ImageTlsDirectory64* PE::TLS::GetDirectory<PE::ImageTlsDirectory64>() const noexcept;

PE::TLSInfo PE::TLS::GetInfo() const noexcept
{
	TLSInfo info{};

	if (!m_present)
	{
		return info;
	}

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
		info.raw_data_size = static_cast<std::uint32_t>(tls->EndAddressOfRawData - tls->StartAddressOfRawData);
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

std::vector<PE::TLSCallback> PE::TLS::GetCallbacks() const noexcept
{
	std::vector<TLSCallback> callbacks;

	if (!m_present)
	{
		return callbacks;
	}

	TLSInfo info = GetInfo();
	if (info.callbacks_va == 0)
	{
		return callbacks;
	}

	std::uint32_t callbacks_rva = ImageUtils(m_image).VaToRva(info.callbacks_va);
	if (callbacks_rva == 0)
	{
		return callbacks;
	}

	std::uint32_t callbacks_offset = ImageUtils(m_image).RvaToOffset(callbacks_rva);
	if (callbacks_offset == 0)
	{
		return callbacks;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();

	if (m_image->IsPE64())
	{
		const std::uint64_t* callback_array = reinterpret_cast<const std::uint64_t*>(data + callbacks_offset);

		while (callbacks_offset < data_size)
		{
			std::uint64_t callback_va = *callback_array;
			if (callback_va == 0)
			{
				break;
			}

			TLSCallback cb{};
			cb.va = callback_va;
			cb.rva = ImageUtils(m_image).VaToRva(callback_va);
			cb.file_offset = ImageUtils(m_image).RvaToOffset(cb.rva);

			callbacks.push_back(cb);
			callback_array++;
			callbacks_offset += sizeof(std::uint64_t);
		}
	}
	else
	{
		const std::uint32_t* callback_array = reinterpret_cast<const std::uint32_t*>(data + callbacks_offset);

		while (callbacks_offset < data_size)
		{
			std::uint32_t callback_va = *callback_array;
			if (callback_va == 0)
				break;

			TLSCallback cb{};
			cb.va = callback_va;
			cb.rva = ImageUtils(m_image).VaToRva(callback_va);
			cb.file_offset = ImageUtils(m_image).RvaToOffset(cb.rva);

			callbacks.push_back(cb);
			callback_array++;
			callbacks_offset += sizeof(std::uint32_t);
		}
	}

	return callbacks;
}

bool PE::TLS::HasCallbacks() const noexcept
{
	if (!m_present)
	{
		return false;
	}

	TLSInfo info = GetInfo();
	if (info.callbacks_va == 0)
	{
		return false;
	}

	std::uint32_t callbacks_rva = ImageUtils(m_image).VaToRva(info.callbacks_va);
	if (callbacks_rva == 0)
	{
		return false;
	}

	std::uint32_t callbacks_offset = ImageUtils(m_image).RvaToOffset(callbacks_rva);
	if (callbacks_offset == 0 || callbacks_offset >= m_image->Data().size())
	{
		return false;
	}

	const std::uint8_t* data = m_image->Data().data();

	if (m_image->IsPE64())
	{
		if (callbacks_offset + sizeof(std::uint64_t) > m_image->Data().size())
		{
			return false;
		}
		return *reinterpret_cast<const std::uint64_t*>(data + callbacks_offset) != 0;
	}
	else
	{
		if (callbacks_offset + sizeof(std::uint32_t) > m_image->Data().size())
		{
			return false;
		}
		return *reinterpret_cast<const std::uint32_t*>(data + callbacks_offset) != 0;
	}
}

// Debug

PE::Debug::Debug(Image* image) : m_image(image)
{
	m_present = DataDirectory(m_image).Exists(IMAGE_DIRECTORY_ENTRY_DEBUG);
}

std::vector<PE::DebugEntry> PE::Debug::GetAll() noexcept
{

	if (!m_present)
	{
		return {};
	}

	std::vector<DebugEntry> entries;
	auto directory = DataDirectory(m_image).Get(IMAGE_DIRECTORY_ENTRY_DEBUG);
	if (!directory)
	{
		return {};
	}

	std::uint32_t debug_offset = ImageUtils(m_image).RvaToOffset(directory->VirtualAddress);
	if (debug_offset == 0)
	{
		return {};
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t data_size = m_image->Data().size();
	size_t entry_count = directory->Size / sizeof(ImageDebugDirectory);

	for (size_t i = 0; i < entry_count; i++)
	{
		size_t entry_offset = debug_offset + i * sizeof(ImageDebugDirectory);
		if (entry_offset + sizeof(ImageDebugDirectory) > data_size)
		{
			break;
		}

		auto debug_entry = reinterpret_cast<const ImageDebugDirectory*>(data + entry_offset);
		DebugEntry entry{};
		entry.type = static_cast<std::uint16_t>(debug_entry->Type);
		entry.size = debug_entry->SizeOfData;
		entry.address_offset = debug_entry->PointerToRawData;

		if (debug_entry->AddressOfRawData < data_size)
		{
			entry.address_rva = debug_entry->AddressOfRawData;
		}

		entries.push_back(entry);
	}

	return entries;
}

PE::DebugEntry PE::Debug::GetByType(const std::uint16_t type_id) noexcept
{
	if (!m_present || type_id > 19 || type_id <= 0)
	{
		return {};
	}

	auto dir = GetAll();
	for (auto& debug_entry : dir)
	{
		if (debug_entry.type == type_id)
		{
			return debug_entry;
		}
	}

	return {};
}

std::string_view PE::Debug::TypeToString(const std::uint16_t type_id) const noexcept
{
	switch (type_id)
	{
	case IMAGE_DEBUG_TYPE_COFF:
		return "COFF";
	case IMAGE_DEBUG_TYPE_CODEVIEW:
		return "Codeview";
	case IMAGE_DEBUG_TYPE_FPO:
		return "FPO";
	case IMAGE_DEBUG_TYPE_MISC:
		return "MISC";
	case IMAGE_DEBUG_TYPE_EXCEPTION:
		return "Exception";
	case IMAGE_DEBUG_TYPE_FIXUP:
		return "Fixup";
	case IMAGE_DEBUG_TYPE_OMAP_TO_SRC:
		return "OMAP to Src";
	case IMAGE_DEBUG_TYPE_OMAP_FROM_SRC:
		return "OMAP from Src";
	case IMAGE_DEBUG_TYPE_BORLAND:
		return "Borland";
	case IMAGE_DEBUG_TYPE_RESERVED10:
		return "Reserved10";
	case IMAGE_DEBUG_TYPE_CLSID:
		return "CLSID";
	case IMAGE_DEBUG_TYPE_VC_FEATURE:
		return "VC Feature";
	case IMAGE_DEBUG_TYPE_POGO:
		return "POGO";
	case IMAGE_DEBUG_TYPE_ILTCG:
		return "ILTCG";
	case IMAGE_DEBUG_TYPE_MPX:
		return "MPX";
	case IMAGE_DEBUG_TYPE_REPRO:
		return "Repro";
	case IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS:
		return "Ex DLL Characteristics";
	default:
		return "Unknown";
	}
}
