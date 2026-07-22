#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <type_traits>
#include <vector>

#include "defs.hpp"

namespace fuzz
{
	// Every fuzzed API result is folded into these volatile globals. Without
	// a sink, LTCG/WholeProgramOptimization is free to inline a call, see the
	// result is unused, and delete the parsing work - including the memory
	// reads ASan would have checked.
	inline volatile std::uint8_t  sink8 = 0;
	inline volatile std::uint64_t sink64 = 0;

	// Reads every byte so ASan checks the whole range, then stores the fold.
	inline void ConsumeBytes(const void* data, std::size_t size) noexcept
	{
		const auto* bytes = static_cast<const std::uint8_t*>(data);
		std::uint8_t acc = 0;
		for (std::size_t i = 0; i < size; ++i)
			acc ^= bytes[i];
		sink8 = acc;
	}

	template <typename T, std::enable_if_t<std::is_arithmetic_v<T> || std::is_enum_v<T>, int> = 0>
	void Consume(T value) noexcept
	{
		sink64 = static_cast<std::uint64_t>(value);
	}

	inline void Consume(const void* pointer) noexcept
	{
		sink64 = reinterpret_cast<std::uintptr_t>(pointer);
	}

	inline void Consume(std::string_view view) noexcept
	{
		Consume(view.size());
		ConsumeBytes(view.data(), view.size());
	}

	// Object representation of a struct whose bytes come straight from the
	// image (headers, directories). Use the field-wise overloads below for
	// library-built result structs, which may contain padding.
	template <typename T, std::enable_if_t<std::is_trivially_copyable_v<T>, int> = 0>
	void ConsumeObject(const T& value) noexcept
	{
		ConsumeBytes(&value, sizeof value);
	}

	template <typename T>
	void Consume(const std::vector<T>& items) noexcept;

	// Field-wise overloads: string_views are followed so the image bytes they
	// reference are actually read.
	inline void Consume(const PE::ImportFunction& f) noexcept
	{
		Consume(f.name);
		Consume(f.hint);
		Consume(f.ordinal);
		Consume(f.is_ordinal);
	}

	inline void Consume(const PE::ImportEntry& e) noexcept
	{
		Consume(e.dll_name);
		Consume(e.functions);
	}

	inline void Consume(const PE::ExportFunction& f) noexcept
	{
		Consume(f.name);
		Consume(f.rva);
		Consume(f.va);
		Consume(f.file_offset);
		Consume(f.ordinal);
		Consume(f.is_forwarded);
		Consume(f.forward_name);
	}

	inline void Consume(const PE::RelocationEntry& e) noexcept
	{
		Consume(e.rva);
		Consume(e.type);
		Consume(e.file_offset);
	}

	inline void Consume(const PE::RelocationBlock& b) noexcept
	{
		Consume(b.page_rva);
		Consume(b.entries);
	}

	inline void Consume(const PE::TLSCallback& c) noexcept
	{
		Consume(c.va);
		Consume(c.rva);
		Consume(c.file_offset);
	}

	inline void Consume(const PE::TLSInfo& info) noexcept
	{
		Consume(info.raw_data_start_va);
		Consume(info.raw_data_end_va);
		Consume(info.index_va);
		Consume(info.callbacks_va);
		Consume(info.zero_fill_size);
		Consume(info.characteristics);
		Consume(info.raw_data_size);
	}

	inline void Consume(const PE::ResourceEntry& e) noexcept
	{
		Consume(e.type_id);
		Consume(e.type_name);
		Consume(e.resource_id);
		Consume(e.resource_name);
		Consume(e.language_id);
		Consume(e.data_rva);
		Consume(e.data_size);
		Consume(e.file_offset);
		Consume(e.code_page);
	}

	inline void Consume(const PE::VersionInfo& v) noexcept
	{
		Consume(v.major);
		Consume(v.minor);
		Consume(v.build);
		Consume(v.revision);
		Consume(v.product_major);
		Consume(v.product_minor);
		Consume(v.product_build);
		Consume(v.product_revision);
		Consume(v.file_flags);
		Consume(v.file_os);
		Consume(v.file_type);
	}

	inline void Consume(const PE::DebugEntry& e) noexcept
	{
		Consume(e.type);
		Consume(e.size);
		Consume(e.address_rva);
		Consume(e.address_offset);
	}

	inline void Consume(const PE::RichEntry& e) noexcept
	{
		Consume(e.product_id);
		Consume(e.build_id);
		Consume(e.use_count);
	}

	template <typename T>
	void Consume(const std::vector<T>& items) noexcept
	{
		Consume(items.size());
		if constexpr (std::is_arithmetic_v<T>)
			ConsumeBytes(items.data(), items.size() * sizeof(T));
		else
			for (const auto& item : items)
				Consume(item);
	}

	// Input gate: identical for every target so one seed corpus works everywhere.
	constexpr std::size_t min_input = 64;
	constexpr std::size_t max_input = 50'000'000;

	inline bool InputInRange(std::size_t size) noexcept
	{
		return size >= min_input && size <= max_input;
	}

	// Fuzzer-chosen parameters (ordinals, type ids, lookup names) are drawn
	// from the tail of the input. They deliberately overlap the image bytes:
	// a corpus of real PEs stays valid as-is, while the mutator can still
	// steer parameter values through the file's last bytes.
	inline std::uint8_t ParamU8(const std::uint8_t* data, std::size_t size, std::size_t index) noexcept
	{
		return data[size - 1 - (index % min_input)];
	}

	inline std::uint16_t ParamU16(const std::uint8_t* data, std::size_t size, std::size_t index) noexcept
	{
		return static_cast<std::uint16_t>(ParamU8(data, size, index * 2) |
			(ParamU8(data, size, index * 2 + 1) << 8));
	}

	inline std::uint32_t ParamU32(const std::uint8_t* data, std::size_t size, std::size_t index) noexcept
	{
		return static_cast<std::uint32_t>(ParamU16(data, size, index * 2)) |
			(static_cast<std::uint32_t>(ParamU16(data, size, index * 2 + 1)) << 16);
	}

	inline std::uint64_t ParamU64(const std::uint8_t* data, std::size_t size, std::size_t index) noexcept
	{
		return static_cast<std::uint64_t>(ParamU32(data, size, index * 2)) |
			(static_cast<std::uint64_t>(ParamU32(data, size, index * 2 + 1)) << 32);
	}

	// A short NUL-terminated lookup name taken from the input tail, for
	// ByName-style APIs. Embedded NULs simply shorten the name.
	struct ParamName
	{
		char value[16];

		ParamName(const std::uint8_t* data, std::size_t size, std::size_t salt) noexcept
		{
			for (std::size_t i = 0; i + 1 < sizeof value; ++i)
				value[i] = static_cast<char>(ParamU8(data, size, salt + i));
			value[sizeof value - 1] = '\0';
		}
	};
}
