
/* image.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#pragma once
#include "defs.hpp"

namespace PE
{

	/*
	* @brief Represents a Portable Executable image.
	*/
	class Image
	{
	private:
		bool m_valid = false;
		std::uint16_t m_magic{ 0 };

		const char* m_path = nullptr;
		std::vector<std::uint8_t> m_data;

		// Main validation
		[[nodiscard]] bool ValidateImage() noexcept;

		// Validation helpers
		[[nodiscard]] bool ValidateNT()    const noexcept;
		[[nodiscard]] bool ValidateDOS()   const noexcept;
		[[nodiscard]] bool ValidateOptional() const noexcept;

	public:
		explicit Image(const char* path);						// from file
		explicit Image(std::vector<std::uint8_t> data);			// owning move
		explicit Image(const std::uint8_t* data, size_t size);	// from memory

		Image(const Image&) = delete;
		Image& operator=(const Image&) = delete;

		[[nodiscard]] __forceinline constexpr bool  IsValid() const noexcept(true) { return m_valid; }
		__forceinline constexpr bool IsPE32()		const noexcept(true) { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
		__forceinline constexpr bool IsPE64()		const noexcept(true) { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }
		const std::vector<std::uint8_t>&  Data()	const noexcept(true) { return m_data; }

		/*
		* @brief Retrieves the DOS header of the image.
		*/
		const ImageDosHeader* GetDOSHeader() const noexcept { return reinterpret_cast<const ImageDosHeader*>(m_data.data()); }

		/*
		* @brief Retrieves the NT headers of the image.
		* @tparam T The type of the NT headers (ImageNtHeaders32 or ImageNtHeaders64).
		*/
		template<typename T>
		const T* GetNTHeaders() const noexcept
		{
			static_assert(std::is_same_v<T, ImageNtHeaders32> ||
				std::is_same_v<T, ImageNtHeaders64>,
				"Type must be ImageNtHeaders32 or ImageNtHeaders64");
			if constexpr (std::is_same_v<T, ImageNtHeaders32>)
			{
				if (IsPE32())
				{
					const auto offset = GetDOSHeader()->e_lfanew;
					return reinterpret_cast<const ImageNtHeaders32*>(m_data.data() + offset);
				}
			}
			else
			{
				if (IsPE64())
				{
					const auto offset = GetDOSHeader()->e_lfanew;
					return reinterpret_cast<const ImageNtHeaders64*>(m_data.data() + offset);
				}
			}
			return nullptr;
		}

		/*
		* @brief Retrieves the optional header of the image.
		* @tparam T The type of the optional header (ImageOptionalHeader32 or ImageOptionalHeader64).
		*/
		template <typename T>
		const T* GetOptionalHeader() const noexcept
		{
			static_assert(std::is_same_v<T, ImageOptionalHeader32> ||
				std::is_same_v<T, ImageOptionalHeader64>,
				"Type must be ImageOptionalHeader32 or ImageOptionalHeader64");
			if constexpr (std::is_same_v<T, ImageOptionalHeader32>)
			{
				if (IsPE32())
				{
					const auto offset = GetDOSHeader()->e_lfanew + sizeof(std::uint32_t) + sizeof(ImageFileHeader);
					return reinterpret_cast<const ImageOptionalHeader32*>(m_data.data() + offset);
				}
			}
			else
			{
				if (IsPE64())
				{
					const auto offset = GetDOSHeader()->e_lfanew + sizeof(std::uint32_t) + sizeof(ImageFileHeader);
					return reinterpret_cast<const ImageOptionalHeader64*>(m_data.data() + offset);
				}
			}
			return nullptr;
		}
	};

	class ImageUtils
	{
	public:
		ImageUtils(Image* image) : m_image(image) {}

		bool StripPDBInfo() const noexcept;
		bool PatternScan(const char* pattern, const char* mask, uintptr_t* out) const noexcept;
		std::uint64_t RvaToVa(std::uint32_t rva) const noexcept;
		std::uint32_t RvaToOffset(std::uint32_t rva) const noexcept;
		std::uint32_t VaToRva(std::uint64_t va) const noexcept;
		std::uint32_t OffsetToRva(std::uint32_t file_offset) const noexcept;
		std::vector<std::string_view>  GetAsciiStrings(std::uint32_t min_length) const noexcept;
		std::vector<std::wstring_view> GetUnicodeStrings(std::uint32_t min_length) const noexcept;

	private:
		Image* m_image;

	};
};