#pragma once

#include "defs.hpp"

class Image;
namespace PE
{
	/*
	* @brief Represents the section table of a Portable Executable image.
	*
	* Provides access to IMAGE_SECTION_HEADER entries and allows adding
	* new sections to an existing PE image.
	*/
	class ImageSections
	{
	private:
		Image* m_image;
		bool m_valid = false;

		std::uint16_t m_number_of_sections = 0;
		const ImageSectionHeader* m_sections = nullptr;

	     template <typename NtHeaders_T> 
		 [[nodiscard]] void BuildSections() noexcept;

		template <typename NtHeaders_T>
		bool AddSection_T(const std::string_view& name, const std::vector<std::uint8_t>& content, std::uint32_t characteristics) noexcept;

	public:
		ImageSections(Image* image);

		__forceinline constexpr bool IsValid() const noexcept(true) { return m_valid; }
		__forceinline constexpr std::uint16_t Count() const noexcept { return m_number_of_sections; }

		const ImageSectionHeader* GetByName(const char* name) const noexcept;
		const ImageSectionHeader* GetByIndex(size_t index) const noexcept;
		const std::vector<const ImageSectionHeader*> GetAll() const noexcept;

		/*
		* @brief Adds a new section to the PE image.
		*
		* Updates the section table, section count and image size.
		*/
		bool AddSection(
			const std::string_view& name,
			const std::vector<uint8_t> content,
			std::uint32_t characteristics) noexcept;

		/*
		* @brief Aligns a value to the specified alignment boundary.
		*
		* Used for PE FileAlignment and SectionAlignment calculations.
		*/
		bool AlignUp(std::uint32_t value, std::uint32_t alignment, std::uint32_t& out) noexcept
		{
			if (alignment == 0)
				return false;

			std::uint64_t widened = (static_cast<std::uint64_t>(value) + alignment - 1) / alignment * alignment;
			if (widened > (std::numeric_limits<std::uint32_t>::max)())
				return false;

			out = static_cast<std::uint32_t>(widened);
			return true;
		}

	};
}