
/* sections.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#pragma once

#include "defs.hpp"

class Image;
namespace PE
{
	class ImageSections
	{
	private:
		Image* m_image;
		bool m_valid = false;

		std::uint16_t m_number_of_sections = 0;
		const ImageSectionHeader* m_sections = nullptr;

		[[nodiscard]] bool ValidateSections(const std::vector<std::uint8_t>& data) noexcept;

	public:
		ImageSections(Image* image);

		__forceinline constexpr bool IsValid() const noexcept(true) { return m_valid; }
		__forceinline constexpr std::uint16_t Count() const noexcept { return m_number_of_sections; }

		const ImageSectionHeader* GetByName(const char* name) const noexcept;
		const ImageSectionHeader* GetByIndex(size_t index) const noexcept;
		const std::vector<const ImageSectionHeader*> GetAll() const noexcept;
	};
}