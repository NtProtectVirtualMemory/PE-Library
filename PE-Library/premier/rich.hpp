
/* rich.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#pragma once

#include "defs.hpp"

constexpr std::uint32_t RICH_SIGNATURE = 0x68636952; // "Rich"
constexpr std::uint32_t DANS_SIGNATURE = 0x536E6144; // "DanS"

class Image;
namespace PE
{
	class RichHeader
	{
	private:
		Image* m_image;

		[[nodiscard]] bool Present() const noexcept;
		[[nodiscard]] bool ValidateChecksum() const noexcept;

	public:
		RichHeader(Image* image) : m_image(image) {}

		std::uint32_t GetChecksum() const noexcept;
		std::uint32_t GetRawOffset() const noexcept;
		std::vector<RichEntry> GetEntries() const noexcept;
		std::uint32_t GetRawSize(bool region_size) const noexcept;
		static std::string_view ProductIdToString(std::uint16_t product_id) noexcept;
	};
}
