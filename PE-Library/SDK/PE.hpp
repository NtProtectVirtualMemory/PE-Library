#pragma once

/* PE.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

#include <vector>
#include "defs.hpp"

namespace PE
{
    class Image
    {
	public:
		Image(const char* path);
		~Image();

        [[nodiscard]]bool IsPEFile() noexcept;

		/* 
        These will be implemented later, currently dont work because m_magic isnt being set
        
		[[nodiscard]]bool IsPE32() const noexcept { return m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
		[[nodiscard]]bool IsPE64() const noexcept { return m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

        */

		PIMAGE_DOS_HEADER GetDOSHeader() noexcept {
			return m_data.empty() ? nullptr : reinterpret_cast<PIMAGE_DOS_HEADER>(m_data.data());
		}

	protected:
		std::vector<BYTE> m_data;

	private:
        bool m_valid = false;
        WORD m_magic = 0;

    };

    namespace dos_header
    {
        
    } // namespace PE::dos_header

    namespace nt_headers
    {

    } // namespace PE::nt_headers

} // namespace PE