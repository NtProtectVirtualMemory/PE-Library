#pragma once


/* PE.hpp - of "Premier" PE Library

* Copyright (C) 2020-2025 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.

*/

#include <windows.h>

namespace PE
{
    class Image
    {
	public:
        Image();
		~Image();
	protected:

	private:
    };

    namespace dos_header
    {
        
    } // namespace PE::dos_header

    namespace nt_headers
    {

    } // namespace PE::nt_headers

} // namespace PE