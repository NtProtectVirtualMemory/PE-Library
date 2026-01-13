
/* rich_impl.cpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#include "image.hpp"
#include "rich.hpp"

bool PE::RichHeader::Present() const noexcept
{
	if (!m_image || !m_image->IsValid())
		return false;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
	{
		return false;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t nt_offset = dos_header->e_lfanew;

	if (nt_offset < sizeof(ImageDosHeader) + 8)
	{
		return false;
	}

	const std::uint32_t* search = reinterpret_cast<const std::uint32_t*>(data + nt_offset - sizeof(std::uint32_t));
	const std::uint32_t* search_end = reinterpret_cast<const std::uint32_t*>(data + sizeof(ImageDosHeader));

	while (search > search_end)
	{
		if (*search == RICH_SIGNATURE)
			return true;
		search--;
	}

	return false;
}

std::uint32_t PE::RichHeader::GetRawOffset() const noexcept
{
	if (!Present())
	{
		return 0;
	}

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
	{
		return 0;
	}

	const std::uint8_t* data = m_image->Data().data();
	size_t nt_offset = dos_header->e_lfanew;

	const std::uint32_t* search =
		reinterpret_cast<const std::uint32_t*>(data + nt_offset - sizeof(std::uint32_t));
	const std::uint32_t* search_end =
		reinterpret_cast<const std::uint32_t*>(data + sizeof(ImageDosHeader));

	const std::uint32_t* rich_ptr = nullptr;

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

	std::uint32_t checksum = *(rich_ptr + 1);

	const std::uint32_t* scan = rich_ptr - 1;
	while (scan > search_end)
	{
		if ((*scan ^ checksum) == DANS_SIGNATURE)
		{
			return static_cast<std::uint32_t>(
				reinterpret_cast<const std::uint8_t*>(scan) - data);
		}
		--scan;
	}

	return 0;
}

std::uint32_t PE::RichHeader::GetRawSize(bool region_size) const noexcept
{
	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
	{
		return 0;
	}

	const std::vector<std::uint8_t>& image = m_image->Data();
	const std::uint8_t* data = image.data();

	size_t nt_offset = dos_header->e_lfanew;
	if (nt_offset < sizeof(ImageDosHeader) || nt_offset > image.size())
	{
		return 0;
	}

	const std::uint32_t* search =
		reinterpret_cast<const std::uint32_t*>(data + nt_offset - sizeof(std::uint32_t));
	const std::uint32_t* search_end =
		reinterpret_cast<const std::uint32_t*>(data + sizeof(ImageDosHeader));

	const std::uint32_t* rich_ptr = nullptr;
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

	std::uint32_t checksum = *(rich_ptr + 1);

	const std::uint8_t* rich_byte = reinterpret_cast<const std::uint8_t*>(rich_ptr);
	const std::uint8_t* dans_ptr = nullptr;

	for (size_t off = (rich_byte - data) - 4; off >= 4; --off)
	{
		std::uint32_t v;
		memcpy(&v, data + off - 4, sizeof(std::uint32_t));
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

	std::uint32_t dans_offset = static_cast<std::uint32_t>(dans_ptr - data);

	std::uint32_t rich_size =
		static_cast<std::uint32_t>((rich_byte + 8) - dans_ptr);

	if (!region_size)
	{
		return rich_size;
	}

	return static_cast<std::uint32_t>(nt_offset) - dans_offset;
}


std::uint32_t PE::RichHeader::GetChecksum() const noexcept
{
	if (!m_image || !m_image->IsValid())
		return 0;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
		return 0;

	const std::uint8_t* data = m_image->Data().data();
	size_t nt_offset = dos_header->e_lfanew;

	const std::uint32_t* search = reinterpret_cast<const std::uint32_t*>(data + nt_offset - sizeof(std::uint32_t));
	const std::uint32_t* search_end = reinterpret_cast<const std::uint32_t*>(data + sizeof(ImageDosHeader));

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

std::vector<PE::RichEntry> PE::RichHeader::GetEntries() const noexcept
{
	std::vector<PE::RichEntry> entries;

	if (!Present())
		return entries;

	std::uint32_t start_offset = GetRawOffset();
	if (start_offset == 0)
		return entries;

	std::uint32_t checksum = GetChecksum();
	if (checksum == 0)
		return entries;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
		return entries;

	const std::uint8_t* data = m_image->Data().data();
	size_t nt_offset = dos_header->e_lfanew;

	const std::uint32_t* search = reinterpret_cast<const std::uint32_t*>(data + nt_offset - sizeof(std::uint32_t));
	const std::uint32_t* search_end = reinterpret_cast<const std::uint32_t*>(data + sizeof(ImageDosHeader));
	const std::uint32_t* rich_ptr = nullptr;

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

	const std::uint32_t* entry_start = reinterpret_cast<const std::uint32_t*>(data + start_offset + 16);
	const std::uint32_t* entry_end = rich_ptr;

	while (entry_start + 1 < entry_end)
	{
		std::uint32_t comp_id = entry_start[0] ^ checksum;
		std::uint32_t count = entry_start[1] ^ checksum;

		RichEntry entry{};
		entry.build_id = static_cast<std::uint16_t>(comp_id & 0xFFFF);
		entry.product_id = static_cast<std::uint16_t>((comp_id >> 16) & 0xFFFF);
		entry.use_count = count;

		entries.push_back(entry);
		entry_start += 2;
	}

	return entries;
}

bool PE::RichHeader::ValidateChecksum() const noexcept
{
	if (!Present())
		return false;

	std::uint32_t stored_checksum = GetChecksum();
	if (stored_checksum == 0)
		return false;

	std::uint32_t start_offset = GetRawOffset();
	if (start_offset == 0)
		return false;

	auto dos_header = m_image->GetDOSHeader();
	if (!dos_header)
		return false;

	const std::uint8_t* data = m_image->Data().data();

	std::uint32_t calc_checksum = start_offset;

	for (size_t i = 0; i < sizeof(ImageDosHeader); ++i)
	{
		if (i >= 0x3C && i < 0x40)
			continue;

		std::uint32_t val = data[i];
		std::uint32_t rot = i % 32;
		calc_checksum += (val << rot) | (val >> (32 - rot));
	}

	for (size_t i = sizeof(ImageDosHeader); i < start_offset; ++i)
	{
		std::uint32_t val = data[i];
		std::uint32_t rot = i % 32;
		calc_checksum += (val << rot) | (val >> (32 - rot));
	}

	auto entries = GetEntries();
	for (const auto& entry : entries)
	{
		std::uint32_t comp_id = (static_cast<std::uint32_t>(entry.product_id) << 16) | entry.build_id;
		std::uint32_t rot = entry.use_count % 32;
		calc_checksum += (comp_id << rot) | (comp_id >> (32 - rot));
	}

	return calc_checksum == stored_checksum;
}

std::string_view PE::RichHeader::ProductIdToString(std::uint16_t product_id) noexcept
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