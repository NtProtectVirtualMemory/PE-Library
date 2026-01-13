
/* directories.hpp - of "Premier" PE Library

* Copyright (C) 2026 Premier. All rights reserved.

* This software is licensed under the MIT License.
* For more details see http://www.opensource.org/licenses/MIT
* or the license file that can be found directly on the github
* of PE Library.
*/

#pragma once

#include "image.hpp"
#include "defs.hpp"
#include <optional>

namespace PE
{
	class DataDirectory
	{
	private:
		Image* m_image;

	public:
		DataDirectory(Image* image) : m_image(image) {}

		const ImageDataDirectory* Get(std::uint16_t index) const noexcept;
		bool Exists(std::uint16_t index) const noexcept;

		template<typename T>
		const T* GetDirectory(std::uint16_t index) const noexcept
		{
			auto dir = Get(index);
			if (!dir || dir->VirtualAddress == 0)
			{
				return nullptr;
			}

			std::uint32_t offset = ImageUtils(m_image).RvaToOffset(dir->VirtualAddress);
			if (offset == 0)
			{
				return nullptr;
			}

			if (offset + sizeof(T) > m_image->Data().size())
			{
				return nullptr;
			}

			return reinterpret_cast<const T*>(m_image->Data().data() + offset);
		}
	};


	class Imports
	{
	private:
		Image* m_image;
		bool m_present{ false };

	public:
		explicit Imports(Image* image);

		[[nodiscard]] bool Present() const noexcept { return m_present; }
		std::vector<std::string_view> GetImportedModules() const noexcept;
		std::vector<ImportEntry> GetAllImports() const noexcept;
		std::vector<ImportFunction> FunctionFromModule(const char* dll_name) const noexcept;
		const ImageImportDescriptor* GetDescriptors() const noexcept;
		size_t GetModuleCount() const noexcept;
	};

	class Exports
	{
	private:
		Image* m_image;
		bool m_present{ false };

	public:
		explicit Exports(Image* image);

		[[nodiscard]] bool Present() const noexcept { return m_present; }
		std::string_view ModuleName() const noexcept;
		std::vector<ExportFunction> All() const noexcept;
		ExportFunction ByName(const char* name) const noexcept;
		ExportFunction ByOrdinal(std::uint16_t ordinal) const noexcept;
		size_t Count() const noexcept;
		const ImageExportDirectory* GetDescriptor() const noexcept;
	};


	/*
	* @brief Do not instantiate this class directly. Use Image::Relocations() instead!
	*/
	class Relocations
	{
	private:
		Image* m_image;
		bool m_present{ false };

	public:
		explicit Relocations(Image* image);

		[[nodiscard]] bool Present() const noexcept { return m_present; }
		std::vector<RelocationBlock> GetBlocks() const noexcept;
		std::vector<RelocationEntry> GetAllEntries() const noexcept;
		size_t Count() const noexcept;
		const ImageBaseRelocation* GetRawTable() const noexcept;
		static std::string_view TypeToString(std::uint16_t type) noexcept;
	};


	/*
	* @brief Do not instantiate this class directly. Use Image::TLS() instead!
	*/
	class TLS
	{
	private:
		Image* m_image;
		bool m_present{ false };

		[[nodiscard]] const ImageTlsDirectory32* GetDirectory32() const noexcept;
		[[nodiscard]] const ImageTlsDirectory64* GetDirectory64() const noexcept;

	public:
		explicit TLS(Image* image);

		[[nodiscard]] bool Present() const noexcept { return m_present; }
		TLSInfo GetInfo() const noexcept;
		std::vector<TLSCallback> GetCallbacks() const noexcept;
		[[nodiscard]] bool HasCallbacks() const noexcept;
		constexpr size_t CallbackCount() const noexcept { return GetCallbacks().size(); }

		template<typename T>
		inline const T* GetDirectory() const noexcept
		{
			static_assert(std::is_same_v<T, ImageTlsDirectory32> ||
				std::is_same_v<T, ImageTlsDirectory64>,
				"T must be IMAGE_TLS_DIRECTORY32 or IMAGE_TLS_DIRECTORY64");

			if constexpr (std::is_same_v<T, ImageTlsDirectory32>)
				return GetDirectory32();
			else
				return GetDirectory64();
		}
	};

	class Resources
	{
	private:
		Image* m_image;
		bool m_present{ false };

	public:
		explicit Resources(Image* image);

		[[nodiscard]] bool Present() const noexcept { return m_present; }
		std::vector<ResourceEntry> GetAll() const noexcept;
		std::vector<ResourceEntry> GetByType(std::uint16_t type_id) const noexcept;
		std::vector<std::uint16_t> GetTypeIds() const noexcept;
		size_t Count() const noexcept;

		std::optional<VersionInfo> GetVersionInfo() const noexcept;
		std::string_view GetManifest() const noexcept;
		std::vector<std::uint8_t> GetResourceData(const ResourceEntry& entry) const noexcept;

		const ImageResourceDirectory* GetRootDirectory() const noexcept;
		static std::string_view TypeToString(std::uint16_t type_id) noexcept;
	};

	class Debug
	{
	private:
		Image* m_image;
		bool m_present{ false };

	public:
		explicit Debug(Image* image);

		[[nodiscard]] bool Present() const noexcept { return m_present; }
		std::vector<DebugEntry> GetAll() noexcept;
		DebugEntry GetByType(const std::uint16_t type_id) noexcept;
		std::string_view TypeToString(const std::uint16_t type_id) const noexcept;
	};

}