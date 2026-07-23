#pragma once
#include "defs.hpp"

enum class ValidationIssue : std::uint32_t
{
	None = 0,
	BadDOSSignature = 1u << 0,
	ELfanewOOB = 1u << 1,
	BadNTSignature = 1u << 2,
	BadSectionCount = 1u << 3,
	BadOptionalHeaderSize = 1u << 4,
	OptionalHeaderOOB = 1u << 5,
	SectionTableOOB = 1u << 6,
	BadOptionalMagic = 1u << 7,
};

inline ValidationIssue operator|(ValidationIssue a, ValidationIssue b) noexcept
{
	return static_cast<ValidationIssue>(
		static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
inline ValidationIssue& operator|=(ValidationIssue& a, ValidationIssue b) noexcept
{
	a = a | b;
	return a;
}
inline bool HasIssue(ValidationIssue mask, ValidationIssue bit) noexcept
{
	return (static_cast<std::uint32_t>(mask) & static_cast<std::uint32_t>(bit)) != 0;
}

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
		ValidationIssue m_issues = ValidationIssue::None;

		// Main validation
		[[nodiscard]] bool Validate() noexcept;

		// Validation helpers
		[[nodiscard]] bool ValidateNT()     noexcept;
		[[nodiscard]] bool ValidateDOS()    noexcept;
		[[nodiscard]] bool ValidateOptional()  noexcept;

	public:
		explicit Image(std::vector<std::uint8_t> data);			// owning move
		explicit Image(const std::uint8_t* data, size_t size);	// from memory

		Image(const Image&) = delete;
		Image& operator=(const Image&) = delete;

		[[nodiscard]] __forceinline constexpr bool  IsValid() const noexcept(true) { return m_valid; }
		__forceinline constexpr bool IsPE32()		const noexcept(true) { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC; }
		__forceinline constexpr bool IsPE64()		const noexcept(true) { return m_valid && m_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC; }

		std::vector<std::uint8_t>& Data() noexcept(true) { return m_data; }
		ValidationIssue	GetValidationIssues() const noexcept { return m_issues; }

		/*
		* @brief Retrieves the DOS header of the image.
		*/
		const ImageDosHeader* GetDOSHeader() const noexcept
		{
			if (m_data.size() < sizeof(ImageDosHeader))
			{
				return nullptr;
			}
			return reinterpret_cast<const ImageDosHeader*>(m_data.data());
		}

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
					if (static_cast<size_t>(offset) + sizeof(T) > m_data.size())
					{
						return nullptr;
					}
					return reinterpret_cast<const ImageNtHeaders32*>(m_data.data() + offset);
				}
			}
			else
			{
				if (IsPE64())
				{
					const auto offset = GetDOSHeader()->e_lfanew;
					if (static_cast<size_t>(offset) + sizeof(T) > m_data.size())
					{
						return nullptr;
					}
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
					if (static_cast<size_t>(offset) + sizeof(T) > m_data.size())
					{
						return nullptr; // OptionalHeaderOOB
					}
					return reinterpret_cast<const ImageOptionalHeader32*>(m_data.data() + offset);
				}
			}
			else
			{
				if (IsPE64())
				{
					const auto offset = GetDOSHeader()->e_lfanew + sizeof(std::uint32_t) + sizeof(ImageFileHeader);
					if (static_cast<size_t>(offset) + sizeof(T) > m_data.size())
					{
						return nullptr;
					}
					return reinterpret_cast<const ImageOptionalHeader64*>(m_data.data() + offset);
				}
			}
			return nullptr;
		}
	};

	class Utils
	{
	public:
		Utils(Image* image) : m_image(image) {}

		bool PatternScan(const char* pattern, const char* mask, uintptr_t* out) const noexcept;
		std::uint32_t RvaToOffset(std::uint32_t rva) const noexcept;
		std::uint32_t VaToRva(std::uint64_t va) const noexcept;
		std::uint32_t OffsetToRva(std::uint32_t file_offset) const noexcept;
		std::vector<std::string_view>  GetAsciiStrings(std::uint32_t min_length) const noexcept;
		std::vector<std::string_view> GetUnicodeStrings(std::uint32_t min_length) const noexcept;

	private:
		Image* m_image;

	};
};