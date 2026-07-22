# `PE::ImageSections`

`#include "pe-lib/sections.hpp"`

Gives you access to the section table (`.text`, `.data`, `.rdata`, etc.) and lets you add new sections to an existing image.

```cpp
PE::Image image("file.exe");
PE::ImageSections sections(&image);
```

### `bool IsValid() const`

Returns whether the section table was parsed successfully.

### `std::uint16_t Count() const`

Returns the number of sections in the image.

### `const ImageSectionHeader* GetByName(const char* name) const`

Looks up a section by name (e.g. `".text"`).

**Returns:** pointer to the section header, or `nullptr` if no section with that name exists.

```cpp
if (auto* text = sections.GetByName(".text")) {
    std::printf("VirtualSize: 0x%X\n", text->Misc.VirtualSize);
}
```

**Notes:** section names on disk are stored as a fixed 8-byte array (`Name[8]`), names longer than 8 bytes are truncated at the file format level and are not guaranteed to be null terminated.

### `const ImageSectionHeader* GetByIndex(size_t index) const`

Returns the section at a given table index (`0` .. `Count() - 1`).

**Returns:** `nullptr` if `index` is out of range.

### `const std::vector<const ImageSectionHeader*> GetAll() const`

Returns pointers to every section header in order.

```cpp
for (const auto* sec : sections.GetAll()) {
    std::printf("%.8s: 0x%X bytes\n", sec->Name, sec->SizeOfRawData);
}
```

`ImageSectionHeader` fields of note:

| Field                                           | Meaning                                            |
| ----------------------------------------------- | -------------------------------------------------- |
| `Name[8]`                                       | section name, not guaranteed null-terminated       |
| `Misc.VirtualSize`                              | size in memory                                     |
| `VirtualAddress`                                | RVA where the section is mapped                    |
| `SizeOfRawData` / `PointerToRawData`            | size/offset of the section's data on disk          |
| `PointerToRelocations` / `PointerToLinenumbers` | legacy COFF fields, rarely populated in modern PEs |

### `bool AddSection(const std::string_view& name, const std::vector<uint8_t> content, std::uint32_t characteristics) noexcept`

Adds a new section to the image in memory, updates the section table, section count, and `SizeOfImage`. Does **not** write to disk! call `Image::Save()` afterward to persist the change.

**Parameters:**

- `name` - section name. Longer than 8 bytes will be truncated per the PE format.

- `content` - raw bytes to place in the new section.

- `characteristics` - section flags (e.g. `IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ`).

**Returns:** `true` on success, `false` if the section couldn't be added (e.g. alignment failure, malformed image).

```cpp
std::vector<std::uint8_t> payload = { /* ... */ };
if (sections.AddSection(".mysec", payload, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) {
    image.Save("patched.exe");
}
```

**Notes:** this modifies the in-memory image, if you need to keep the original bytes too, work on a copy (`Image` is not copyable, so construct a second `Image` from a duplicated `std::vector<uint8_t>` if you need both, see \[Image.md]\(Image.md)]).

### `bool AlignUp(std::uint32_t value, std::uint32_t alignment, std::uint32_t& out) noexcept`

Rounds `value` up to the nearest multiple of `alignment`, writing the result to `out`. Used internally by `AddSection` for `FileAlignment`/`SectionAlignment` math, but exposed in the public API just in case.

**Returns:** `false` if `alignment` is `0` or the aligned result would overflow `std::uint32_t`; `true` and writes to `out` otherwise.

```cpp
std::uint32_t aligned = 0;
if (sections.AlignUp(0x1050, 0x1000, aligned)) {
    // aligned == 0x2000
}
```

---

# `PE::RichHeader`

`#include "pe-lib/rich.hpp"`

Parses the undocumented "Rich header", metadata embedded by the MSVC linker identifying which compiler/linker tool versions and how many object files went into building the binary. Useful for toolchain fingerprints and some malware heuristics.

```cpp
PE::RichHeader rich(&image);
```

**Notes:** unlike the other directory classes, `RichHeader` has no public `Present()`, since a missing Rich header just means an empty/zeroed result. If `GetEntries()` comes back empty and `GetChecksum()` is `0`, treat that as "no Rich header."

### `std::uint32_t GetChecksum() const`

Returns the Rich header's embedded checksum value.

### `std::uint32_t GetRawOffset() const`

Returns the file offset where the Rich header begins.

### `std::vector<RichEntry> GetEntries() const`

Returns each entry in the Rich header, one per object file/tool that contributed to the build.

`RichEntry`:

| Field        | Type            | Meaning                                                                                 |
| ------------ | --------------- | --------------------------------------------------------------------------------------- |
| `product_id` | `std::uint16_t` | identifies which MSVC tool/component produced this entry, pass to `ProductIdToString()` |
| `build_id`   | `std::uint16_t` | build number of that tool                                                               |
| `use_count`  | `std::uint32_t` | how many times that tool/version was used                                               |

```cpp
for (const auto& entry : rich.GetEntries()) {
    std::cout << PE::RichHeader::ProductIdToString(entry.product_id)
               << " (build " << entry.build_id << ") x" << entry.use_count << "\n";
}
```

### `std::uint32_t GetRawSize(bool region_size) const`

Returns the size of the Rich header region.

**Parameters:**

- `region_size` - when `true`, returns the size of the whole padded region between the DOS stub and the PE header, when `false`, returns just the size of the data itself (excluding padding/signature).

### `static std::string_view ProductIdToString(std::uint16_t product_id)`

Converts a raw product ID into a human-readable tool/version name (e.g. `"Visual Studio 2022 v17.x C++ compiler"` style labels, exact strings depend on the internal product ID table).
