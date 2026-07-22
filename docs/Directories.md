# `PE::Relocations`

`#include "pe-lib/directories.hpp"`

Parses the base relocation table (`.reloc`), the fixes the loader applies when an image can't load at its preferred base address.

```cpp
PE::Relocations relocs(&image);
```

### `bool Present() const`

Returns whether the image has a relocation table. Executables built without ASLR support, or stripped of relocations, will return `false`.

### `std::vector<RelocationBlock> GetBlocks() const`

Returns the relocation table grouped by page.

`RelocationBlock`:

| Field | Type | Meaning |
|---|---|---|
| `page_rva` | `std::uint32_t` | RVA of the 4KB page this block covers |
| `entries` | `std::vector<RelocationEntry>` | individual fixups within that page |

`RelocationEntry`:

| Field | Type | Meaning |
|---|---|---|
| `rva` | `std::uint32_t` | absolute RVA of the fixup (page RVA + in-block offset) |
| `type` | `std::uint16_t` | relocation type (e.g. `IMAGE_REL_BASED_DIR64`), pass to `TypeToString` for a readable name |
| `file_offset` | `std::uint32_t` | raw file offset of the fixup |

```cpp
for (const auto& block : relocs.GetBlocks()) {
    for (const auto& entry : block.entries) {
        std::cout << PE::Relocations::TypeToString(entry.type)
                   << " @ 0x" << std::hex << entry.rva << "\n";
    }
}
```

### `std::vector<RelocationEntry> GetAllEntries() const`

Same data as `GetBlocks()`, just flattened into a single list if you don't care about page grouping.

### `size_t Count() const`

Total number of individual relocation entries across all blocks.

### `const ImageBaseRelocation* GetRawTable() const`

Pointer to the raw `IMAGE_BASE_RELOCATION` table for manual walking.

### `static std::string_view TypeToString(std::uint16_t type)`

Converts a raw relocation type value into a human-readable name (e.g. `"IMAGE_REL_BASED_DIR64"`).

---

# `PE::TLS`

`#include "pe-lib/directories.hpp"`

Parses the Thread Local Storage (TLS) directory, including TLS callbacks, functions the loader invokes before `main`/`DllMain`, notably used by some anti-debug/packing techniques.

```cpp
PE::TLS tls(&image);
```

### `bool Present() const`

Returns whether the image has a TLS directory.

### `TLSInfo GetInfo() const`

Returns the raw TLS directory fields as a bitness-normalized struct.

`TLSInfo`:

| Field | Type | Meaning |
|---|---|---|
| `raw_data_start_va` / `raw_data_end_va` | `std::uint64_t` | VA range of the TLS template data |
| `index_va` | `std::uint64_t` | VA of the TLS index variable |
| `callbacks_va` | `std::uint64_t` | VA of the callback array |
| `zero_fill_size` | `std::uint32_t` | size of zero-initialized TLS data beyond the raw template |
| `characteristics` | `std::uint32_t` | reserved/alignment flags |
| `raw_data_size` | `std::uint32_t` | size of the raw TLS template (`end - start`) |

### `std::vector<TLSCallback> GetCallbacks() const`

Returns every TLS callback registered by the image.

`TLSCallback`:

| Field | Type | Meaning |
|---|---|---|
| `va` | `std::uint64_t` | callback's virtual address |
| `rva` | `std::uint32_t` | callback's RVA |
| `file_offset` | `std::uint32_t` | callback's raw file offset |

```cpp
if (tls.HasCallbacks()) {
    for (const auto& cb : tls.GetCallbacks())
        std::printf("TLS callback @ 0x%llX\n", cb.va);
}
```

**Notes:** a nonzero number of TLS callbacks is a fairly common signal in malware/packer analysis, anti-debug checks run before the real entry point, worth flagging in any triage tools built on this.

### `bool HasCallbacks() const`

Cheaper check than `GetCallbacks().empty()` if you only need a yes/no.

### `constexpr size_t CallbackCount() const`

**Notes:** this calls `GetCallbacks()` internally to get the size, so it re-parses the callback array every time, don't call it in a loop, cache the result of `GetCallbacks()` once instead if you need both the list and the count.

### `template<typename T> const T* GetDirectory() const`

Returns the raw `ImageTlsDirectory32` or `ImageTlsDirectory64` pointer, matching the image's actual bitness (same pattern as `Image::GetNTHeaders<T>()`, see [Image.md](Image.md)).

---

# `PE::Resources`

`#include "pe-lib/directories.hpp"`

Parses the resource tree (`.rsrc`), icons, manifests, version info, dialogs, strings, etc.

```cpp
PE::Resources resources(&image);
```

### `bool Present() const`

Returns whether the image has a resource directory.

### `std::vector<ResourceEntry> GetAll() const`

Returns every resource entry in the tree, flattened.

`ResourceEntry`:

| Field | Type | Meaning |
|---|---|---|
| `type_id` | `std::uint16_t` | resource type (see `resource_*` constants, e.g. `PE::resource_manifest`) |
| `type_name` | `std::string_view` | name if the type is a named (not numeric) entry |
| `resource_id` | `std::uint16_t` | resource ID |
| `resource_name` | `std::string_view` | name if the resource is named rather than numbered |
| `language_id` | `std::uint16_t` | LCID of this resource variant |
| `data_rva` / `data_size` / `file_offset` | `std::uint32_t` | location of the raw resource bytes |
| `code_page` | `std::uint32_t` | code page for interpreting string data |

```cpp
for (const auto& res : resources.GetAll()) {
    std::cout << PE::Resources::TypeToString(res.type_id) << "\n";
}
```

### `std::vector<ResourceEntry> GetByType(std::uint16_t type_id) const`

Same as `GetAll()`, filtered to a single resource type, use with the `PE::resource_*` constants (`resource_icon`, `resource_manifest`, `resource_version`, etc.).

```cpp
auto manifests = resources.GetByType(PE::resource_manifest);
```

### `std::vector<std::uint16_t> GetTypeIds() const`

Returns the distinct resource type IDs present in the image, without the full entries.

### `size_t Count() const`

Total number of resource entries.

### `std::optional<VersionInfo> GetVersionInfo() const`

Parses the `VS_VERSION_INFO` resource (file/product version numbers, flags) if present.

`VersionInfo` fields (`major`/`minor`/`build`/`revision` for file version, `product_major`/`product_minor`/`product_build`/`product_revision` for product version, plus `file_flags`, `file_os`, `file_type`) map directly to the fields of `VS_FIXEDFILEINFO`.

**Returns:** `std::nullopt` if the image has no version resource, check before dereferencing.

```cpp
if (auto ver = resources.GetVersionInfo()) {
    std::printf("%u.%u.%u.%u\n", ver->major, ver->minor, ver->build, ver->revision);
}
```

### `std::string_view GetManifest() const`

Returns the raw XML text of the embedded application manifest, if present. Empty if there's no manifest resource.

### `std::vector<std::uint8_t> GetResourceData(const ResourceEntry& entry) const`

Returns the raw bytes of a specific resource, given an entry from `GetAll()`/`GetByType()`.

```cpp
auto icons = resources.GetByType(PE::resource_icon);
if (!icons.empty()) {
    auto bytes = resources.GetResourceData(icons.front());
}
```

### `const ImageResourceDirectory* GetRootDirectory() const`

Returns a pointer to the raw root `IMAGE_RESOURCE_DIRECTORY` node for manual tree walking.

### `static std::string_view TypeToString(std::uint16_t type_id)`

Converts a numeric resource type ID into a readable name (e.g. `"RT_MANIFEST"`).

---

# `PE::Debug`

`#include "pe-lib/directories.hpp"`

Parses the debug directory, PDB references, timestamps, and other debug-info metadata embedded at link time.

```cpp
PE::Debug debug(&image);
```

### `bool Present() const`

Returns whether the image has a debug directory.

### `std::vector<DebugEntry> GetAll()`

Returns every debug directory entry.

`DebugEntry`:

| Field | Type | Meaning |
|---|---|---|
| `type` | `std::uint16_t` | debug info type (e.g. CodeView/PDB, COFF, etc.), pass to `TypeToString` |
| `size` | `std::uint32_t` | size of the debug data |
| `address_rva` | `std::uint32_t` | RVA of the debug data |
| `address_offset` | `std::uint32_t` | raw file offset of the debug data |

```cpp
for (const auto& entry : debug.GetAll()) {
    std::cout << debug.TypeToString(entry.type) << "\n";
}
```

**Notes:** unlike most other `GetAll`/`Present` pairs in this library, `GetAll()` here is non-`const`, keep your `Debug` instance mutable if you plan to call it.

### `DebugEntry GetByType(const std::uint16_t type_id)`

Returns the first debug entry matching `type_id`. Like `Exports::ByName`/`ByOrdinal`, this returns by value rather than `std::optional`, check the returned entry's fields (e.g. `size != 0`) to confirm a match was actually found.

### `std::string_view TypeToString(const std::uint16_t type_id) const`

Converts a numeric debug type into a readable name.