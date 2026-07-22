# `PE::Image`

`#include "pe-lib/image.hpp"`

Represents a loaded Portable Executable image and owns its raw bytes. Every other class in the library (`Imports`, `Exports`, `ImageSections`, etc.) takes a `PE::Image*` and reads through it, it's the object you must construct first.

`Image` is not copyable. Move it or hold it by pointer/reference if you need to.

---

### Constructors

#### `explicit Image(std::vector<std::uint8_t> data)`

Constructs an image from an existing byte buffer, taking ownership of it (moved in, not copied).

**Parameters:**

- `data` - raw file bytes.

**Example:**

```cpp
std::vector<std::uint8_t> bytes = read_file();
PE::Image image(std::move(bytes));
```

**Notes:** Use this when you've already got the bytes in memory and don't want a second copy.

#### `explicit Image(const std::uint8_t* data, size_t size)`

Constructs an image from a raw memory buffer, copying `size` bytes internally.

**Parameters:**

- `data` - pointer to the start of the PE image in memory.

- `size` - number of bytes to copy.

**Example:**

```cpp
PE::Image image(buffer, buffer_size);
```

**Notes:** Unlike the `std::vector` overload, this one copies it, should only be used when you don't own the source buffer's lifetime (e.g. a mapped module, a fixed-size stack buffer).

---

### Validation

#### `bool IsValid() const`

Returns whether the image passed DOS/NT/optional-header validation. **Always check this before calling anything else!**

```cpp
PE::Image image("trash.bin");
if (!image.IsValid()) {
    std::cerr << "not a valid PE file\n";
    return;
}
```

#### `bool IsPE32() const` / `bool IsPE64() const`

Returns whether the image is a PE32 (x86) or PE32+ (x64) image. Both return `false` on an invalid image.

**Example:**

```cpp
if (image.IsPE64()) {
    auto* nt = image.GetNTHeaders<PE::ImageNtHeaders64>();
    // ...
} else if (image.IsPE32()) {
    auto* nt = image.GetNTHeaders<PE::ImageNtHeaders32>();
    // ...
}
```

---

### Header access

#### `const ImageDosHeader* GetDOSHeader() const`

Returns a pointer to the DOS header at the start of the image.

```cpp
auto* dos = image.GetDOSHeader();
std::printf("e_lfanew: 0x%X\n", dos->e_lfanew);
```

#### `template<typename T> const T* GetNTHeaders() const`

Returns a pointer to the NT headers, interpreted as either `ImageNtHeaders32` or `ImageNtHeaders64`.

**Template parameter:**

- `T` - must be `ImageNtHeaders32` or `ImageNtHeaders64`. Anything else won't compile.

**Returns:** valid pointer on success; `nullptr` if the image's if the image is invalid.

```cpp
if (auto* nt = image.GetNTHeaders<PE::ImageNtHeaders64>()) {
    std::printf("Entry point: 0x%X\n", nt->OptionalHeader.AddressOfEntryPoint);
}
```

#### `template<typename T> const T* GetOptionalHeader() const`

Returns a pointer to the optional header directly, interpreted as `ImageOptionalHeader32` or `ImageOptionalHeader64`. Same rules as `GetNTHeaders<T>()`.

```cpp
auto* opt = image.GetOptionalHeader<PE::ImageOptionalHeader32>();
```

**Notes:** This is just a shortcut, it's equivalent to reading `GetNTHeaders<T>()->OptionalHeader`.

---

### Raw data access

#### `const std::vector<std::uint8_t>& Data() const` / `std::vector<std::uint8_t>& Data()`

Returns the raw bytes. The non-const overload lets you make changes to the buffer directly (e.g. patching bytes before calling `Save`).

```cpp
image.Data()[0x1337] = 0x90; // patch a byte
```

#### `bool Save(const char* path) const`

Writes the current in-memory image bytes back out to disk.

```cpp
if (!image.Save("patched.exe")) {
    std::cerr << "failed to write output file\n";
}
```

---

# `PE::Utils`

`#include "pe-lib/image.hpp"`

Address-conversion and scanning helpers for a given `Image`.

```cpp
PE::Image image("malware.exe");
PE::Utils utils(&image);
```

### `std::uint32_t RvaToOffset(std::uint32_t rva) const`

Converts a Relative Virtual Address (RVA) to a raw file offset, using the section table to figure out which section the RVA falls in.

**Returns:** file offset on success, `0` if the RVA doesn't map into any section.

```cpp
std::uint32_t offset = utils.RvaToOffset(0x2000);
```

### `std::uint32_t VaToRva(std::uint64_t va) const`

Converts a Virtual Address to an RVA, by subtracting the image base.

```cpp
std::uint32_t rva = utils.VaToRva(0x140002000);
```

### `std::uint32_t OffsetToRva(std::uint32_t file_offset) const`

The opposite of `RvaToOffset`, converts a raw file offset back to an RVA.

### `bool PatternScan(const char* pattern, const char* mask, uintptr_t* out) const`

Scans the image's raw bytes for a byte pattern with wildcard support.

**Parameters:**

- `pattern` - bytes to search for.

- `mask` - mask string (`x` if the byte should match, `?` if its a wildcard)

- `out` - receives the address/offset of the first match if found.

**Returns:** `true` if a match was found, `false` otherwise.

```cpp
uintptr_t match = 0;
if (utils.PatternScan("\x48\x8B\x00\x00", "xx??", &match)) {
    std::printf("Found at: 0x%llX\n", match);
}
```

### `std::vector<std::string_view> GetAsciiStrings(std::uint32_t min_length) const`

Extracts printable ASCII strings from the raw image data, filtering out anything shorter than `min_length`.

```cpp
for (auto s : utils.GetAsciiStrings(4)) {
    std::cout << s << "\n";
}
```

### `std::vector<std::string_view> GetUnicodeStrings(std::uint32_t min_length) const`

Same as `GetAsciiStrings`, but scans for UTF-16LE printable strings instead.
