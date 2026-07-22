# `PE::Imports`

`#include "pe-lib/directories.hpp"`

Parses the image's import table, which DLLs it depends on, and which functions it pulls from each.

```cpp
PE::Image image("file.exe");
PE::Imports imports(&image);
```

### `bool Present() const`

Returns whether the image has an import directory at all. Worth checking first, some images (packed binaries, certain drivers) have no imports.

```cpp
if (!imports.Present()) {
    std::cout << "no import table\n";
    return;
}
```

### `std::vector<std::string_view> GetImportedModules() const`

Returns just the list of DLL names the image imports from, without their functions. Cheaper than `GetAllImports()`.

```cpp
for (auto name : imports.GetImportedModules()) {
    std::cout << name << "\n";
}
```

### `std::vector<ImportEntry> GetAllImports() const`

Returns the full import table, every imported module, with every function pulled from it.

`ImportEntry`:

| Field | Type | Meaning |
|---|---|---|
| `dll_name` | `std::string_view` | name of the imported DLL |
| `functions` | `std::vector<ImportFunction>` | functions imported from that DLL |

`ImportFunction`:

| Field | Type | Meaning |
|---|---|---|
| `name` | `std::string_view` | function name, empty if imported by ordinal |
| `hint` | `std::uint16_t` | import hint (not guaranteed accurate) |
| `ordinal` | `std::uint16_t` | ordinal value |
| `is_ordinal` | `bool` | `true` if imported by ordinal rather than by name |

```cpp
for (const auto& entry : imports.GetAllImports()) {
    std::cout << entry.dll_name << ":\n";
    for (const auto& fn : entry.functions) {
        if (fn.is_ordinal)
            std::cout << "  ordinal #" << fn.ordinal << "\n";
        else
            std::cout << "  " << fn.name << "\n";
    }
}
```

**Notes:** check `is_ordinal` before reading `name`, ordinal-only imports leave `name` empty, and treating it as a valid string just gives you garbage output.

### `std::vector<ImportFunction> FunctionFromModule(const char* dll_name) const`

Returns just the functions imported from one named module, without walking the whole table.

```cpp
auto fns = imports.FunctionFromModule("kernel32.dll");
```

### `size_t GetModuleCount() const`

Returns the number of imported modules, without building the full import list.

### `const ImageImportDescriptor* GetDescriptors() const`

Returns a pointer to the raw `IMAGE_IMPORT_DESCRIPTOR` array, in case you want to walk the structure manually instead of using the parsed `ImportEntry` results.

---

# `PE::Exports`

`#include "pe-lib/directories.hpp"`

Parses the image's export table, functions/data it makes available to other modules.

```cpp
PE::Exports exports(&image);
```

### `bool Present() const`

Returns whether the image has an export directory.

### `std::string_view ModuleName() const`

Returns the module's own name as recorded in the export directory. This is what other binaries see when they import from it.

### `std::vector<ExportFunction> All() const`

Returns every exported function/symbol.

`ExportFunction`:

| Field | Type | Meaning |
|---|---|---|
| `name` | `std::string_view` | exported name, empty if exported by ordinal only |
| `rva` | `std::uint32_t` | RVA of the export |
| `va` | `std::uint64_t` | absolute VA (image base + rva) |
| `file_offset` | `std::uint32_t` | raw file offset |
| `ordinal` | `std::uint16_t` | export ordinal |
| `is_forwarded` | `bool` | `true` if this export forwards to another DLL instead of pointing at code in this image |
| `forward_name` | `std::string_view` | `"OtherDll.FunctionName"`-style forward target, only meaningful when `is_forwarded` is `true` |

```cpp
for (const auto& fn : exports.All()) {
    if (fn.is_forwarded)
        std::cout << fn.name << " -> " << fn.forward_name << "\n";
    else
        std::cout << fn.name << " @ 0x" << std::hex << fn.rva << "\n";
}
```

**Notes:** check `is_forwarded` before treating `rva`/`va` as real code addresses, a forwarded export's RVA points into the forward-name string, not executable code.

### `ExportFunction ByName(const char* name) const`

Looks up a single export by name.

```cpp
auto fn = exports.ByName("MyExportedFunc");
```

**Notes:** this returns `ExportFunction` by value, not `std::optional`, so check the result's `name` (or `rva != 0`) before trusting it, a miss won't throw.

### `ExportFunction ByOrdinal(std::uint16_t ordinal) const`

Same as `ByName`, but looks up by ordinal. Needed for exports that have no name at all.

### `size_t Count() const`

Returns the total number of exports.

### `const ImageExportDirectory* GetDescriptor() const`

Returns a pointer to the raw `IMAGE_EXPORT_DIRECTORY` struct for manual walking.