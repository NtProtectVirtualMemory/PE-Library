# PE-Library API Reference

Every class here (except `Image` itself) is a thin wrapper constructed around an already-loaded `PE::Image*`. The usual flow looks like this:

```cpp
PE::Image image("path/to/file.exe");
if (!image.IsValid()) {
    return; // not a valid PE
}

PE::Imports imports(&image);
PE::Exports exports(&image);
PE::ImageSections sections(&image);
// ...etc
```

## Contents

- **[Image.md](./Image.md)**, `PE::Image` (loading, validation, header access) and `PE::Utils` (address conversion, pattern scanning, string extraction)
- **[Imports-Exports.md](./Imports-Exports.md)**, `PE::Imports` and `PE::Exports`
- **[Relocations-TLS-Resources-Debug.md](./Relocations-TLS-Resources-Debug.md)**, `PE::DataDirectory`, `PE::Relocations`, `PE::TLS`, `PE::Resources`, `PE::Debug`
- **[Sections-RichHeader.md](./Sections-RichHeader.md)**, `PE::ImageSections` and `PE::RichHeader`

## Conventions used throughout

- Classes with a `Present()` method should have it checked before calling other accessors. An absent directory usually just means empty/zeroed results, not an exception.
- Lookup functions like `Exports::ByName`/`ByOrdinal` and `Debug::GetByType` return their result struct by value, not `std::optional`. Check a relevant field (a non-empty name, a non-zero size) to confirm a match, since a miss won't throw.
- All parsing is read-only except `ImageSections::AddSection` and direct writes through `Image::Data()`, which only mutate the in-memory buffer. Call `Image::Save()` to persist changes to disk.

## Contributing to these docs

Docs are hand-written to explain when and why to use something, not just parameter types. If a method's behavior around edge cases (empty results, ordinal-only imports, forwarded exports, etc.) isn't covered here, please open an issue or a pull request.