
# PE Library
A modern C++ library for parsing and manipulating Windows Portable Executable (PE) files.
Full API docs can be found [here](docs/README.md).

## Overview
This Library provides a clean interface for working with Windows PE file formats. The library is designed to handle DOS headers, NT headers, Sections, Data directories and more with a focus on simplicity and performance.

## Features
The Following Features this Library currently offers will be listed below 
```
- Full PE32 and PE32+ (x86 / x64) parsing support
- DOS header, NT headers, optional headers, and section table access
- Import and export table enumeration (by name and ordinal)
- Relocation table parsing with block and entry detail
- TLS directory inspection and callback enumeration
- Resource tree parsing with version info and manifest extraction
- Rich header parsing with checksum validation and tool identification
- RVA, VA, and file offset conversion utilities
- Debug directory parsing
- Unicode and ASCII String extraction
```

## Getting Started
### Prerequisites
- Visual Studio 2022 (or later with C++17 support)
- Windows SDK 10.0
- Platform Toolset v143 or later

### Basic Usage

```cpp
#include <vector>

#include "pe-lib/image.hpp"
#include "pe-lib/sections.hpp"

int main()
{
    // Read your PE file into a byte buffer
    std::vector<std::uint8_t> bytes = /* ... */;

    PE::Image image(std::move(bytes));
    PE::ImageSections sections(&image);

    // Your code here...

    return 0;
}

```

> **Note:** `PE::Image` no longer performs file I/O. Load the file into memory, then construct the image from the resulting byte buffer.
## PE Fuzzer
The fuzzer has already processed **~200,000** different PE samples and helped discover & fix multiple parsing edge-cases, buffer issues and potential crashes as well as slow units.

For more information see: [`PE-Fuzzer/`](PE-Fuzzer/README.md)

### Current State
- **~200k** unique samples processed.
- All discovered crashes & undefined behavior issues have been fixed.
- Actively used during development & testing

## Contributing
What we **accept**:
- Bug reports & crash reproducers (especially with ASAN logs) 
- Parser robustness improvements / edge-case handling 
- Performance optimizations - Better documentation / code comments 
- Fuzzer corpus samples, dictionary entries, or mutation strategies

### How to contribute
1. If you're fixing a bug or adding a feature, please **open an issue first** (unless it's a very obvious typo/doc fix) 
2. Fork the repository and create your branch from `master` 
3. If possible, add or extend tests, this is highly appreciated.
4. Make sure the code follows the current style: 
   - Use C++ features when it improves readability/safety 
   - Keep public API clean & minimal
   - Use `snake_case` for private members/functions, `PascalCase` for public types
 5. Make small, focused pull requests with clear titles & description

## Special Thanks
Special thanks to [Christopher Wellons (skeeto)](https://github.com/skeeto) for the Fuzzer, design suggestions, and overall feedback that helped improve the library and fuzzer.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.
