
# PE Library
A modern C++ library for parsing and manipulating Windows Portable Executable (PE) files.

Full API docs can be found [here](docs/README.md).

## Overview
This Library provides a clean interface for working with Windows PE file formats. The library is designed to handle DOS headers, NT headers, Sections, Data directories and more with a focus on simplicity and performance.

## Features

### Core
- **Full PE32 & PE32+ (x86/x64)** support with validation
- Complete **DOS Header**, **NT Headers**, **Optional Header**, and **Section Table** access
- Section addition and modification
- RVA ↔ File Offset ↔ VA conversion utilities

### Directories & Structures
- **Import Table** – enumeration by name and ordinal
- **Export Table** – function listing with ordinals and forwarders
- **Relocations** – full block and entry parsing
- **TLS Directory** – callbacks and data inspection
- **Resources** – tree traversal, version info, manifest, and icon extraction
- **Rich Header** – parsing, checksum validation, and compiler/linker identification
- **Debug Directory** – support for common debug formats

### Additional Capabilities
- Unicode and ANSI string extraction
- Data directory validation and bounds checking
- Pattern Scanning

## Getting Started
### Prerequisites
- Visual Studio 2022 (or later with C++17 support)
- Windows SDK 10.0
- Platform Toolset v143 or later

## Installation (CMake)

The library can be added directly to your project using CMake's `FetchContent`

```cmake
include(FetchContent)

FetchContent_Declare(
    pe_lib
    GIT_REPOSITORY https://github.com/NtProtectVirtualMemory/PE-Library.git
    GIT_TAG master # or whichever commit your prefer
    SOURCE_SUBDIR PE-Library
)

FetchContent_MakeAvailable(pe_lib)

target_link_libraries(your_target PRIVATE PE::Library)
```

After linking, the public headers are automatically available:

```cpp
#include <image.hpp>
#include <sections.hpp>
#include <directories.hpp>
#include <rich.hpp>
```

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
The fuzzer has already processed **~275,000** different PE samples and helped discover & fix multiple parsing edge-cases, buffer issues and potential crashes as well as slow units.

For more information see: [`PE-Fuzzer/`](PE-Fuzzer/README.md)

### Current State
- All discovered crashes, UB and slow units have been fixed.
- Actively used during development & testing

## Contributing
What we **accept**:
- Bug reports & crash reproducers (especially with ASAN logs) 
- Parser improvements / edge-case handling 
- Performance optimizations 
- Better documentation / code comments 
- Fuzzer samples, dictionary entries, or mutation strategies

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
