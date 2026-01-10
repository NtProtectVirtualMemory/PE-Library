
# Premier PE Library

A modern C++20 library for parsing and manipulating Windows Portable Executable (PE) files.

## Overview

Premier PE Library provides a clean interface for working with Windows PE file formats. The library is designed to handle DOS headers, NT headers, Sections, Data directories and more with a focus on simplicity and performance.

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
- PE Packer detection
```

## Current Project Structure

```
PE Fuzzer/
├── Corpus/
│   └── 900+ Samples        # Testing Samples
├── pe-fuzzer.dict          # Fuzzer dictionary
└── main.cpp                # Entry of the fuzzer

PE Library/
├── premier/
│   ├── PE.hpp              # Main library header
│   ├── PE.cpp              # Main library implementation
└── example.cpp             # Usage examples
```

## Getting Started

### Prerequisites

- Visual Studio 2022 (or later with C++20 support)
- Windows SDK 10.0
- Platform Toolset v145 or later

### Building

1. Clone the repository:
```bash
git clone https://github.com/NtProtectVirtualMemory/PE-Library.git
```

2. Open `PE Library.slnx` in Visual Studio

3. Select the correct configuration: 
   - **Release**
   - **x64**

4. Build the solution (Ctrl+Shift+B)

### Output Directories

- Binaries:  `bin/PE Library/{Platform}/{Configuration}/`
- Intermediates: `bin/intermediates/PE Library/{Platform}/{Configuration}/`

### Basic Usage

```cpp
#include <cstdio>
#include "PE.hpp"

int main() {
    PE::Image image("path\to\file.exe");
    
    // Your code here
    
    return 0;
}
```

## PE Fuzzer
The fuzzer has already processed **~150,000** different PE samples and helped discover & fix multiple parsing edge-cases, buffer issues and potential crashes as well as slow units.

### Current State

- **~150k** unique samples processed.
- All discovered crashes & undefined behavior issues have been fixed.
- Actively used during development & testing

### Basic Usage
1. Open "x64 Native Tools Command Prompt for VS"
2. cd "path/to/PE-Fuzzer.exe"
3. PE-Fuzzer.exe "path/to/corpus" -jobs=6 -workers=6 -rss_limit_mb=0 -dict="path/to/pe-fuzzer.dict"

## Contributing

What we **accept**:
- Bug reports & crash reproducers (especially with ASAN logs) 
- Parser robustness improvements / edge-case handling 
- Performance optimizations - Better documentation / code comments 
- Fuzzer corpus samples, dictionary entries, or mutation strategies


### How to contribute

1. If you're fixing a bug or adding a feature, please **open an issue first** (unless it's a very obvious typo/doc fix) 
2. Fork the repository and create your branch from `main` 
3. If possible, add or extend tests, this is highly appreciated.
4. Make sure the code follows the current style: 
   - Use C++20 features when it improves readability/safety 
   - Keep public API clean & minimal
    - Use `snake_case` for private members/functions, `PascalCase` for public types
 5. Make small, focused pull requests with clear titles & description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.
