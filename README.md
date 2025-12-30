# Premier PE Library

A modern C++20 library for parsing and manipulating Windows Portable Executable (PE) files.

## Overview

Premier PE Library provides a clean interface for working with Windows PE file formats. The library is designed to handle DOS headers, NT headers, Sections, Data directories and more with a focus on simplicity and performance.

## Current Project Structure

```
PE Library/
├── SDK/
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

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
