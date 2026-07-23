cmake_minimum_required(VERSION 3.15)
project(PE-Library LANGUAGES CXX)

add_library(pe-lib)
add_library(PE::Library ALIAS pe-lib)

target_sources(pe-lib PRIVATE
    pe-lib/directories_impl.cpp
    pe-lib/image_impl.cpp
    pe-lib/rich_impl.cpp
    pe-lib/sections_impl.cpp
)

target_sources(pe-lib PUBLIC
    pe-lib/defs.hpp
    pe-lib/directories.hpp
    pe-lib/image.hpp
    pe-lib/pe_platform.hpp
    pe-lib/rich.hpp
    pe-lib/sections.hpp
)

# Public include directory
target_include_directories(pe-lib PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/pe-lib"
)