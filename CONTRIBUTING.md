# Contributing to PE-Library

Thanks for your interest in contributing! This document covers what we accept, how to submit changes, and the conventions you should follow.

## What We Accept

* Bug reports & crash reproducers (especially with ASAN/UBSAN logs)
* Parser improvements / edge-case handling
* Performance optimizations
* Better documentation / code comments
* Fuzzer samples, dictionary entries, or mutation strategies

## Before You Start

If you're fixing a bug or adding a feature, please **open an issue first** so it can be discussed before you invest time in a PR, unless it's a very obvious typo or doc fix, in which case you can go straight to a pull request.

## Getting Set Up

### Prerequisites

* Visual Studio 2022 (or later, with C++17 support)
* Windows SDK 10.0
* Platform Toolset v143 or later

### Building

The library is designed to be consumed via CMake's `FetchContent`, but for local development you can clone and build directly:

```
git clone https://github.com/NtProtectVirtualMemory/PE-Library.git
cd PE-Library
```

Open the project in Visual Studio, or configure with CMake, and build as usual.

## Making Changes

1. Fork the repository and create your branch from `master`.
2. Make your changes, following the existing code style (see [Code Style](#code-style) below).
3. If you're fixing a bug found via fuzzing, include a minimized reproducer and, if available, ASAN/UBSAN output.
4. Keep pull requests small and focused, with a clear title and description. Note any change in validation behavior explicitly (e.g. "now also flags X as `ValidationIssue::Y`"), since downstream consumers may rely on existing flag semantics.

## Code Style

* **Naming:** `snake_case` for private members/functions, `PascalCase` for public types and public member functions.
* **Braces:** Allman style (opening brace on its own line).
* **Safety:** This library parses untrusted, attacker-controlled PE files. Bounds-check before every offset calculation and before any `reinterpret_cast` into the byte buffer. Never trust a header field without validating it against the buffer size first.
* **Error handling:** No exceptions in the parsing path, return `false` / `0` / empty containers (or partial results if any) on failure, and use `ValidationIssue` flags to communicate what went wrong. Mark parsing/query functions `noexcept` where possible.
* **Overflow:** When combining attacker-controlled offsets and sizes, widen to `uint64_t` before adding, then range-check before narrowing back down.

## Fuzzing

The `PE-Fuzzer/` directory contains our fuzzing setup, which has already processed ~275,000 PE samples and helped catch multiple parsing edge cases, buffer issues, and slow units. If you're modifying parsing logic:

* Consider running the fuzzer locally against your change.
* Report any new crashes or slow units the same way as other bugs; with a reproducer and, ideally, ASAN/UBSAN output.

## Reporting Security Issues

If you find a memory-safety bug (out-of-bounds read/write, crash on malformed input, etc.), please report it responsibly:

* Open an issue and mark it clearly as a security concern, or reach out to a maintainer directly.
* Include reproduction steps and, where possible, a minimized sample and ASAN/UBSAN logs.

## Questions?

If anything here is unclear, feel free to open an issue and ask before submitting a PR.