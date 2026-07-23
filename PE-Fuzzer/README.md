# PE-Fuzzer

libFuzzer harnesses for PE-Library. Instead of one monolithic test that
exercises every parser per input, there is one focused target per subsystem:

| Target        | Covers                                                        |
|---------------|---------------------------------------------------------------|
| `image`       | `Image` construction/validation, header getters, `DataDirectory` |
| `sections`    | Section table parsing, lookups, `AddSection` + reparse        |
| `rich`        | Rich header location, checksum, entry decoding                |
| `imports`     | Import descriptors, thunk walking, name lookups               |
| `exports`     | Export tables, forwarders, `ByName`/`ByOrdinal`               |
| `relocations` | Base relocation blocks and entries                            |
| `tls`         | TLS directory (32/64-bit) and callback array                  |
| `resources`   | Resource tree, version info, manifest, data blobs             |
| `debug`       | Debug directory entries                                       |
| `utils`       | RVA/VA/offset conversions, string extraction, `PatternScan`   |

Each target lives in `targets/fuzz_<name>.cpp` and builds into its own binary,
so coverage feedback is specific to that subsystem and the corpus for (say)
imports evolves toward interesting import tables instead of having to satisfy
every parser at once.

## Building

One target per build, selected by the `FuzzTarget` MSBuild property
(default: `image`):

```
msbuild PE-Fuzzer.vcxproj /p:Configuration=Release /p:Platform=x64 /p:FuzzTarget=imports
```

Or build everything:

```
build-all.cmd [Configuration] [Platform]
```

Binaries land in `bin\PE-Fuzzer-<target>\<platform>\<configuration>\`.

## Building & running on Linux/macOS (Clang)

The library is now portable C++ - `pe_platform.hpp` supplies the PE constants
and CRT shims that `<windows.h>` provides on Windows, so the fuzzers build
natively with Clang's libFuzzer under ASan + UBSan:

```
./build-linux.sh                 # all targets -> build/fuzz_<name>
./build-linux.sh imports tls     # just these two
CXX=clang++-18 ./build-linux.sh  # pick a compiler

python3 make_seed.py seed.bin    # minimal valid PE64 corpus seed
mkdir -p corpus_imports
./build/fuzz_imports -max_len=65536 corpus_imports seed.bin
```

UBSan runs with the `alignment` check disabled: PE-Library reinterpret_casts
directly into the file buffer at attacker-controlled offsets, so unaligned
reads happen on nearly every input, technically UB, but harmless on x86/ARM
and intrinsic to how the parser reads packed on-disk structures. Every other
UBSan check stays fatal. See the header of `build-linux.sh` to re-enable
alignment auditing.

## Running

All targets accept the same inputs (any PE file, 64 bytes – 50 MB), so a
single seed corpus of real PEs can seed every target. Give each target its
own working corpus directory so they evolve independently:

```
PE-Fuzzer-imports.exe corpus\imports seeds -jobs=6 -workers=6 -rss_limit_mb=0 -dict=pe-fuzzer.dict
```

Tip: `-max_len=1048576` (or similar) keeps per-exec cost down, large inputs
mostly add I/O, not coverage.

## Harness conventions (`targets/common.hpp`)

- **Sinks.** Every API result is passed to `fuzz::Consume`/`ConsumeObject`,
  which folds it into `volatile` globals. The Release configuration builds
  with LTCG (`WholeProgramOptimization`), under which a discarded return
  value lets the optimizer inline the call and delete the parsing work,
  including the out-of-bounds reads ASan exists to catch. The sinks force
  every result (and every byte behind returned `string_view`s/vectors) to be
  genuinely computed and read.
- **Parameters.** Fuzzer-chosen values (ordinals, type ids, lookup names)
  come from `fuzz::ParamU8/U16/U32/U64/ParamName`, which read the tail bytes
  of the input. The tail overlaps the image bytes on purpose: real PEs remain
  valid corpus entries, and the mutator steers parameters via the file's last
  64 bytes.
- **Exceptions.** The library is `noexcept`-heavy; the `catch (...)` guards
  `std::bad_alloc` and standard-library throws only. Memory errors are
  reported by ASan regardless.

### Note:
When adding a new subsystem to the library, add a matching
`targets/fuzz_<name>.cpp`, consume every result through the sinks, and add
the name to the list in `build-all.cmd`.
