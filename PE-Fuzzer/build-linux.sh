#!/usr/bin/env bash
# Build the PE-Library fuzz targets natively on Linux/macOS with Clang's
# libFuzzer, AddressSanitizer, and UndefinedBehaviorSanitizer.
#
# Usage:
#   ./build-linux.sh [target ...]      # default: all targets
#   CXX=clang++-18 ./build-linux.sh image imports
#
# Output binaries: build/fuzz_<target>
#
# UBSan note: the `alignment` check is disabled. PE-Library reinterpret_casts
# directly into the file buffer at attacker-controlled offsets, so unaligned
# reads occur on nearly every input. That is UB but harmless on x86/ARM and
# intrinsic to how the parser reads packed on-disk structures. Disabling it
# lets every other UBSan check stay fatal (-fno-sanitize-recover=all) and
# meaningful. To audit alignment instead, drop -fno-sanitize=alignment below
# and add -fsanitize-recover=alignment so it logs without aborting.

set -euo pipefail

cd "$(dirname "$0")"

CXX="${CXX:-clang++}"
LIB=../PE-Library/pe-lib
OUT=build
mkdir -p "$OUT"

SAN="address,undefined"
COMMON=(-std=c++20 -O1 -g -fno-omit-frame-pointer -I "$LIB")
# Applied AFTER -fsanitize= so they win: -fsanitize=undefined would otherwise
# re-enable the whole set (including alignment) if it came later.
SAN_TUNE=(-fno-sanitize=alignment -fno-sanitize-recover=all)

ALL_TARGETS=(image sections rich imports exports relocations tls resources debug utils)
TARGETS=("$@")
if [ ${#TARGETS[@]} -eq 0 ]; then
	TARGETS=("${ALL_TARGETS[@]}")
fi

echo "Compiling library (instrumented)..."
LIB_OBJS=()
for src in "$LIB"/*_impl.cpp; do
	obj="$OUT/$(basename "$src" .cpp).o"
	"$CXX" "${COMMON[@]}" -fsanitize=fuzzer-no-link,"$SAN" "${SAN_TUNE[@]}" -c "$src" -o "$obj"
	LIB_OBJS+=("$obj")
done

for t in "${TARGETS[@]}"; do
	echo "Linking fuzz target: $t"
	"$CXX" "${COMMON[@]}" -fsanitize=fuzzer,"$SAN" "${SAN_TUNE[@]}" \
		"targets/fuzz_$t.cpp" "${LIB_OBJS[@]}" -o "$OUT/fuzz_$t"
done

echo "Done. Binaries in $OUT/"
