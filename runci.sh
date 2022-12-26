#!/bin/bash
set -euo pipefail

USE_MSAN=0
USE_TSAN=0

autoreconf -i

# Test with ASAN / Address Sanitizer
export ASAN_OPTIONS="abort_on_error=1"
./configure CFLAGS="-fsanitize=address -U_FORTIFY_SOURCE" LDFLAGS="-fsanitize=address -U_FORTIFY_SOURCE"
make clean
make
make check

# Test with clang and UBSAN / Undefined Behavior Sanitizer
export UBSAN_OPTIONS="halt_on_error=1:abort_on_error=1"
./configure CC=clang LD=clang CFLAGS="-fsanitize=undefined" LDFLAGS="-fsanitize=undefined"
make clean
make
make check

# Test with clang and MSAN / Memory Sanitizer
if [ "$USE_MSAN" -eq 1 ]; then
	export MSAN_OPTIONS="abort_on_error=1"
	./configure CC=clang LD=clang CFLAGS="-fsanitize=memory -U_FORTIFY_SOURCE" LDFLAGS="-fsanitize=memory -U_FORTIFY_SOURCE"
	make clean
	make
	make check
fi

# Test with clang and MSAN / Memory Sanitizer
if [ "$USE_TSAN" -eq 1 ]; then
	export MSAN_OPTIONS="abort_on_error=1"
	./configure CC=clang LD=clang CFLAGS="-fsanitize=memory -U_FORTIFY_SOURCE" LDFLAGS="-fsanitize=memory -U_FORTIFY_SOURCE"
	make clean
	make
	make check
fi

