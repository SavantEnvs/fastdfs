#!/usr/bin/env bash
# Builds, in place and offline: the FastDFS client library and the tracker server's state objects
# (sanitized, for the fuzz targets, and plain, for the test probes), the fuzz targets with their
# -standalone reproducers, and the known-answer probes.
# libfastcommon / libserverframe come prebuilt (static) from /opt/toolchains/deps (see build-deps.sh).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

FC=/opt/toolchains/deps/libfastcommon-1.0.88
SF=/opt/toolchains/deps/libserverframe-1.2.15
# libfastcommon's inline buff2int/buff2long (decoding every wire field) shift signed bytes into the sign bit,
# so UBSan's shift-base aborts on any packet with a high byte; that one check is relaxed, the rest stay on.
RELAX_UBSAN="-fno-sanitize=shift-base"
INC="-I$SRC/common -I$SRC/tracker -I$SRC/storage/trunk_mgr -I$SRC/client -I$SRC/mayhem -I$FC/include -I$SF/include"
DEFS="-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE"
LIBS="$SF/lib/libserverframe.a $FC/lib/libfastcommon.a -lpthread -lm -ldl"

LIB_SRCS="common/fdfs_global.c common/fdfs_http_shared.c common/mime_file_parser.c
 tracker/tracker_proto.c tracker/fdfs_shared_func.c tracker/fdfs_server_id_func.c
 storage/trunk_mgr/trunk_shared.c client/tracker_client.c client/client_func.c
 client/client_global.c client/storage_client.c"
# The tracker server pieces fuzz_tracker_request links: tracker_service.c and tracker_mem.c are #included
# into its translation unit (tracker_env.h), so only these are compiled on their own.
SRV_SRCS="tracker/tracker_global.c tracker/tracker_relationship.c tracker/tracker_status.c"
TARGETS="fuzz_file_id fuzz_tracker_response fuzz_storage_response fuzz_config_text fuzz_tracker_request"

B="$SRC/mayhem/build"
rm -rf "$B"
mkdir -p "$B/fuzz" "$B/test" "$B/fuzz_srv" "$B/test_srv"

# 1) The project's client library, sanitized (fuzz build) and plain (test build).
compile_lib() { # <objdir> <sources> <flags...>
  local dir="$1" srcs="$2"; shift 2
  for src in $srcs; do
    "$CC" "$@" $DEFS $INC -Wall -Wno-format-truncation -c "$src" -o "$dir/$(basename "$src" .c).o"
  done
}
# shellcheck disable=SC2086
compile_lib "$B/fuzz" "$LIB_SRCS" $SANITIZER_FLAGS $RELAX_UBSAN $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1
# shellcheck disable=SC2086
compile_lib "$B/fuzz_srv" "$SRV_SRCS" $SANITIZER_FLAGS $RELAX_UBSAN $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1
# shellcheck disable=SC2086
compile_lib "$B/test" "$LIB_SRCS" -O2 -g $COVERAGE_FLAGS
# shellcheck disable=SC2086
compile_lib "$B/test_srv" "$SRV_SRCS" -O2 -g $COVERAGE_FLAGS

# 2) Leak-sanitizer off-switch, linked into every fuzz and standalone binary.
# shellcheck disable=SC2086
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c mayhem/lsan_off.cc -o "$B/lsan_off.o"

# 3) Fuzz targets + standalone reproducers.
for t in $TARGETS; do
  # fuzz_config_text includes tracker/fdfs_server_id_func.c itself, so it links without that object.
  objs=()
  for o in "$B"/fuzz/*.o; do
    if [ "$t" = fuzz_config_text ] && [ "$(basename "$o")" = fdfs_server_id_func.o ]; then continue; fi
    objs+=("$o")
  done
  if [ "$t" = fuzz_tracker_request ]; then objs+=("$B"/fuzz_srv/*.o); fi
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $RELAX_UBSAN $DEBUG_FLAGS -fsanitize=fuzzer-no-link -O1 $DEFS $INC -c "mayhem/$t.c" -o "$B/$t.o"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/$t.o" "${objs[@]}" "$B/lsan_off.o" $LIBS -o "/mayhem/$t"
  # shellcheck disable=SC2086
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$STANDALONE_FUZZ_MAIN" "$B/$t.o" "${objs[@]}" "$B/lsan_off.o" $LIBS -o "/mayhem/$t-standalone"
done

# 4) Known-answer probes for mayhem/test.sh (normal flags, dynamically linked).
# shellcheck disable=SC2086
$CC -O2 -g $COVERAGE_FLAGS $DEFS $INC mayhem/kat_probe.c "$B"/test/*.o $LIBS -o /mayhem/kat_probe
file /mayhem/kat_probe | grep -q 'dynamically linked'
# shellcheck disable=SC2086
$CC -O2 -g $COVERAGE_FLAGS $DEFS $INC mayhem/kat_tracker_probe.c "$B"/test/*.o "$B"/test_srv/*.o $LIBS \
  -o /mayhem/kat_tracker_probe
file /mayhem/kat_tracker_probe | grep -q 'dynamically linked'
