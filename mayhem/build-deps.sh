#!/usr/bin/env bash
# Builds libfastcommon and libserverframe (FastDFS's two dependencies, neither packaged by apt)
# once from pinned source into /opt/toolchains/deps/<name>-<version>/{src,include,lib}.
set -euxo pipefail
FC_VER=1.0.88;  FC_COMMIT=4c6efd434bdb24b72748a687e2bb5d7f33a31724
FC_SHA=7c9049ddddfb1f7c0ccd910c6ea0c4e8a9fedfe0f92cd7b54a8a6344df36d4fa
SF_VER=1.2.15;  SF_COMMIT=f15fc50e3bcd0b9b04ed12321734d181cf269348
SF_SHA=2504146b7e22c7124006ed478a27aaf3bd2f85c30c138c7b27cd81fe8d3a91a1
FC=/opt/toolchains/deps/libfastcommon-$FC_VER
SF=/opt/toolchains/deps/libserverframe-$SF_VER
B=/tmp/dep-build
CFLAGS_DEP="-Wall -Wno-format-truncation -D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -O2 -g -gdwarf-3"

fetch() { # name commit sha dest
  mkdir -p "$4"
  curl -fsSL -o /tmp/dep.tgz "https://github.com/happyfish100/$1/archive/$2.tar.gz"
  echo "$3  /tmp/dep.tgz" | sha256sum -c -
  tar -xzf /tmp/dep.tgz --strip-components=1 -C "$4"
}

mkdir -p $B
fetch libfastcommon "$FC_COMMIT" "$FC_SHA" "$FC/src"
fetch libserverframe "$SF_COMMIT" "$SF_SHA" "$SF/src"

# libfastcommon: make.sh only generates src/_os_define.h (-n: no compile); build out of tree with clang.
cp -a "$FC/src" $B/fc && cd $B/fc && bash make.sh -n >/dev/null && cd src
objs=$(sed -n '/^FAST_STATIC_OBJS/,/^$/p' Makefile.in | tr -d '\\' | sed 's/^FAST_STATIC_OBJS *=//' | tr -s ' \t\n' ' ')
make -f Makefile.in -j"$(nproc)" CC=clang CFLAGS="$CFLAGS_DEP" INC_PATH= $objs
ar rcs libfastcommon.a $objs
mkdir -p "$FC/include/fastcommon" "$FC/lib"
hdrs=$(sed -n '/^HEADER_FILES/,/^$/p' Makefile.in | tr -d '\\' | sed 's/^HEADER_FILES *=//' | tr -s ' \t\n' ' ')
cp $hdrs "$FC/include/fastcommon/"
cp libfastcommon.a "$FC/lib/"

# libserverframe: only builds a shared lib upstream; compile its objects and archive them.
cp -a "$SF/src" $B/sf && cd $B/sf/src
lo=$(find . -name '*.c' | sed 's/\.c$/.lo/')
make -f Makefile.in -j"$(nproc)" CC=clang CFLAGS="$CFLAGS_DEP" INC_PATH="-Iinclude -I$FC/include" $lo
ar rcs libserverframe.a $lo
mkdir -p "$SF/include/sf" "$SF/lib"
(cd "$SF/src/src" && find . -name '*.h' -not -path './include/*' -exec cp --parents {} "$SF/include/sf/" \;)
cp libserverframe.a "$SF/lib/"

rm -rf $B /tmp/dep.tgz
chmod -R a+rX "$FC" "$SF"
