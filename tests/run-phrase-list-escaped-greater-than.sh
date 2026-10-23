#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
build_dir="$root/src"
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

if [ ! -f "$root/e2config.h" ] || [ ! -f "$build_dir/e2guardian-ListContainer.o" ]; then
    echo "Build e2guardian first with ./autogen.sh, ./configure, and make." >&2
    exit 2
fi

cd "$build_dir"
g++ ${CXXFLAGS:-} -std=c++11 -DHAVE_CONFIG_H -include e2config.h -I. -I.. -Dmain=e2guardian_main \
    -c e2guardian.cpp -o "$tmp_dir/e2guardian-no-main.o"
set -- $(find . -name 'e2guardian-*.o' ! -name 'e2guardian-e2guardian.o' -print)
g++ ${CXXFLAGS:-} -std=c++11 -DHAVE_CONFIG_H -include e2config.h -I. -I.. \
    "$root/tests/phrase_list_escaped_greater_than.cpp" \
    "$tmp_dir/e2guardian-no-main.o" "$@" -lpthread -lz -lssl -lcrypto \
    -o "$tmp_dir/phrase-list-escaped-greater-than"
cd "$tmp_dir"
./phrase-list-escaped-greater-than
