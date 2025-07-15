#!/bin/bash
set -euo pipefail

# ============================================================================
# Alpine Linux build script for subconverter
# ============================================================================

BUILD_JOBS=${BUILD_JOBS:-$(nproc)}
step() { echo -e "\n==> $1\n"; }

# --- Install system dependencies ---
step "Installing build dependencies"
apk add --no-cache --virtual .build-deps bash git nodejs npm gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 mbedtls-dev mbedtls-static curl-dev curl-static openssl-dev openssl-libs-static zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static libpsl-dev libpsl-static c-ares-dev nghttp2-dev nghttp2-static brotli-dev brotli-static zstd-dev zstd-static libidn2-dev libidn2-static libunistring-dev libunistring-static

# --- Compiler flags ---
export CXXFLAGS="${CXXFLAGS:-} -Wno-shadow -Wno-deprecated-declarations -Wno-deprecated-copy -Wno-sign-conversion -Wno-conversion -isystem /usr/local/include"
export CPPFLAGS="${CPPFLAGS:-} -isystem /usr/local/include"
export LDFLAGS="${LDFLAGS:-} -L/usr/lib"

# --- Helper: cmake configure + build + install (no clone) ---
cmake_build_install() {
    local dir=$1 extra_args=${2:-} subdir=${3:-.} target=${4:-}
    cmake -S "$dir/$subdir" -B "$dir/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF $extra_args
    cmake --build "$dir/build" -j "$BUILD_JOBS" ${target:+--target "$target"}
    cmake --install "$dir/build"
}

# --- Helper: clone + cmake build + install ---
build_cmake() {
    local repo=$1 dir=$2 extra_args=${3:-} subdir=${4:-.} target=${5:-}
    git clone --depth=1 "$repo" "$dir"
    cmake_build_install "$dir" "$extra_args" "$subdir" "$target"
}

# --- Build dependencies from source ---

step "Building quickjspp"
git clone --depth=1 https://github.com/ftk/quickjspp quickjspp
cmake -S quickjspp -B quickjspp/build -DCMAKE_BUILD_TYPE=Release
cmake --build quickjspp/build -j "$BUILD_JOBS" --target quickjs
install -d /usr/lib/quickjs/ /usr/include/quickjs/
install -m644 quickjspp/build/quickjs/libquickjs.a /usr/lib/quickjs/
install -m644 quickjspp/quickjs/quickjs.h quickjspp/quickjs/quickjs-libc.h /usr/include/quickjs/
install -m644 quickjspp/quickjspp.hpp /usr/include/

step "Building libcron"
git clone --depth=1 https://github.com/PerMalmberg/libcron libcron
(cd libcron && git submodule update --init)
cmake_build_install libcron "" "." libcron

step "Building toml11"
build_cmake https://github.com/ToruNiina/toml11 toml11 "-DCMAKE_CXX_STANDARD=11"

step "Building yaml-cpp"
git clone --depth=1 https://github.com/jbeder/yaml-cpp yaml-cpp
cmake -S yaml-cpp -B yaml-cpp/build -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TESTS=OFF -DYAML_BUILD_SHARED_LIBS=OFF
cmake --build yaml-cpp/build -j "$BUILD_JOBS"
cmake --install yaml-cpp/build

# --- Build subconverter ---
step "Building subconverter"
export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF
cmake --build build -j "$BUILD_JOBS"

# --- Update rules ---
step "Updating rules"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install -q gitpython
python3 scripts/update_rules.py -c scripts/rules_config.conf

# --- Package ---
step "Packaging"
mkdir -p subconverter
cp build/subconverter subconverter/
cp -r base/* subconverter/
chmod +rx subconverter/subconverter
echo "Build complete: subconverter/"
