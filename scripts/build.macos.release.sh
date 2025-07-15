#!/bin/bash
set -euo pipefail

# ============================================================================
# macOS build script for subconverter
# ============================================================================

BUILD_JOBS=${BUILD_JOBS:-$(sysctl -n hw.ncpu 2>/dev/null || echo 4)}
BREW_PREFIX=$(brew --prefix)
step() { echo -e "\n==> $1\n"; }

# --- Install dependencies ---
step "Installing dependencies"
brew reinstall rapidjson zlib pcre2 pkgconfig curl openssl@3

# --- Environment setup ---
export PATH="${BREW_PREFIX}/bin:$PATH"
export PKG_CONFIG_PATH="${BREW_PREFIX}/lib/pkgconfig"
export CPPFLAGS="${CPPFLAGS:-} -I${BREW_PREFIX}/opt/zlib/include -I${BREW_PREFIX}/opt/curl/include -I${BREW_PREFIX}/opt/openssl@3/include"
export LDFLAGS="${LDFLAGS:-} -L${BREW_PREFIX}/opt/zlib/lib -L${BREW_PREFIX}/opt/curl/lib -L${BREW_PREFIX}/opt/openssl@3/lib"
export CXXFLAGS="${CXXFLAGS:-} -Wno-shadow -Wno-deprecated-declarations -Wno-deprecated-copy"
export CFLAGS="${CFLAGS:-} -Wno-shadow -Wno-deprecated-declarations -Wno-deprecated-copy"

# --- Helper: cmake configure + build + install (no clone) ---
cmake_build_install() {
    local dir=$1 extra_args=${2:-} subdir=${3:-.} target=${4:-}
    cmake -S "$dir/$subdir" -B "$dir/build" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF $extra_args
    cmake --build "$dir/build" -j "$BUILD_JOBS" ${target:+--target "$target"}
    sudo cmake --install "$dir/build"
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
sudo install -d /usr/local/lib/quickjs/ /usr/local/include/quickjs/
sudo install -m644 quickjspp/build/quickjs/libquickjs.a /usr/local/lib/quickjs/
sudo install -m644 quickjspp/quickjs/quickjs.h quickjspp/quickjs/quickjs-libc.h /usr/local/include/quickjs/
sudo install -m644 quickjspp/quickjspp.hpp /usr/local/include/

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
sudo cmake --install yaml-cpp/build

# --- Build subconverter ---
step "Building subconverter"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DFORCE_STATIC_DEPS=OFF -DCURL_ROOT="${BREW_PREFIX}/opt/curl" -DOPENSSL_ROOT_DIR="${BREW_PREFIX}/opt/openssl@3"
cmake --build build -j "$BUILD_JOBS"

# macOS special linking: hide all internal symbols, use static libs
step "Linking final binary"
rm -f build/subconverter
c++ -Xlinker -unexported_symbol -Xlinker "*" -o base/subconverter -framework CoreFoundation -framework Security $(find build/CMakeFiles/subconverter.dir/src/ -name "*.o") "${BREW_PREFIX}/opt/zlib/lib/libz.a" "${BREW_PREFIX}/opt/pcre2/lib/libpcre2-8.a" $(find build/ /usr/local/lib/ -name "*.a" 2>/dev/null) -L"${BREW_PREFIX}/lib" -L"${BREW_PREFIX}/opt/openssl@3/lib" -lyaml-cpp -lcurl -lssl -lcrypto -O3

# --- Update rules ---
step "Updating rules"
python3 -m venv venv
# shellcheck disable=SC1091
source venv/bin/activate
pip install -q gitpython
python3 scripts/update_rules.py -c scripts/rules_config.conf

# --- Package ---
step "Packaging"
chmod +rx base/subconverter
chmod +r base/*
mv base subconverter

echo "Build complete: subconverter/"
