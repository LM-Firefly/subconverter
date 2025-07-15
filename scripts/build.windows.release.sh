#!/bin/bash
set -xe

# 获取系统架构
ARCH=$(uname -m)

if [ "$ARCH" == "x86_64" ]; then
    TOOLCHAIN="mingw-w64-x86_64"
else
    TOOLCHAIN="mingw-w64-i686"
fi

pacman -S --needed --noconfirm base-devel ${TOOLCHAIN}-toolchain ${TOOLCHAIN}-cmake ${TOOLCHAIN}-openssl ${TOOLCHAIN}-curl ${TOOLCHAIN}-zstd ${TOOLCHAIN}-pcre2 ${TOOLCHAIN}-mbedtls ${TOOLCHAIN}-nghttp2 ${TOOLCHAIN}-libidn2 ${TOOLCHAIN}-libunistring ${TOOLCHAIN}-brotli

git clone https://github.com/jbeder/yaml-cpp --depth=1
cd yaml-cpp
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF -DCMAKE_INSTALL_PREFIX="$MINGW_PREFIX" -G "Unix Makefiles" .
make install -j4
cd ..

git clone https://github.com/ftk/quickjspp --depth=1
cd quickjspp
patch quickjs/quickjs-libc.c -i ../scripts/patches/0001-quickjs-libc-add-realpath-for-Windows.patch
cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-D__MINGW_FENV_DEFINED" .
make quickjs -j4

install -d "$MINGW_PREFIX/lib/quickjs/"
install -m644 quickjs/libquickjs.a "$MINGW_PREFIX/lib/quickjs/"
install -d "$MINGW_PREFIX/include/quickjs"
install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h "$MINGW_PREFIX/include/quickjs/"
install -m644 quickjspp.hpp "$MINGW_PREFIX/include/"
cd ..

git clone https://github.com/PerMalmberg/libcron --depth=1
cd libcron
git submodule update --init
cmake -G "Unix Makefiles" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$MINGW_PREFIX" .
make libcron install -j4
cd ..

git clone https://github.com/Tencent/rapidjson --depth=1
cd rapidjson
cmake -DRAPIDJSON_BUILD_DOC=OFF -DRAPIDJSON_BUILD_EXAMPLES=OFF -DRAPIDJSON_BUILD_TESTS=OFF -DCMAKE_INSTALL_PREFIX="$MINGW_PREFIX" -G "Unix Makefiles" .
make install -j4
cd ..

git clone https://github.com/ToruNiina/toml11 --depth=1
cd toml11
cmake -DCMAKE_INSTALL_PREFIX="$MINGW_PREFIX" -G "Unix Makefiles" -DCMAKE_CXX_STANDARD=11 .
make install -j4
cd ..

python -m venv venv
if [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi
pip install gitpython

python -m ensurepip
python -m pip install gitpython
python scripts/update_rules.py -c scripts/rules_config.conf

rm -f C:/Strawberry/perl/bin/pkg-config C:/Strawberry/perl/bin/pkg-config.bat
cmake -DCMAKE_PREFIX_PATH=$MINGW_PREFIX -DCMAKE_BUILD_TYPE=Release '-DCMAKE_EXE_LINKER_FLAGS=-static -Wl,--allow-multiple-definition -s' -G 'Unix Makefiles' -DCURL_INCLUDE_DIR="$MINGW_PREFIX/include" -DCURL_LIBRARY="$MINGW_PREFIX/lib/libcurl.a" -DNGHTTP2_INCLUDE_DIR="$MINGW_PREFIX/include" -DNGHTTP2_LIBRARY="$MINGW_PREFIX/lib/libnghttp2.a" .
make -j4
mkdir -p out_tmp
cp subconverter.exe out_tmp/
cp -r base/* out_tmp/
rm -rf subconverter
mv out_tmp subconverter
ldd subconverter/subconverter.exe
