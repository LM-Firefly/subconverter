#!/bin/bash
set -xe

apk add --no-cache --virtual .build-deps bash git nodejs npm gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 mbedtls-dev mbedtls-static curl-dev curl-static openssl-dev zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static yaml-cpp-dev libpsl-dev libpsl-static c-ares-dev nghttp2-dev nghttp2-static

# Suppress noisy warnings from third-party headers during CI builds.
# These make subproject cmake runs inherit flags via environment in many cases.
export CXXFLAGS="${CXXFLAGS} -Wno-shadow -Wno-deprecated-declarations -Wno-deprecated-copy -Wno-sign-conversion -Wno-conversion"
export CFLAGS="${CFLAGS}"
export CPPFLAGS="${CPPFLAGS} -isystem /usr/local/include"
export CXXFLAGS="${CXXFLAGS} -isystem /usr/local/include"
export LDFLAGS="${LDFLAGS} -L/usr/lib"

git clone https://github.com/ftk/quickjspp --depth=1
cd quickjspp
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="${CXXFLAGS}" .
make quickjs -j4
install -d /usr/lib/quickjs/
install -m644 quickjs/libquickjs.a /usr/lib/quickjs/
install -d /usr/include/quickjs/
install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/
install -m644 quickjspp.hpp /usr/include/
cd ..

git clone https://github.com/PerMalmberg/libcron --depth=1
cd libcron
git submodule update --init
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF -DCMAKE_CXX_FLAGS="${CXXFLAGS}" .
cmake --build . --target libcron -- -j4
cmake --install . --prefix /usr/local
cd ..

git clone https://github.com/ToruNiina/toml11 --depth=1
cd toml11
cmake -DCMAKE_CXX_STANDARD=11 -DBUILD_TESTING=OFF -DCMAKE_CXX_FLAGS="${CXXFLAGS}" .
make install -j4
cd ..

export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="${CXXFLAGS}" -DBUILD_TESTING=OFF .
make -j4

python3 -m venv venv
source venv/bin/activate

pip install gitpython
python3 scripts/update_rules.py -c scripts/rules_config.conf
mkdir -p base
mv subconverter base/

cd base
chmod +rx subconverter
chmod +r ./*
cd ..
mv base subconverter
