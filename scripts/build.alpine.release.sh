#!/bin/bash
set -xe

apk add --no-cache --virtual .build-deps bash git nodejs npm gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 mbedtls-dev mbedtls-static curl-dev curl-static openssl-dev zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static yaml-cpp-dev libpsl-dev libpsl-static c-ares-dev nghttp2-dev nghttp2-static

git clone https://github.com/jbeder/yaml-cpp --depth=1
cd yaml-cpp
cmake -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF .
make install -j4
cd ..

git clone https://github.com/ftk/quickjspp --depth=1
cd quickjspp
cmake -DCMAKE_BUILD_TYPE=Release .
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
cmake -DCMAKE_BUILD_TYPE=Release .
make libcron install -j4
cd ..

git clone https://github.com/ToruNiina/toml11 --depth=1
cd toml11
cmake -DCMAKE_CXX_STANDARD=11 .
make install -j4
cd ..

export PKG_CONFIG_PATH=/usr/lib64/pkgconfig
cmake -DCMAKE_BUILD_TYPE=Release .
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
