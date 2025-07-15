#!/bin/bash
set -xe

# 获取系统架构
ARCH=$(uname -m)
[ "$ARCH" == "x86_64" ] && TOOLCHAIN="mingw-w64-x86_64" || TOOLCHAIN="mingw-w64-i686"

# 设置构建参数
SRC_BUILD_JOBS=${SRC_BUILD_JOBS:-4}
CMAKE_GENERATOR="Unix Makefiles"
CMAKE_COMMON_ARGS="-DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=$MINGW_PREFIX"

# 安装依赖包
pacman -S --needed --noconfirm \
    base-devel \
    ${TOOLCHAIN}-{toolchain,cmake,openssl,curl,zstd,pcre2,mbedtls} \
    ${TOOLCHAIN}-{nghttp2,nghttp3,ngtcp2,libssh2,libpsl} \
    ${TOOLCHAIN}-{libidn2,libunistring,libiconv,brotli,zlib}

# 从源码构建静态库的辅助函数
build_static_cmake() {
    local repo=$1 dir=$2 extra_args=$3
    git clone --depth=1 "$repo" "$dir"
    cmake -S "$dir" -B "$dir/build" -G "$CMAKE_GENERATOR" $CMAKE_COMMON_ARGS $extra_args
    cmake --build "$dir/build" -j $SRC_BUILD_JOBS
    cmake --install "$dir/build"
}

# 构建 brotli 和 zstd（MSYS2包可能包含动态库，从源码构建确保纯静态）
echo "=== Building brotli and zstd from source ==="
build_static_cmake https://github.com/google/brotli brotli-src "-DBROTLI_DISABLE_TESTS=ON"

# zstd 需要特殊处理（CMake在子目录）
ZSTD_VERSION=1.5.6
curl -sL "https://github.com/facebook/zstd/archive/refs/tags/v${ZSTD_VERSION}.tar.gz" | \
    tar -xz --exclude="*/tests" --exclude="*/contrib"
cmake -S "zstd-${ZSTD_VERSION}/build/cmake" -B "zstd-build" -G "$CMAKE_GENERATOR" $CMAKE_COMMON_ARGS \
    -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_TESTS=OFF
cmake --build zstd-build -j $SRC_BUILD_JOBS --target libzstd_static
cmake --install zstd-build

# 清理导入库，强制使用静态库
echo "=== Cleaning import libraries ==="
for lib in brotli{dec,enc,common} zstd idn2 unistring iconv psl; do
    rm -f "$MINGW_PREFIX/lib/lib${lib}.dll.a"
done

# 验证静态库存在
REQUIRED_LIBS=(curl nghttp{2,3} ngtcp2 brotli{dec,enc,common} zstd 
               idn2 unistring iconv psl ssh2 ssl crypto z)
echo "=== Verifying static libraries ==="
missing=()
for lib in "${REQUIRED_LIBS[@]}"; do
    [ -f "$MINGW_PREFIX/lib/lib${lib}.a" ] || missing+=("$lib")
done
if [ ${#missing[@]} -gt 0 ]; then
    echo "Missing: ${missing[*]}"
    exit 1
fi
echo "All required static libraries present"

rm -rf ~/.cache/pkgconfig 2>/dev/null || true

# 构建其他依赖库
echo "=== Building additional dependencies ==="
build_static_cmake https://github.com/jbeder/yaml-cpp yaml-cpp \
    "-DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF"

build_static_cmake https://github.com/Tencent/rapidjson rapidjson \
    "-DRAPIDJSON_BUILD_DOC=OFF -DRAPIDJSON_BUILD_EXAMPLES=OFF -DRAPIDJSON_BUILD_TESTS=OFF"

build_static_cmake https://github.com/ToruNiina/toml11 toml11 "-DCMAKE_CXX_STANDARD=11"

# libcron 需要子模块
git clone --depth=1 https://github.com/PerMalmberg/libcron
(cd libcron && git submodule update --init)
# 单独构建 libcron (已手动 clone，直接配置与安装)
cmake -S libcron -B libcron/build -G "$CMAKE_GENERATOR" $CMAKE_COMMON_ARGS
cmake --build libcron/build -j $SRC_BUILD_JOBS --target libcron
cmake --install libcron/build

# QuickJS 需要特殊处理
git clone --depth=1 https://github.com/ftk/quickjspp
cd quickjspp
patch quickjs/quickjs-libc.c -i ../scripts/patches/0001-quickjs-libc-add-realpath-for-Windows.patch
cmake -G "$CMAKE_GENERATOR" $CMAKE_COMMON_ARGS -DCMAKE_C_FLAGS="-D__MINGW_FENV_DEFINED" .
cmake --build . -j $SRC_BUILD_JOBS --target quickjs
install -Dm644 quickjs/libquickjs.a -t "$MINGW_PREFIX/lib/quickjs/"
install -Dm644 quickjs/{quickjs.h,quickjs-libc.h} -t "$MINGW_PREFIX/include/quickjs/"
install -Dm644 quickjspp.hpp -t "$MINGW_PREFIX/include/"
cd ..

# 更新规则
python -m venv venv
source venv/$([ -f venv/Scripts/activate ] && echo Scripts || echo bin)/activate
pip install -q gitpython
python scripts/update_rules.py -c scripts/rules_config.conf

# 移除可能干扰的 pkg-config
rm -f /c/Strawberry/perl/bin/pkg-config{,.bat}

# 构建 subconverter
echo "=== Building subconverter ==="
export CMAKE_FIND_LIBRARY_SUFFIXES=".a"

cmake -G "$CMAKE_GENERATOR" $CMAKE_COMMON_ARGS \
    -DCMAKE_PREFIX_PATH=$MINGW_PREFIX \
    -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++ -Wl,--allow-multiple-definition -Wl,-Bstatic -s" \
    -DFORCE_STATIC_DEPS=ON \
    -DCURL_INCLUDE_DIR="$MINGW_PREFIX/include" \
    -DCURL_LIBRARY="$MINGW_PREFIX/lib/libcurl.a" \
    -DCURL_STATICLIB=ON \
    -DNGHTTP2_INCLUDE_DIR="$MINGW_PREFIX/include" \
    -DNGHTTP2_LIBRARY="$MINGW_PREFIX/lib/libnghttp2.a" .

make VERBOSE=1 -j$SRC_BUILD_JOBS 2>&1 | tee build.log

# 验证无动态依赖
echo "=== Verifying static linkage ==="
if ldd subconverter.exe 2>/dev/null | grep -iE "(libcurl|libpcre2|libnghttp|libbrotli|libidn|libunistring|libzstd)" | grep -v "not found"; then
    echo "Found unwanted DLL dependencies!"
    exit 1
fi

# 打包
mkdir -p subconverter
cp -r subconverter.exe base/* subconverter/
echo "Static build successful"
ldd subconverter/subconverter.exe 2>/dev/null || echo "Pure static executable"