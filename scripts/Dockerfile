ARG ALPINE_VERSION=latest

# ============================================================================
# Stage 1: Build
# ============================================================================
FROM alpine:${ALPINE_VERSION} AS builder

ARG THREADS="4"
ARG REPO_URL="https://github.com/LM-Firefly/subconverter"
ARG VERSION=""
ARG SHA=""

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache bash git nodejs npm gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 mbedtls-dev mbedtls-static curl-dev curl-static openssl-dev openssl-libs-static zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static libpsl-dev libpsl-static c-ares-dev nghttp2-dev nghttp2-static brotli-dev brotli-static zstd-dev zstd-static libidn2-dev libidn2-static libunistring-dev libunistring-static

# Build quickjspp
RUN git clone --depth=1 https://github.com/ftk/quickjspp && \
    cd quickjspp && \
    git submodule update --init && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j ${THREADS} --target quickjs && \
    install -d /usr/lib/quickjs/ /usr/include/quickjs/ && \
    install -m644 build/quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include/ && \
    cd .. && rm -rf quickjspp

# Build libcron
RUN git clone --depth=1 https://github.com/PerMalmberg/libcron && \
    cd libcron && git submodule update --init && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF && \
    cmake --build build -j ${THREADS} --target libcron && \
    cmake --install build && \
    cd .. && rm -rf libcron

# Build toml11
RUN git clone --depth=1 https://github.com/ToruNiina/toml11 && \
    cd toml11 && \
    cmake -S . -B build -DCMAKE_CXX_STANDARD=11 -DBUILD_TESTING=OFF && \
    cmake --build build -j ${THREADS} && \
    cmake --install build && \
    cd .. && rm -rf toml11

# Build yaml-cpp
RUN git clone --depth=1 https://github.com/jbeder/yaml-cpp && \
    cd yaml-cpp && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TESTS=OFF -DYAML_BUILD_SHARED_LIBS=OFF && \
    cmake --build build -j ${THREADS} && \
    cmake --install build && \
    cd .. && rm -rf yaml-cpp

# Clone and build subconverter
RUN git clone --depth=1 ${REPO_URL} subconverter && \
    cd subconverter && \
    if [ -n "${VERSION}" ]; then sed -i "s/\(v[0-9]\.[0-9]\.[0-9]\)/\1-${VERSION}/" src/version.h; else time=$(date +%y.%m%d.%H%M-) && sha=$(git rev-parse --short HEAD) && sed -i "s/\(v[0-9]\.[0-9]\.[0-9]\)/\1-${time}${sha}/" src/version.h; fi && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j ${THREADS} && \
    cp build/subconverter /usr/bin/subconverter

# Update rules
RUN cd subconverter && \
    python3 -m venv venv && \
    . venv/bin/activate && \
    pip install -q gitpython && \
    python3 scripts/update_rules.py -c scripts/rules_config.conf && \
    cp -r base /base && \
    cd .. && rm -rf subconverter

# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM alpine:${ALPINE_VERSION}

LABEL maintainer="firefly.lzh@gmail.com"

RUN apk add --no-cache --virtual subconverter-deps pcre2 libcurl yaml-cpp tzdata && \
    cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    apk del tzdata

COPY --from=builder /usr/bin/subconverter /usr/bin/subconverter
COPY --from=builder /base /base

WORKDIR /base
CMD ["subconverter"]
EXPOSE 25500/tcp
