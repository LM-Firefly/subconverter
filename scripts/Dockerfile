FROM alpine:latest
# FROM fireflylzh/subconverter:latest
LABEL maintainer="firefly.lzh@gmail.com"
# ADD https://github.com/LM-Firefly/subconverter/commits/main.atom cache_bust
ARG THREADS="4"
# ARG SHA=""

# build minimized
WORKDIR /
RUN set -xe && \
    apk add tzdata && ls /usr/share/zoneinfo && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && echo "Asia/Shanghai" > /etc/timezone && date && apk del tzdata && \
    apk add --no-cache --virtual .build-deps bash git nodejs npm gcc g++ build-base linux-headers cmake make autoconf automake libtool python3 mbedtls-dev mbedtls-static curl-dev curl-static openssl-dev zlib-dev zlib-static rapidjson-dev pcre2-dev pcre2-static yaml-cpp-dev libpsl-dev libpsl-static c-ares-dev nghttp2-dev nghttp2-static && \
    git clone https://github.com/jbeder/yaml-cpp --depth=1 && \
    cd yaml-cpp && \
    cmake -DCMAKE_BUILD_TYPE=Release -DYAML_CPP_BUILD_TESTS=OFF -DYAML_CPP_BUILD_TOOLS=OFF . && \
    make install -j4 && \
    cd .. && \
    git clone https://github.com/ftk/quickjspp --depth=1 && \
    cd quickjspp && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make quickjs -j $THREADS && \
    install -d /usr/lib/quickjs/ && \
    install -m644 quickjs/libquickjs.a /usr/lib/quickjs/ && \
    install -d /usr/include/quickjs/ && \
    install -m644 quickjs/quickjs.h quickjs/quickjs-libc.h /usr/include/quickjs/ && \
    install -m644 quickjspp.hpp /usr/include && \
    cd .. && \
    git clone https://github.com/PerMalmberg/libcron --depth=1 && \
    cd libcron && \
    git submodule update --init && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make libcron -j $THREADS && \
    install -m644 libcron/out/Release/liblibcron.a /usr/lib/ && \
    install -d /usr/include/libcron/ && \
    install -m644 libcron/include/libcron/* /usr/include/libcron/ && \
    install -d /usr/include/date/ && \
    install -m644 libcron/externals/date/include/date/* /usr/include/date/ && \
    cd .. && \
    git clone https://github.com/ToruNiina/toml11 --depth=1 && \
    cd toml11 && \
    cmake -DCMAKE_CXX_STANDARD=11 . && \
    make install -j $THREADS && \
    cd .. && \
    git clone https://github.com/LM-Firefly/subconverter --depth=1 && \
    cd subconverter && \
#    [ -n "$SHA" ] && sed -i 's/\(v[0-9]\.[0-9]\.[0-9]\)/\1-'"$SHA"'/' src/version.h;\
    time=$(date +%y.%m%d.%H%M-) && sha=$(git rev-parse --short HEAD) && sed -i 's/\(v[0-9]\.[0-9]\.[0-9]\)/\1-'"$time$sha"'/' src/version.h && \
    cmake -DCMAKE_BUILD_TYPE=Release . && \
    make -j $THREADS && \
    python3 -m venv venv && \
    source venv/bin/activate && \
    pip install gitpython && \
    python3 scripts/update_rules.py -c scripts/rules_config.conf && \
    mv subconverter /usr/bin && \
    mv base ../ && \
    cd .. && \
    rm -rf subconverter quickjspp libcron toml11 /usr/lib/lib*.a /usr/include/* /usr/local/include/lib*.a /usr/local/include/* && \
    apk add --no-cache --virtual subconverter-deps pcre2 libcurl yaml-cpp && \
    apk del .build-deps

## build final image
#FROM alpine:latest
#LABEL maintainer="firefly.lzh@gmail.com"
#
#RUN apk add --no-cache --virtual subconverter-deps pcre2 libcurl yaml-cpp
#
#COPY --from=builder /subconverter/subconverter /usr/bin/
#COPY --from=builder /subconverter/base /base/
#ENV TZ=Africa/Abidjan
#RUN ln -sf /usr/share/zoneinfo/$TZ /etc/localtime
#RUN echo $TZ > /etc/timezone

# set entry
WORKDIR /base
CMD subconverter

EXPOSE 25500/tcp
