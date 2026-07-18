CMAKE_MINIMUM_REQUIRED(VERSION 3.10)
CMAKE_POLICY(SET CMP0074 NEW)
PROJECT(subconverter LANGUAGES CXX)
SET(BUILD_TARGET_NAME ${PROJECT_NAME})
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/include/")

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
ENDIF()
SET(CMAKE_CXX_STANDARD 20)

IF(NOT MSVC)
    ADD_COMPILE_OPTIONS(-Wall -Wextra -Wno-unused-parameter -Wno-unused-result -Wno-shadow -Wno-deprecated-declarations -Wno-deprecated-copy)
    IF(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        # -Wno-unknown-warning-option silences errors for Clang-specific flags not supported by older Clang versions
        ADD_COMPILE_OPTIONS(-Wno-unknown-warning-option -Wno-cast-function-type-mismatch -Wno-deprecated-literal-operator -Wno-nontrivial-memcall)
    ENDIF()
ELSE()
    ADD_COMPILE_OPTIONS(/W4)
ENDIF()

#remove std::regex support since it is not compatible with group modifiers and slow
#OPTION(USING_STD_REGEX "Use std::regex from C++ library instead of PCRE2." OFF)
OPTION(USING_MALLOC_TRIM "Call malloc_trim after processing request to lower memory usage (Your system must support malloc_trim)." OFF)
#now using internal MD5 calculation
#OPTION(USING_MBEDTLS "Use mbedTLS instead of OpenSSL for MD5 calculation." OFF)
OPTION(BUILD_STATIC_LIBRARY "Build a static library containing only the essential part." OFF)
OPTION(FORCE_STATIC_DEPS "Prefer linking static libraries for third-party dependencies." ON)

# Prefer static archives when FORCE_STATIC_DEPS is ON
IF(FORCE_STATIC_DEPS)
    SET(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    MESSAGE(STATUS "Preferring static archives (.a)")
ENDIF()

# On MinGW, statically link C/C++ runtime
IF(MINGW)
    ADD_LINK_OPTIONS(-static-libgcc -static-libstdc++)
ENDIF()

INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES(
"
#include<string>
int main(){std::to_string(0);}
" HAVE_TO_STRING)

IF(NOT BUILD_STATIC_LIBRARY)

ADD_EXECUTABLE(${BUILD_TARGET_NAME}
    src/generator/config/nodemanip.cpp
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/handler/interfaces.cpp
    src/handler/multithread.cpp
    src/handler/upload.cpp
    src/handler/webget.cpp
    src/handler/settings.cpp
    src/main.cpp
    src/parser/infoparser.cpp
    src/parser/subparser.cpp
    src/script/cron.cpp
    src/script/script_quickjs.cpp
#    src/server/webserver_libevent.cpp
    src/server/webserver_httplib.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/file.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/regexp.cpp
    src/utils/string.cpp
    src/utils/system.cpp
    src/utils/urlencode.cpp
    src/utils/age_decrypt.cpp)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE src)
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

FIND_PACKAGE(PkgConfig REQUIRED)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})

#PKG_CHECK_MODULES(LIBEVENT libevent>=2.1.10 REQUIRED)
#FIND_PATH(LIBEVENT_INCLUDE_DIR NAMES event.h PATHS ${LIBEVENT_INCLUDE_DIRS})
#FIND_LIBRARY(LIBEVENT_LIBRARY NAMES event PATHS ${LIBEVENT_LIBRARY_DIRS})
#TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${LIBEVENT_LIBRARY_DIRS})
#TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${LIBEVENT_INCLUDE_DIR})
#TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${LIBEVENT_LIBRARY})

# When using static deps, find static libcurl manually
IF(FORCE_STATIC_DEPS)
    FIND_PACKAGE(CURL 7.54.0 REQUIRED)
    TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CURL_INCLUDE_DIRS})
    # CURL_LIBRARY (singular) is not set by CURLConfig.cmake; use CURL_STATIC_LIB which holds the path to libcurl.a
    IF(NOT CURL_LIBRARY AND CURL_STATIC_LIB)
        SET(CURL_LIBRARY "${CURL_STATIC_LIB}")
    ENDIF()
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${CURL_LIBRARY})
    MESSAGE(STATUS "Forcing static libcurl: ${CURL_LIBRARY}")
ELSE()
    FIND_PACKAGE(CURL 7.54.0 REQUIRED)
    TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CURL_LIBRARY_DIRS})
    TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CURL_INCLUDE_DIRS})
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} CURL::libcurl)
ENDIF()
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DCURL_STATICLIB)

# Extra static dependency linking for libcurl under MinGW
IF(FORCE_STATIC_DEPS AND MINGW)
    # Derive MinGW prefix from the static curl library already found
    GET_FILENAME_COMPONENT(_MINGW_PREFIX "${CURL_LIBRARY}" DIRECTORY)
    GET_FILENAME_COMPONENT(_MINGW_PREFIX "${_MINGW_PREFIX}" DIRECTORY)
    MESSAGE(STATUS "Using MinGW prefix for static deps: ${_MINGW_PREFIX}")
    # Common static dependency libraries for libcurl
    # They may not all be present depending on build configuration; link those that exist.
    SET(_STATIC_DEPS
        ngtcp2_crypto_ossl
        nghttp3
        ngtcp2
        nghttp2
        brotlidec
        brotlienc
        brotlicommon
        zstd
        psl
        idn2
        unistring
        iconv
        ssh2
        ldap
        lber
        z
        ssl
        crypto)
    FOREACH(_dep ${_STATIC_DEPS})
        SET(_static_path "${_MINGW_PREFIX}/lib/lib${_dep}.a")
        IF(EXISTS "${_static_path}")
            TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} "${_static_path}")
            MESSAGE(STATUS "Link static lib: ${_static_path}")
        ELSE()
            MESSAGE(WARNING "Static lib not found (skipping): ${_static_path}")
        ENDIF()
    ENDFOREACH()
    # Ensure Windows libraries for networking, crypto, LDAP, and bcrypt
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ws2_32 crypt32 wldap32 bcrypt secur32 iphlpapi)
ENDIF()

# Static curl transitive dependencies on Linux/macOS
IF(FORCE_STATIC_DEPS AND NOT MINGW AND NOT WIN32)
    SET(_CURL_TRANSITIVE_DEPS nghttp2 cares psl brotlidec brotlicommon zstd z idn2 unistring)
    FOREACH(_dep ${_CURL_TRANSITIVE_DEPS})
        FIND_LIBRARY(_CURL_DEP_${_dep} NAMES ${_dep})
        IF(_CURL_DEP_${_dep})
            TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${_CURL_DEP_${_dep}})
            MESSAGE(STATUS "Link static curl dependency: ${_CURL_DEP_${_dep}}")
        ELSE()
            MESSAGE(WARNING "Static curl dependency not found (skipping): ${_dep}")
        ENDIF()
    ENDFOREACH()
ENDIF()

FIND_PACKAGE(Rapidjson REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

FIND_PACKAGE(toml11 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${TOML11_INCLUDE_DIRS})

PKG_CHECK_MODULES(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
FIND_LIBRARY(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${YAML_CPP_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DYAML_CPP_STATIC_DEFINE)

# CMAKE_FIND_LIBRARY_SUFFIXES is already set to prefer .a when FORCE_STATIC_DEPS is ON
FIND_PACKAGE(PCRE2 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${PCRE2_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DPCRE2_STATIC)

FIND_PACKAGE(QuickJS REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${QUICKJS_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${QUICKJS_LIBRARIES})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DJS_SetHostUnhandledPromiseRejectionTracker=JS_SetHostPromiseRejectionTracker)

FIND_PACKAGE(LibCron REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${LIBCRON_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${LIBCRON_LIBRARIES})

FIND_PACKAGE(OpenSSL REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} OpenSSL::SSL OpenSSL::Crypto)

IF(WIN32)
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} wsock32 ws2_32)
ELSE()
    INCLUDE(GNUInstallDirs)
    INSTALL(TARGETS ${BUILD_TARGET_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME})
    INSTALL(DIRECTORY base/ DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME} FILES_MATCHING PATTERN "*")
ENDIF()

ELSE() #BUILD_STATIC_LIBRARY

ADD_LIBRARY(${BUILD_TARGET_NAME} STATIC
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/lib/wrapper.cpp
    src/parser/subparser.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/regexp.cpp
    src/utils/string.cpp
    src/utils/urlencode.cpp)
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DNO_JS_RUNTIME -DNO_WEBGET)

TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PUBLIC src)

FIND_PACKAGE(Rapidjson REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

FIND_PACKAGE(PkgConfig REQUIRED)

PKG_CHECK_MODULES(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
FIND_LIBRARY(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DYAML_CPP_STATIC_DEFINE)

FIND_PACKAGE(PCRE2 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DPCRE2_STATIC)

IF(WIN32)
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ws2_32)
ENDIF()

ENDIF() #BUILD_STATIC_LIBRARY

IF(HAVE_TO_STRING)
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DHAVE_TO_STRING)
ENDIF()

IF(USING_MALLOC_TRIM)
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE -DMALLOC_TRIM)
ENDIF()
