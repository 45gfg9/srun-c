# Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

cmake_minimum_required(VERSION 3.20)
project(srun C)
project(srun VERSION 0.101.0)

set(SRUN_CRYPTO "openssl" CACHE STRING "The crypto library to use")
string(TOLOWER "${SRUN_CRYPTO}" SRUN_CRYPTO)

set(CMAKE_C_STANDARD 11)
add_executable(${PROJECT_NAME} srun.c main.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -pedantic -fsanitize=address,undefined -fstack-protector-all -fno-omit-frame-pointer -ggdb")
if (LINUX)
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=leak")
endif ()

target_include_directories(${PROJECT_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}"
        "${CMAKE_CURRENT_SOURCE_DIR}/platform"
)

# find current Git revision
find_package(Git)
if (GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --always --tags --dirty
            OUTPUT_VARIABLE SRUN_GIT_HASH
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
endif ()

string(TIMESTAMP SRUN_BUILD_TIME "%Y-%m-%d %H:%M:%S")
set(SRUN_VERSION "${CMAKE_PROJECT_VERSION}")

if (SRUN_CONF_CACERT)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${SRUN_CONF_CACERT}" SRUN_CONF_CERT_PEM)
    string(REPLACE "\n" "\\n" SRUN_CONF_CERT_PEM "${SRUN_CONF_CERT_PEM}")
endif ()

if (NOT SRUN_CONF_USERNAME AND SRUN_CONF_PASSWORD)
    message(WARNING "Cannot set password without username")
    unset(SRUN_CONF_PASSWORD)
endif ()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h.in" "${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h")

# libbsd
if (NOT (APPLE OR BSD))
    find_library(LIBBSD_LIB NAMES bsd libbsd)
    find_path(LIBBSD_INCLUDE_DIRS bsd/readpassphrase.h)
    if (LIBBSD_LIB AND LIBBSD_INCLUDE_DIRS)
        message(STATUS "Found libbsd: ${LIBBSD_LIB}")
        target_include_directories(${PROJECT_NAME} PRIVATE ${LIBBSD_INCLUDE_DIRS})
        target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBBSD_LIB})
    else ()
        message(WARNING "libbsd not found, will use potentially insecure fallback implementation")
    endif ()
endif ()

find_package(CURL REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE CURL::libcurl)
target_sources(${PROJECT_NAME} PRIVATE platform/libcurl.c)

find_package(cJSON REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${CJSON_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CJSON_LIBRARIES})
target_sources(${PROJECT_NAME} PRIVATE platform/cjson.c)

find_library(MbedCrypto_LIB mbedcrypto)
find_path(MbedCrypto_INCLUDE_DIR mbedtls/md.h)
find_package(OpenSSL COMPONENTS Crypto)
if (MbedCrypto_LIB AND MbedCrypto_INCLUDE_DIR AND (NOT OpenSSL_FOUND OR SRUN_CRYPTO STREQUAL "mbedtls"))
    message(STATUS "Found MbedTLS: ${MbedCrypto_LIB}")
    target_include_directories(${PROJECT_NAME} PRIVATE ${MbedCrypto_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${MbedCrypto_LIB})
    target_sources(${PROJECT_NAME} PRIVATE platform/mbedtls.c)
elseif (OpenSSL_FOUND AND NOT (SRUN_CRYPTO STREQUAL "self"))
    if (NOT (SRUN_CRYPTO STREQUAL "openssl"))
        message(WARNING "Could not find specified crypto library: ${SRUN_CRYPTO}. Using OpenSSL instead")
    endif ()
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)
    target_sources(${PROJECT_NAME} PRIVATE platform/openssl.c)
else ()
    IF (NOT (SRUN_CRYPTO STREQUAL "self"))
        message(WARNING "Could not find crypto library: ${SRUN_CRYPTO}")
    endif ()
    message(STATUS "Using self-implemented crypto functions")
    target_sources(${PROJECT_NAME} PRIVATE platform/md.c)
endif ()
