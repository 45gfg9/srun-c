# Copyright © 2023-2025 45gfg9 <45gfg9@45gfg9.net>
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See the LICENSE file for more details.

cmake_minimum_required(VERSION 3.20)
project(srun C)
project(srun VERSION 0.13)

option(SRUN_MBEDTLS "Use MbedTLS instead of OpenSSL" OFF)

# uncomment these lines to provide default values
# WARNING: password is stored in plain-text and can be dumped easily using `strings`
#set(SRUN_CONF_AUTH_URL "https://example.com")
#set(SRUN_CONF_DEFAULT_USERNAME "TanikazeAmane")
#set(SRUN_CONF_DEFAULT_PASSWORD "p4ssw@rd")
#set(SRUN_CONF_DEFAULT_AC_ID 12)
#set(SRUN_CONF_DEFAULT_CERTFILE "example-cert.pem")
#set(SRUN_CONF_DEFAULT_CLIENT_IP "0.0.0.0")

set(CMAKE_C_STANDARD 11)
add_executable(${PROJECT_NAME} srun.c main.c)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined -fstack-protector-all -fno-omit-frame-pointer -ggdb")
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

if (SRUN_CONF_DEFAULT_CERTFILE)
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${SRUN_CONF_DEFAULT_CERTFILE}" SRUN_CONF_DEFAULT_CERT)
    string(REPLACE "\n" "\\n" SRUN_CONF_DEFAULT_CERT "${SRUN_CONF_DEFAULT_CERT}")
endif ()

if (NOT SRUN_CONF_DEFAULT_USERNAME AND SRUN_CONF_DEFAULT_PASSWORD)
    message(WARNING "Cannot set password without username")
    unset(SRUN_CONF_DEFAULT_PASSWORD)
endif ()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h.in" "${CMAKE_CURRENT_SOURCE_DIR}/srun_config.h")

# libbsd
if (NOT (APPLE OR BSD))
    if (SRUN_NO_LIBBSD OR (DEFINED ENV{SRUN_NO_LIBBSD} AND ENV{SRUN_NO_LIBBSD}))
        message(WARNING "libbsd is disabled, readpassphrase will not work")
        target_compile_definitions(${PROJECT_NAME} PRIVATE SRUN_NO_LIBBSD)
    else ()
        find_library(LIBBSD_LIB NAMES bsd libbsd REQUIRED)
        find_path(LIBBSD_INCLUDE_DIRS bsd/readpassphrase.h REQUIRED)
        message(STATUS "Found libbsd: ${LIBBSD_LIB}")
        target_include_directories(${PROJECT_NAME} PRIVATE ${LIBBSD_INCLUDE_DIRS})
        target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBBSD_LIB})
    endif ()
endif ()

find_package(CURL REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE CURL::libcurl)
target_sources(${PROJECT_NAME} PRIVATE platform/libcurl.c)

find_package(cJSON REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${CJSON_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${CJSON_LIBRARIES})
target_sources(${PROJECT_NAME} PRIVATE platform/cjson.c)

find_library(MbedCrypto_LIB NAMES mbedcrypto)
find_path(MbedCrypto_INCLUDE_DIR mbedtls/md.h)
find_package(OpenSSL COMPONENTS Crypto)
if (SRUN_MBEDTLS AND MbedCrypto_LIB AND MbedCrypto_INCLUDE_DIR)
    message(STATUS "Found MbedTLS: ${MbedCrypto_LIB}")
    target_include_directories(${PROJECT_NAME} PRIVATE ${MbedCrypto_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${MbedCrypto_LIB})
    target_sources(${PROJECT_NAME} PRIVATE platform/mbedtls.c)
else ()
    if (NOT OpenSSL_FOUND)
        message(FATAL_ERROR "OpenSSL or MbedTLS is required")
    elseif (SRUN_MBEDTLS)
        message(WARNING "MbedTLS is requested but not found, using OpenSSL instead")
    endif ()
    message(STATUS "Found OpenSSL: ${OPENSSL_INCLUDE_DIR}")
    target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)
    target_sources(${PROJECT_NAME} PRIVATE platform/openssl.c)
endif ()
