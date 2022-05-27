project(openssl-cmake)

cmake_minimum_required(VERSION 3.19)

set(OPENSSL_VERSION "1.1.1k")
set(OPENSSL_ARCHIVE_SHA256 "892a0875b9872acd04a9fde79b1f943075d5ea162415de3047c327df33fbaee5")
set(install_prefix "${CMAKE_CURRENT_BINARY_DIR}/local")

set(THIRDPARTY_OPENSSL_PREFIX ${install_prefix} PARENT_SCOPE)
set(HAS_THIRDPARTY_OPENSSL ON PARENT_SCOPE)

include(ExternalProject)

option(enable_sslv2 "enable sslv2 feature" OFF)
option(enable_sslv3 "enable sslv3 feature" ON)

if (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
    set(TARGET_PROCESSOR "x86_64")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(TARGET_PROCESSOR "x86_64")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    set(TARGET_PROCESSOR "aarch64")
elseif (CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(TARGET_PROCESSOR "arm64")
else()
    message(FATAL_ERROR "Unsupported architecture ${CMAKE_HOST_SYSTEM_PROCESSOR}, system processeor: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

function(opensslMain)
    set(common_options
        no-asm
        no-shared
        no-weak-ssl-ciphers
        no-comp
        enable-cms
        )

    if (enable_sslv2)
        message(STATUS "openssl enable sslv2.")
        list(APPEND common_options enable-ssl2)
    else()
        message(STATUS "openssl disable sslv2.")
        list(APPEND common_options no-ssl2)
    endif()

    if (enable_sslv3)
        message(STATUS "openssl enable sslv3.")
        list(APPEND common_options enable-ssl3 enable-ssl3-method)
    else()
        message(STATUS "openssl disable sslv3.")
        list(APPEND common_options no-ssl3)
    endif()

    add_library(thirdparty_openssl_ssl STATIC IMPORTED GLOBAL)
    add_library(thirdparty_openssl_crypto STATIC IMPORTED GLOBAL)

    if("${CMAKE_GENERATOR}" STREQUAL "Unix Makefiles")
        set(make_command "$(MAKE)")
    else()
        set(make_command "make")
    endif()

    if("${CMAKE_SYSTEM_NAME}" STREQUAL "Linux")
        set(configure_command
            "${CMAKE_COMMAND}" -E env "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}"
            perl ./Configure linux-${TARGET_PROCESSOR}
            ${common_options}
            ${FORMULA_CFLAGS}

            "--prefix=${install_prefix}"
            "--openssldir=${install_prefix}/etc/openssl"

            -fPIC
            --sysroot=${CMAKE_SYSROOT}
            -lunwind
            -lpthread
            )

        set(build_command
            "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/etc/openssl" &&
            ${make_command} depend &&
            ${make_command}
            )

        set(install_command
            ${make_command} install_sw install_ssldirs
            )

        set(openssl_libs
            "${install_prefix}/lib/libssl.a"
            "${install_prefix}/lib/libcrypto.a"
            )

        set_target_properties(thirdparty_openssl_ssl PROPERTIES IMPORTED_LOCATION
            "${install_prefix}/lib/libssl.a"
            )
        set_target_properties(thirdparty_openssl_crypto PROPERTIES IMPORTED_LOCATION
            "${install_prefix}/lib/libcrypto.a"
            )

    elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Darwin")
        set(platform_c_flags
            -fPIC
            )

        if(NOT "${CMAKE_OSX_DEPLOYMENT_TARGET}" STREQUAL "")
            list(APPEND platform_c_flags
                -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}
                )
        endif()
        if (${TARGET_PROCESSOR} STREQUAL "x86_64")
            set(platform darwin64-x86_64-cc)
        else()
            set(platform darwin64-arm64-cc)
        endif()
        set(configure_command
            "${CMAKE_COMMAND}" -E env "CC=${CMAKE_C_COMPILER}" "AR=${CMAKE_AR}"
            perl ./Configure ${platform}
            ${common_options}
            ${FORMULA_CFLAGS}

            "--prefix=${install_prefix}"
            "--openssldir=${install_prefix}/etc/openssl"

            enable-ec_nistp_64_gcc_128
            ${platform_c_flags}
            )

        # Don't be afraid to manually patch the build scripts; for some settings, there is no
        # other way.
        # see https://wiki.openssl.org/index.php/Compilation_and_Installation#Modifying_Build_Settings
        set(build_command
            /usr/bin/sed -i ".bak" "s+^CFLAGS=+CFLAGS=-isysroot ${CMAKE_OSX_SYSROOT} +g" "Makefile" &&
            "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/etc/openssl" &&
            ${make_command} depend &&
            ${make_command}
            )

        set(install_command
            ${make_command} install_sw install_ssldirs
            )

        set(openssl_libs
            "${install_prefix}/lib/libssl.a"
            "${install_prefix}/lib/libcrypto.a"
            )

        set_target_properties(thirdparty_openssl_ssl PROPERTIES IMPORTED_LOCATION
            "${install_prefix}/lib/libssl.a"
            )
        set_target_properties(thirdparty_openssl_crypto PROPERTIES IMPORTED_LOCATION
            "${install_prefix}/lib/libcrypto.a"
            )

    elseif("${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
        set(CMAKE_PREFIX_PATH "C:\\Strawberry\\perl\\bin")
        find_package(Perl REQUIRED)

        set(configure_command
            "${CMAKE_COMMAND}" -E env
            "${PERL_EXECUTABLE}" Configure VC-WIN64A
            ${common_options}
            )

        get_filename_component(perl_bin_path "${PERL_EXECUTABLE}" DIRECTORY)

        string(REPLACE "/" "\\\\" perl_executable_path "${PERL_EXECUTABLE}")

        set(build_command
            "${CMAKE_COMMAND}" -E env "cmd.exe" "/C" "nmake PERL=${perl_executable_path}"
            )

        set(install_command
            "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/lib" &&
            "${CMAKE_COMMAND}" -E copy "./libssl.lib" "${install_prefix}/lib" &&
            "${CMAKE_COMMAND}" -E copy "./libcrypto.lib" "${install_prefix}/lib" &&
            "${CMAKE_COMMAND}" -E make_directory "${install_prefix}/include" &&
            "${CMAKE_COMMAND}" -E copy_directory "./include/openssl" "${install_prefix}/include/openssl" &&
            "${CMAKE_COMMAND}" -E remove "${install_prefix}/include/openssl/__DECC_INCLUDE_PROLOGUE.h"
            "${install_prefix}/include/openssl/__DECC_INCLUDE_EPILOGUE.h"
            "${install_prefix}/include/openssl/opensslconf.h.in"
            )

        set(openssl_libs
            "${install_prefix}/lib/libssl.lib"
            "${install_prefix}/lib/libcrypto.lib"
            )

        set_target_properties(thirdparty_openssl_ssl PROPERTIES IMPORTED_LOCATION
            "${install_prefix}/lib/libssl.lib"
            )
        set_target_properties(thirdparty_openssl_crypto PROPERTIES IMPORTED_LOCATION
            "${install_prefix}/lib/libcrypto.lib"
            )

    else()
        message(FATAL_ERROR "Unsupported system")
    endif()

    list(APPEND openssl_c_flags ${FORMULA_CFLAGS})
    string(REPLACE ";" " " openssl_c_flags "${openssl_c_flags}")

    string(REGEX MATCH "[0-9]\\.[0-9]\\.[0-9]" OPENSSL_VERSION_NO_PATCH "${OPENSSL_VERSION}")
    message(STATUS "openssl version: ${OPENSSL_VERSION_NO_PATCH}")
    set(openssl_urls
        "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
        "https://www.openssl.org/source/old/${OPENSSL_VERSION_NO_PATCH}/openssl-${OPENSSL_VERSION}.tar.gz"
        )

    ExternalProject_Add(openssl
        URL "${openssl_urls}"
        URL_HASH SHA256=${OPENSSL_ARCHIVE_SHA256}
        CONFIGURE_COMMAND ${configure_command}
        BUILD_COMMAND ${build_command}
        INSTALL_COMMAND ""
        BUILD_IN_SOURCE true
        EXCLUDE_FROM_ALL true
        )

    ExternalProject_Get_property(openssl SOURCE_DIR)

    ExternalProject_Add_Step(openssl custom_install
        COMMAND ${install_command}
        DEPENDEES build
        BYPRODUCTS ${openssl_libs}
        WORKING_DIRECTORY "${SOURCE_DIR}"
        )

    add_library(thirdparty_openssl INTERFACE)

    add_dependencies(thirdparty_openssl_ssl openssl)
    add_dependencies(thirdparty_openssl_crypto openssl)
    add_dependencies(thirdparty_openssl thirdparty_openssl_crypto thirdparty_openssl_ssl)

    target_include_directories(thirdparty_openssl INTERFACE "${install_prefix}/include")
    target_link_libraries(thirdparty_openssl INTERFACE
        thirdparty_openssl_ssl
        thirdparty_openssl_crypto
        )
endfunction()

function(easyMain)
    add_library(thirdparty_openssl_easy
        easy/aes.cpp
        easy/base64.cpp
        easy/hash.cpp
        easy/hex.cpp
        easy/rc4.cpp
        )
    target_link_libraries(thirdparty_openssl_easy thirdparty_openssl)
    target_include_directories(thirdparty_openssl_easy INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}")
endfunction()

function(opensslSugar)
    add_executable(sugar-cli sugar/main.cpp)
    target_link_libraries(sugar-cli thirdparty_openssl_easy)
endfunction()

opensslMain()

easyMain()

opensslSugar()
