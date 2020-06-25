cmake_minimum_required(VERSION 3.10)
project(client)

set(CMAKE_CXX_STANDARD 14)

include_directories(chunking)
include_directories(coding)
include_directories(comm)
include_directories(lib)
include_directories(utils)

# colorful output
if (NOT WIN32)
    string(ASCII 27 Esc)
    set(BoldYellow "${Esc}[1;33m")
    set(ColourReset "${Esc}[m")
    set(BoldCyan "${Esc}[1;36m")
endif ()

# set compile mode default to Release
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "${BoldYellow}No build type selected, default to <Release>${ColourReset}")
    set(CMAKE_BUILD_TYPE "Release")
endif ()

# Misc default
set(CMAKE_CXX_FLAGS "-fno-operator-names")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(client
        chunking/chunker.cc chunking/chunker.hh
        coding/CDCodec.cc coding/CDCodec.hh
        coding/decoder.cc coding/decoder.hh
        coding/encoder.cc coding/encoder.hh
        comm/downloader.cc comm/downloader.hh
        comm/uploader.cc comm/uploader.hh
        keyClient/exchange.cc keyClient/exchange.hh
        utils/conf.hh
        utils/CryptoPrimitive.cc utils/CryptoPrimitive.hh
        utils/DataStruct.hh
        utils/Logger.cc utils/Logger.hh
        utils/MessageQueue.hh
        utils/socket.cc utils/socket.hh
        utils/ssl.cc utils/ssl.hh
        main.cc)

set_target_properties(client
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )

if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "Optimizing")
    # Release mode: Disable AdressSanitizer since Asan affects performance significantly
    if (CMAKE_BUILD_TYPE STREQUAL "Release")
        message(STATUS "${BoldCyan}Use Release mode${ColourReset}")
        add_compile_options(-O3)
    elseif (CMAKE_BUILD_TYPE STREQUAL "Optimizing")
        # Enable -ggdb3 for profiling like VTune
        add_compile_options(-O3 -ggdb3)
        message(STATUS "${BoldCyan}Use Normal mode${ColourReset}")
    endif ()
    target_link_libraries(client -lssl -lcrypto -lpthread)
    target_link_libraries(client libgf_complete.a)
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Debug mode: Enable AdressSanitizer
    message("${BoldCyan}\n[Info] You are under debugging mode!! Performance may drop hugely.\n\n${ColourReset}")
    add_compile_options(
            -ggdb3
            -fsanitize=address
    )

    target_link_libraries(client -lssl -lcrypto -lpthread -fsanitize=address)
    target_link_libraries(client libgf_complete.a -fsanitize=address)
endif ()
