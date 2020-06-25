cmake_minimum_required(VERSION 3.10)
project(server)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(backend)
include_directories(comm)
include_directories(dedup)
include_directories(keymanager)
include_directories(utils)
include_directories(lib/leveldb/include)

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

add_executable(server
        backend/BackendStorer.cc backend/BackendStorer.hh
        comm/server.cc comm/server.hh
        dedup/dataStruct.hh
        dedup/DedupCore.cc dedup/DedupCore.hh
        dedup/minDedupCore.cc dedup/minDedupCore.hh
        utils/CryptoPrimitive.cc utils/CryptoPrimitive.hh
        utils/Logger.cc utils/Logger.hh
        main.cc)

set_target_properties(server
        PROPERTIES
        ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
        )

link_directories(lib/leveldb)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    # Release mode: Disable AdressSanitizer since Asan affects performance significantly
    message(STATUS "${BoldCyan}Use Release mode${ColourReset}")
    add_compile_options(-O3)
    target_link_libraries(server -lssl -lcrypto -lpthread)
    target_link_libraries(server ${CMAKE_SOURCE_DIR}/lib/leveldb/libleveldb.a -lsnappy)
elseif (CMAKE_BUILD_TYPE STREQUAL "Debug")
    # Debug mode: Enable AdressSanitizer
    message("${BoldCyan}\n[Info] You are under debugging mode!! Performance may drop hugely.\n\n${ColourReset}")
    add_compile_options(
            -ggdb3
            -fsanitize=address
    )
    target_link_libraries(server -lssl -lcrypto -lpthread -fsanitize=address)
    target_link_libraries(server ${CMAKE_SOURCE_DIR}/lib/leveldb/libleveldb.a -lsnappy -fsanitize=address)
endif ()
