cmake_minimum_required(VERSION 3.16)
project(lmd C)

set(CMAKE_C_STANDARD 11)
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DDEBUG_ON -ggdb)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build.${CMAKE_BUILD_TYPE}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build.${CMAKE_BUILD_TYPE}")
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/build.${CMAKE_BUILD_TYPE}")

include_directories(src)

add_executable(lmd
    src/cor_array.c
    src/cor_array.h
    src/cor_buf.c
    src/cor_buf.h
    src/cor_core.h
    src/cor_http.c
    src/cor_http.h
    src/cor_list.c
    src/cor_list.h
    src/cor_log.c
    src/cor_log.h
    src/cor_pool.c
    src/cor_pool.h
    src/cor_str.c
    src/cor_str.h
    src/lmd.c
    src/lmd.h
    src/lmd_db.c
    src/lmd_db.h)

target_link_libraries(lmd
    ev)