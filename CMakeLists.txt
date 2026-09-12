cmake_minimum_required(VERSION 3.16)

project(saboteur C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(AVFORMAT REQUIRED IMPORTED_TARGET libavformat)
pkg_check_modules(AVUTIL REQUIRED IMPORTED_TARGET libavutil)

add_executable(saboteur
    src/main.c
)

target_compile_options(saboteur PRIVATE -Wall -Wextra -Wpedantic)
target_link_libraries(saboteur
    PRIVATE
        PkgConfig::AVFORMAT
        PkgConfig::AVUTIL
        pthread
)
