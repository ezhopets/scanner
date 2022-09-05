cmake_minimum_required(VERSION 3.5...3.20)

project(scan_util LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)

add_executable(scan_util main.cpp)

target_link_libraries(scan_util scan_util_lib)

add_subdirectory(my_scan_util)
