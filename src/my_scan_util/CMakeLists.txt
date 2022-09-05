cmake_minimum_required(VERSION 3.5...3.20)


find_package(Boost 1.74 COMPONENTS filesystem REQUIRED)
include_directories(${Boost_INCLUDE_DIR})

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

add_library(scan_util_lib scan_util.cpp)

target_link_libraries(scan_util_lib LINK_PUBLIC ${Boost_LIBRARIES} Threads::Threads)
