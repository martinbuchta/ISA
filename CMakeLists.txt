cmake_minimum_required(VERSION 3.7)
project(d6r)

set(CMAKE_CXX_STANDARD 11)

include(FindPCAP.cmake)

set(SOURCE_FILES main.cc)
find_package (Threads)
add_executable(d6r ${SOURCE_FILES})
target_link_libraries(d6r ${PCAP_LIBRARY} ${CMAKE_THREAD_LIBS_INIT})