cmake_minimum_required(VERSION 3.16)
project(pcap_parser VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Optimization flags for production (performance testing)
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG -flto")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -fsanitize=address -DDEBUG")

# Include directories
include_directories(include)

# Main executable (release/performance version)
add_executable(pcap_parser src/main.cpp)
target_compile_options(pcap_parser PRIVATE -O3 -march=native -DNDEBUG -flto)

# Debug executable (with debug output)
add_executable(pcap_parser_debug src/main.cpp)
target_compile_options(pcap_parser_debug PRIVATE -O0 -g -DDEBUG)

# Test executable
add_executable(test_pcap src/test/test_pcap.cpp)

# Installation
install(TARGETS pcap_parser DESTINATION bin)
install(TARGETS pcap_parser_debug DESTINATION bin)
