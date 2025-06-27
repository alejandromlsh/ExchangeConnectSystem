cmake_minimum_required(VERSION 3.16)
project(pcap_simba_decoder VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

# HFT optimization flags
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -DNDEBUG -flto -ffast-math")
set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g -DDEBUG")

# Include directories
include_directories(include)

# Task 1: Original PCAP Parser
# add_executable(pcap_parser 
#     src/main.cpp
# )
# target_compile_options(pcap_parser PRIVATE -O3 -march=native -DNDEBUG -flto)

# Task 1+2+3: Complete SIMBA pipeline (integrated)
add_executable(pcap_pipeline 
    src/main_pipeline.cpp
)
target_compile_options(pcap_pipeline PRIVATE -O3 -march=native -DNDEBUG -flto -ffast-math)
target_link_libraries(pcap_pipeline PRIVATE Threads::Threads)

# Debug version
add_executable(pcap_pipeline_debug 
    src/main_pipeline.cpp
)
target_compile_options(pcap_pipeline_debug PRIVATE -O0 -g -DDEBUG)
target_link_libraries(pcap_pipeline_debug PRIVATE Threads::Threads)

# Set default build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()
