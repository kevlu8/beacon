cmake_minimum_required(VERSION 3.10)

# Project name
project(beacon)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Source files
set(SOURCES
    src/main.cpp
    src/random.cpp
)

# Add executable
add_executable(beacon ${SOURCES})

# Link libraries
target_link_libraries(beacon gmp gmpxx)
