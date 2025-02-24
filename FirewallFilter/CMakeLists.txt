cmake_minimum_required(VERSION 3.31)
project(FirewallFilter)

set(CMAKE_CXX_STANDARD 20)

# Define the source directory
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)

# Recursively find all source files
file(GLOB_RECURSE SOURCES "${SRC_DIR}/*.cpp")

# Add include directories
include_directories(${SRC_DIR})

# Create the executable
add_executable(FirewallFilter main.cpp ${SOURCES} # Link system libraries
)

# Link system libraries
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(FirewallFilter ${LINUX_LIBS})
endif()
