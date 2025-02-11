cmake_minimum_required(VERSION 3.31)
project(FirewallSharedObject)

set(CMAKE_CXX_STANDARD 20)

add_library(FirewallSharedObject SHARED
        src/fwso-main.cpp
        src/fwso-main.hpp
        src/utils.cpp
        src/structs/fw-message.cpp
)

find_package(PkgConfig REQUIRED)
pkg_check_modules(KEYUTILS REQUIRED keyutils)
find_package(OpenSSL REQUIRED)

# Include directories
target_include_directories(FirewallSharedObject PRIVATE ${KEYUTILS_INCLUDE_DIRS})

# Link against keyutils and OpenSSL
target_link_libraries(FirewallSharedObject PRIVATE ${KEYUTILS_LIBRARIES} OpenSSL::Crypto)
