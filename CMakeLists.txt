cmake_minimum_required(VERSION 3.12)
project(certutils VERSION 0.0.1)

message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")

option(UNITTEST "Builds unit tests" OFF)
message(STATUS "Building Unit Tests: ${UNITTEST}")

option(COVERAGE "Enables source code coverage" OFF)
message(STATUS "Test coverage: ${COVERAGE}")

option(DOXYGEN "Generates Doxygen documentation" OFF)
message(STATUS "Doxygen: ${DOXYGEN}")

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include_directories(include)
add_subdirectory(src)

if(COVERAGE)
    include(Coverage)
endif()

if(UNITTEST)
    enable_testing()
    add_subdirectory(test)
endif()

if(DOXYGEN)
    include(Doxygen)
endif()
