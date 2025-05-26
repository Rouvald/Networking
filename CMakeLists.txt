cmake_minimum_required(VERSION 3.28)

# setup conan profiles
set(USE_CONAN "OFF" CACHE BOOL "Turn ON/OFF using Conan for dependency management")

if(USE_CONAN)
    include(${CMAKE_SOURCE_DIR}/devops/cmake/CMakeHelpers.cmake)
    setup_conan_profiles()
endif()

# common settings
set(VERSION_MAJOR 0)
set(VERSION_MINOR 0)
set(VERSION_PATCH 1)
set(PROJECT_VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

project(networking VERSION ${PROJECT_VERSION} LANGUAGES CXX)

# setup base c++ params
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++23 -Wall -Wextra -Wpedantic -fpermissive -fPIC -fmax-errors=5 ") # -pthread
set(CMAKE_CXX_FLAGS_RELEASE "-O3 ${CMAKE_CXX_FLAGS}")

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
# set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc -static-libstdc++ -static")
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc")

# All executable to /bin/ dir
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR}/bin)

# add network lib
set(NETWORK_LIB_NAME "networklib")
add_subdirectory(${NETWORK_LIB_NAME})

# add server
set(SERVER_NAME "server")
add_subdirectory(${SERVER_NAME})

# add client
set(CLIENT_NAME "client")
add_subdirectory(${CLIENT_NAME})

set(NETWORKING_TESTS "OFF" CACHE BOOL "Turn ON/OFF tests building")

if(${NETWORKING_TESTS})
    enable_testing()
    set(NETWORKING_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
    set(NETWORKING_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    add_subdirectory(${NETWORKING_TESTS_DIR})
endif()
