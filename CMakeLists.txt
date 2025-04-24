cmake_minimum_required(VERSION 3.28)


project(networking)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++23 -Wall -Wextra -Wpedantic -fpermissive -fPIC -fmax-errors=5 ") # -pthread

set(CMAKE_CXX_FLAGS_RELEASE "-O3 ${CMAKE_CXX_FLAGS}")

set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_EXE_LINKER_FLAGS "-static -static-libgcc -static-libstdc++")

set(NETWORK_LIB_NAME "networklib")
add_subdirectory(NetworkLib)

add_executable(${PROJECT_NAME} main.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/NetworkLib/include
)

target_link_libraries(${PROJECT_NAME} PUBLIC
    ${NETWORK_LIB_NAME}
)
