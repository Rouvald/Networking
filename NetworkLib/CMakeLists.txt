project(networklib)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(Boost_USE_STATIC_LIBS ON)
#[[set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_USE_MULTITHREADED ON)]]

find_package(Boost 1.87.0 REQUIRED COMPONENTS thread json url)

set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(OpenSSL 3.0.0 REQUIRED) # 3.2.0

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/manager.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/manager.h"
)

add_library(${PROJECT_NAME} INTERFACE
    ${SOURCES}
    ${HEADERS}
)

target_include_directories(${PROJECT_NAME} INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(${PROJECT_NAME} INTERFACE
        Boost::system
        Boost::thread
        Boost::json
        Boost::url
        OpenSSL::SSL
        OpenSSL::Crypto
)