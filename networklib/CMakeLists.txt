project(${NETWORK_LIB_NAME})

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(Boost_USE_STATIC_LIBS     ON)
set(Boost_USE_DEBUG_LIBS     OFF)
set(Boost_USE_RELEASE_LIBS    ON)
set(Boost_USE_MULTITHREADED   ON)
set(Boost_USE_STATIC_RUNTIME  ON)

find_package(Boost 1.87.0 REQUIRED CONFIG COMPONENTS headers)

if(USE_CONAN)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    find_package(OpenSSL 3.5.5 REQUIRED CONFIG)
else()
    if(WIN32)
        set(OPENSSL_USE_STATIC_LIBS FALSE)
    else()
        set(OPENSSL_USE_STATIC_LIBS TRUE)
    endif()
        find_package(OpenSSL 3.5.5 REQUIRED)
endif()

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/utils/types.cpp" 
    "${CMAKE_CURRENT_SOURCE_DIR}/src/network/handshakemanager.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/network/handshakemessages.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/network/keyschedule.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/network/tlsrecordlayer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/rsacrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/aescrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/crypto/ecdhecrypto.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/utils/types.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/utils/functions.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/network/handshakemanager.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/network/handshakemessages.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/network/keyschedule.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/network/tlsrecordlayer.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/crypto/rsacrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/crypto/aescrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/include/crypto/ecdhecrypto.h"
)

add_library(${PROJECT_NAME} STATIC
    ${SOURCES}
    ${HEADERS}
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        Boost::headers
        OpenSSL::SSL
        OpenSSL::Crypto
)

target_compile_definitions(${PROJECT_NAME} PUBLIC BOOST_ERROR_CODE_HEADER_ONLY)

enable_options(${PROJECT_NAME})

# Windows networking requires winsock library when using Boost.Asio
if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC ws2_32)
endif()
