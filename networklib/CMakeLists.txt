project(${NETWORK_LIB_NAME})

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
    "${CMAKE_CURRENT_SOURCE_DIR}/tls/src/HandshakeContext.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/tls/src/SessionCipher.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/src/manager.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/RSACustom.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/AESCustom.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/RSACrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/AESCrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/ECDHECrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/SHA256Custom.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/tls/include/HandshakeContext.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/tls/include/SessionCipher.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/include/manager.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/RSAPublicKey.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/RSACustom.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/AESCustom.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/RSACrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/AESCrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/ECDHECrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/SHA256Custom.h"
)

add_library(${PROJECT_NAME} STATIC
    ${SOURCES}
    ${HEADERS}
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/network/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/tls/include"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        Boost::thread
        Boost::json
        Boost::url
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
)