project(${NETWORK_LIB_NAME})

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

set(Boost_USE_STATIC_LIBS     ON)
set(Boost_USE_DEBUG_LIBS     OFF)
set(Boost_USE_RELEASE_LIBS    ON)
set(Boost_USE_MULTITHREADED   ON)
set(Boost_USE_STATIC_RUNTIME  ON)

find_package(Boost 1.88.0 REQUIRED COMPONENTS system)

set(OPENSSL_USE_STATIC_LIBS TRUE)

find_package(OpenSSL 3.5.5 REQUIRED)

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/datatypes/src/iobytes.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/src/HandshakeManager.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/src/HandshakeMessages.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/src/KeySchedule.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/src/TLSRecordLayer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/RSACrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/AESCrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/src/ECDHECrypto.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/datatypes/include/iobytes.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/include/Utils.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/include/UtilsNetwork.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/utils/include/UtilsCrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/include/HandshakeManager.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/include/HandshakeMessages.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/include/KeySchedule.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/network/include/TLSRecordLayer.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/RSACrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/AESCrypto.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/ECDHECrypto.h"
)

add_library(${PROJECT_NAME} STATIC
    ${SOURCES}
    ${HEADERS}
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/datatypes/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/utils/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/crypto/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/network/include"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        Boost::thread
        Boost::json
        Boost::url
        Boost::system
        OpenSSL::SSL
        OpenSSL::Crypto
)

enable_options(${PROJECT_NAME})

# Windows networking requires winsock library when using Boost.Asio
if (WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC ws2_32)
endif()
