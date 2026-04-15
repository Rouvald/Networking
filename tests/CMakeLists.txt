project(networking_test LANGUAGES CXX)

find_package(GTest REQUIRED)
include(GoogleTest)

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_UtilsNetwork.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_UtilsCrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_Utils.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_RSACrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_AESCrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_ECDHECrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_TLSRecordLayer.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_Types.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_HandshakeMessages.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_KeySchedule.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_HandshakeManager.cpp"
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main_test.cpp"
)

target_include_directories(${PROJECT_NAME} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${NETWORK_LIB_NAME}
    GTest::gtest
)

if(MINGW)
    # Conan's prebuilt GTest and MinGW CRT both provide _stat64i32 on Windows.
    target_link_options(${PROJECT_NAME} PRIVATE -Wl,--allow-multiple-definition)
endif()

enable_options(${PROJECT_NAME})
gtest_discover_tests(${PROJECT_NAME})
