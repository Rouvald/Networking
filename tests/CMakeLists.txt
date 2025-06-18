project(networking_test LANGUAGES CXX)

find_package(benchmark REQUIRED)
find_package(GTest REQUIRED)

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_UtilsNetwork.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_UtilsCrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_Utils.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_RSACrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_AESCrypto.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/test_ECDHECrypto.cpp"
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main_test.cpp"
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${benchmark_INCLUDE_DIRS}"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        ${NETWORK_LIB_NAME}
        benchmark::benchmark
        GTest::gtest
        GTest::gtest_main
)
