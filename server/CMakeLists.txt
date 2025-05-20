project(${SERVER_NAME})

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/TLSServer.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/TLSServer.h"
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/main_server.cpp"
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        ${NETWORK_LIB_NAME}
)