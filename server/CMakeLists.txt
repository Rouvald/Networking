project(${SERVER_NAME})

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/tlsserver.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/tlsserver.h"
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/mainserver.cpp"
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        ${NETWORK_LIB_NAME}
)

enable_options(${PROJECT_NAME})
