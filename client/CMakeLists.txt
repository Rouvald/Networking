project(${CLIENT_NAME})

set(SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/src/tlsclient.cpp"
)

set(HEADERS
    "${CMAKE_CURRENT_SOURCE_DIR}/include/tlsclient.h"
)

add_executable(${PROJECT_NAME}
    ${SOURCES}
    ${HEADERS}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/mainclient.cpp"
)

target_include_directories(${PROJECT_NAME} PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${NETWORK_LIB_NAME}
)

enable_options(${PROJECT_NAME})