project(${SERVER_NAME})


add_executable(${PROJECT_NAME}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/mainserver.cpp"
)

target_include_directories(${PROJECT_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PUBLIC
        ${NETWORK_LIB_NAME}
)

enable_options(${PROJECT_NAME})
