project(${CLIENT_NAME})

add_executable(${PROJECT_NAME}
    "${CMAKE_CURRENT_SOURCE_DIR}/src/mainclient.cpp"
)

target_include_directories(${PROJECT_NAME} PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${NETWORK_LIB_NAME}
)

enable_options(${PROJECT_NAME})
