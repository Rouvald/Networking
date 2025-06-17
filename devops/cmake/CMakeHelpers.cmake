macro(setup_conan_profiles)
    set(PROFILE_PATH_Windows_Release "${CMAKE_CURRENT_SOURCE_DIR}/conanProfiles/conanProfileRelease_Win")
    set(PROFILE_PATH_Windows_Debug "${CMAKE_CURRENT_SOURCE_DIR}/conanProfiles/conanProfileDebug_Win")
    set(PROFILE_PATH_Linux_Release "${CMAKE_CURRENT_SOURCE_DIR}/conanProfiles/conanProfileRelease_Linux")
    set(PROFILE_PATH_Linux_Debug "${CMAKE_CURRENT_SOURCE_DIR}/conanProfiles/conanProfileDebug_Linux")

    set(CURRENT_PROFILE "PROFILE_PATH_${CMAKE_HOST_SYSTEM_NAME}_${CMAKE_BUILD_TYPE}")
    message(STATUS "Selected Conan profile variable: ${CURRENT_PROFILE}")

    if(DEFINED ${CURRENT_PROFILE})
        set(CONAN_PROFILE "${${CURRENT_PROFILE}}" CACHE INTERNAL "Conan profile path")
        message(STATUS "Using Conan profile: ${CONAN_PROFILE}")
    else()
        message(FATAL_ERROR "Unsupported configuration for: ${CURRENT_PROFILE}")
    endif()

    # Загрузка conan_provider.cmake
    set(CMAKE_CONAN_PATH "${CMAKE_BINARY_DIR}/conan_provider.cmake")
    if(NOT EXISTS ${CMAKE_CONAN_PATH})
        message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
        file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/refs/heads/develop2/conan_provider.cmake" "${CMAKE_CONAN_PATH}")
    endif()

    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES ${CMAKE_CONAN_PATH})
    set(CONAN_HOST_PROFILE "${CONAN_PROFILE}")
    set(CONAN_BUILD_PROFILE "${CONAN_PROFILE}")
endmacro()