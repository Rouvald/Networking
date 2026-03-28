function(setup_conan_profiles)
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

    # These variables must outlive the function scope so `project()` can load
    # the Conan dependency provider during the top-level configure step.
    set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${CMAKE_CONAN_PATH}" PARENT_SCOPE)
    set(CONAN_HOST_PROFILE "${CONAN_PROFILE}" PARENT_SCOPE)
    set(CONAN_BUILD_PROFILE "${CONAN_PROFILE}" PARENT_SCOPE)
endfunction()

function(enable_options target_name)
    if(NOT TARGET ${target_name})
        message(FATAL_ERROR "enable_options(${target_name}) called before target creation")
    endif()

    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            /W4
            /permissive-
            /Zc:__cplusplus
        )

        if(ENABLE_WERROR)
            message(STATUS "enable_options(${target_name}): enable error are configured for MSVC")
            target_compile_options(${target_name} PRIVATE /WX)
        endif()

        if(ENABLE_SANITIZERS AND NOT ENABLE_TSAN)
            message(WARNING "enable_options(${target_name}): sanitizers are not configured for MSVC")
        endif()

        if(ENABLE_TSAN)
            message(WARNING "enable_options(${target_name}): ThreadSanitizer is not supported for MSVC")
        endif()

        return()
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        target_compile_options(${target_name} PRIVATE
            -Wall      # def
            -Wextra    #
            -Wpedantic #
            -Wshadow          # some convs
            -Wconversion      #
            -Wsign-conversion #
            -Wdouble-promotion     # additional check
            -Wformat=2             #
            -Woverloaded-virtual   #
            -Wimplicit-fallthrough #
            -fno-omit-frame-pointer     # stack trace
            -fno-optimize-sibling-calls #
            -fstack-protector-strong # stack protect (test)
        )

        # runtime stl check
        if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR MINGW)
            target_compile_definitions(${target_name} PRIVATE _GLIBCXX_ASSERTIONS)
        endif()

        # my death
        if(ENABLE_WERROR)
            message(STATUS "enable_options(${target_name}): enable error are configured for ${CMAKE_CXX_COMPILER_ID}")
            target_compile_options(${target_name} PRIVATE -Werror)
        endif()

        # sanitizers
        if(ENABLE_SANITIZERS AND NOT ENABLE_TSAN)
            message(STATUS "enable_options(${target_name}): trying enable AddressSanitizer and UndefinedBehaviorSanitizer for ${CMAKE_CXX_COMPILER_ID}")
            if(WIN32)
                target_compile_options(${target_name} PRIVATE
                    -fsanitize=address
                    -fno-sanitize-recover=all
                )
                target_link_options(${target_name} PRIVATE -fsanitize=address)
                message(STATUS "enable_options(${target_name}): enabled AddressSanitizer only on Windows")
            else()
                target_compile_options(${target_name} PRIVATE
                    -fsanitize=address,undefined
                    -fno-sanitize-recover=all
                )
                target_link_options(${target_name} PRIVATE -fsanitize=address,undefined)
            endif()
        endif()

        if(ENABLE_TSAN)
            message(STATUS "enable_options(${target_name}): trying enable ThreadSanitizer for ${CMAKE_CXX_COMPILER_ID}")
            if(WIN32)
                message(WARNING "enable_options(${target_name}): ThreadSanitizer is not supported on Windows")
            else()
                target_compile_options(${target_name} PRIVATE -fsanitize=thread)
                target_link_options(${target_name} PRIVATE -fsanitize=thread)
            endif()
        endif()

        if(WIN32)
            target_link_options(${target_name} PRIVATE -Wl,--no-undefined)
        elseif(APPLE)
            target_link_options(${target_name} PRIVATE -Wl,-undefined,error)
        else()
            target_link_options(${target_name} PRIVATE -Wl,-z,defs)
        endif()

        return()
    endif()

    message(STATUS "enable_options(${target_name}): no compiler-specific options configured for ${CMAKE_CXX_COMPILER_ID}")
endfunction()
