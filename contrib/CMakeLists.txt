# Third-party libraries may have substandard code.

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w")


set_property(DIRECTORY PROPERTY EXCLUDE_FROM_ALL 1)

add_subdirectory (lz4-cmake)
add_subdirectory (boost-cmake)

if (USE_BZIP2)
    add_subdirectory(bzip2-cmake)
endif()

if (USE_INTERNAL_ZSTD_LIBRARY)
    add_subdirectory (zstd-cmake)
endif ()

# if (USE_INTERNAL_BROTLI_LIBRARY)
#     add_subdirectory(brotli-cmake)
#     target_compile_definitions(brotli PRIVATE BROTLI_BUILD_PORTABLE=1)
# endif ()
if (USE_BROTLI)
    add_subdirectory(brotli-cmake)
    target_compile_definitions(brotli PRIVATE BROTLI_BUILD_PORTABLE=1)
endif ()

# if (USE_INTERNAL_XZ_LIBRARY)
#     add_subdirectory (xz)
# endif()
add_subdirectory (xz)
include_directories(${PROJECT_SOURCE_DIR}/contrib/xz/src/liblzma/api)
