# Third-party libraries may have substandard code.

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w")


# add_contrib cmake_folder[ base_folder1[, ...base_folderN]]
function(add_contrib cmake_folder)
    if (ARGN)
        set(base_folders ${ARGN})
    else()
        set(base_folders ${cmake_folder})
    endif()

    foreach (base_folder ${base_folders})
        # some typos in the code
        if (NOT IS_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/${base_folder}")
            message(FATAL_ERROR "No such base folder '${base_folder}' (for '${cmake_folder}' cmake folder). Typo in the base folder name?")
        endif()

        file(GLOB contrib_files "${base_folder}/*")
        if (NOT contrib_files)
            # Checking out *all* submodules takes > 5 min. Therefore, the smoke build ("FastTest") in CI initializes only the set of
            # submodules minimally needed for a build and we cannot assume here that all submodules are populated.
            message(STATUS "submodule ${base_folder} is missing or empty. to fix try run:")
            message(STATUS "    git submodule update --init")
            return()
        endif()
    endforeach()

    message(STATUS "Adding contrib module ${base_folders} (configuring with ${cmake_folder})")
    add_subdirectory (${cmake_folder})
endfunction()

set_property(DIRECTORY PROPERTY EXCLUDE_FROM_ALL 1)

# add_subdirectory (boost-cmake)

# include_directories(${PROJECT_SOURCE_DIR}/contrib/xz/src/liblzma/api)
include_directories(${PROJECT_SOURCE_DIR}/contrib/poco/Foundation/include)


add_contrib (re2-cmake re2)
add_contrib (boost-cmake boost)
add_contrib (brotli-cmake brotli)
add_contrib (bzip2-cmake bzip2)
add_contrib (lz4-cmake lz4)
add_contrib (xz-cmake xz)
add_contrib (zstd-cmake zstd)
add_contrib (zlib-ng-cmake zlib-ng)
add_contrib (poco-cmake poco)
add_contrib (abseil-cpp-cmake abseil-cpp)
add_contrib (nuraft-cmake NuRaft)
