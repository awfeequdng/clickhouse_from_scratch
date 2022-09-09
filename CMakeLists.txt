CMAKE_MINIMUM_REQUIRED(VERSION 3.15.3)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


project(clickhouse)


set (CONFIG_VERSION "${CMAKE_CURRENT_BINARY_DIR}/src/Common/config_version.h")
set (CONFIG_COMMON "${CMAKE_CURRENT_BINARY_DIR}/src/Common/config.h")

include (./cmake/version.cmake)
message (STATUS "Will build ${VERSION_FULL} revision ${VERSION_REVISION} ${VERSION_OFFICIAL}")
configure_file (src/Common/config.h.in ${CONFIG_COMMON})
configure_file (src/Common/config_version.h.in ${CONFIG_VERSION})
configure_file (src/Core/config_core.h.in "${CMAKE_CURRENT_BINARY_DIR}/src/Core/include/config_core.h")

include_directories(${CMAKE_CURRENT_BINARY_DIR}/src)

include (cmake/target.cmake)

include(FetchContent)                   # FetchContent_ functions.
# find_package(PkgConfig REQUIRED)        # pkg_search_module function.

function(add_cfs_dep NAME GIT_URL GIT_TAG)
    string(TOLOWER "${NAME}" NAME_LOWER)    # The automatically created variables are lowercase. Footgun!
    FetchContent_Declare(${NAME})           # Declare the resource to be fetched.
    if (NOT ${NAME}_POPULATED)
        # The long form of FetchContent_Populate is used since pxtidb requires control of the source folder name.
        # This is to enable includes like #include "NAME/their_files.h".
        FetchContent_Populate(${NAME}
                # QUIET                                                   # Don't print verbose output while populating.
                SOURCE_DIR ${CMAKE_BINARY_DIR}/_deps/src/${NAME}        # Source files go here.
                BINARY_DIR ${CMAKE_BINARY_DIR}/_deps/build/${NAME}      # Build files go here.
                SUBBUILD_DIR ${CMAKE_BINARY_DIR}/_deps/sub/${NAME}      # Sub-build files go here.
                GIT_REPOSITORY ${GIT_URL}                               # Download from GIT_URL.
                GIT_TAG ${GIT_TAG}                                      # Checkout the specific GIT_TAG version.
                )

        # set(MESSAGE_QUIET ON)                                                           # Silence third party includes.
        add_subdirectory(${${NAME_LOWER}_SOURCE_DIR} ${${NAME_LOWER}_BINARY_DIR})       # Include the dependency.
        unset(MESSAGE_QUIET)                                                            # Undo silence.
    endif ()

    # Get the date of the last git commit for the GIT_TAG branch.
    execute_process(COMMAND git log -1 --format=%cd --date=short                        # Get the last commit's date.
            WORKING_DIRECTORY ${${NAME_LOWER}_SOURCE_DIR}                               # From the specified git dir.
            OUTPUT_VARIABLE GIT_LAST_COMMIT)                                            # Save to GIT_LAST_COMMIT.
    string(STRIP "${GIT_LAST_COMMIT}" GIT_LAST_COMMIT)                                  # Remove any trailing newlines.

    message(STATUS "[FOUND] ${NAME} (${GIT_URL} ${GIT_TAG} ${GIT_LAST_COMMIT})")        # Print a success message.
endfunction()

function(add_cfs_dep_singlefile NAME FILE_URL)
    string(TOLOWER "${NAME}" NAME_LOWER)    # For consistency with add_pxtidb_dep above, also use lowercase.
    get_filename_component(FILE_NAME ${FILE_URL} NAME)                                  # Get the filename.
    set(DOWNLOAD_FOLDER ${CMAKE_BINARY_DIR}/_deps/src/${NAME})                          # Set download folder.
    if (EXISTS ${DOWNLOAD_FOLDER}/${FILE_NAME})                                         # Only download if required.
        message(STATUS "[FOUND] ${NAME} (already in ${DOWNLOAD_FOLDER}, skipping download)")
    else ()
        file(DOWNLOAD ${FILE_URL} ${DOWNLOAD_FOLDER}/${FILE_NAME})                      # Download the file.
        message(STATUS "[FOUND] ${NAME} (${FILE_URL})")                                 # Print a success message.
    endif ()
    set(${NAME_LOWER}_SOURCE_DIR ${DOWNLOAD_FOLDER} PARENT_SCOPE)                       # Set SOURCE_DIR in parent.
endfunction()

# add_cfs_dep(utf8proc https://github.com/JuliaStrings/utf8proc.git v2.6.1)
# add_cfs_dep(fmt https://github.com/fmtlib/fmt.git 9.0.0)
# add_cfs_dep(gtest https://github.com/google/googletest.git release-1.10.0)

# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/poco)
link_directories(poco_build/lib)


add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/gtest)

set(CMAKE_CXX_STANDARD 17)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/fmt)
set(CMAKE_CXX_STANDARD 20)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/cityhash102)
include_directories(contrib/cityhash102/include)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/replxx)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/double-conversion)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/cctz)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/dragonbox)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/magic_enum)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/contrib/fast_float)


include_directories(contrib/poco/Net/include)
include_directories(contrib/poco/Foundation/include)
include_directories(contrib/poco/Util/include)

include_directories(contrib/pcg-random/include)


set(CMAKE_BUILD_TYPE Release)


SET (CMAKE_CXX_STANDARD 20)

# set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++2a")

# include generated files in project environment
include_directories(
  ${PROJECT_SOURCE_DIR}
)

# include_directories(include/)
# include_directories(src/include/)
include_directories(src/)
include_directories(programs/)
include_directories(programs/server)
include_directories(base)
include_directories(base/daemon)
include_directories(base/widechar_width)
include_directories(${CMAKE_CURRENT_BINARY_DIR})


# Get the list of all pxtidb sources.
file(GLOB_RECURSE
        CFS_SRCS                  # Store the list of files into the variable ${PXTIDB_SRCS}.
        CONFIGURE_DEPENDS               # See above. Ask CMake to regenerate the build system if these files change.
        ${PROJECT_SOURCE_DIR}/src/*.cpp
        ${PROJECT_SOURCE_DIR}/src/*.h
        ${PROJECT_SOURCE_DIR}/base/*.cpp
        ${PROJECT_SOURCE_DIR}/base/*.h
        )

add_library(cfs
  ${CFS_SRCS}
)
target_link_libraries(cfs
  PUBLIC
  PocoNet
  PocoFoundation
  PocoUtil
  fmt
  replxx
  double-conversion
  cctz
  dragonbox_to_chars
  magic_enum
  fast_float
  ${CMAKE_DL_LIBS}
)

add_executable(clickhouse
  programs/main.cpp
  programs/server/Server.cpp
)

target_link_libraries(clickhouse
  PRIVATE
  cfs
)

SET(PX_TEST_PARALLELISM 1)
SET(UNITTEST_OUTPUT_ON_FAILURE ON)
# //////////////////////////////////// test ///////////////////////////////////
# unittest invoke ctest on tests which are labeled "unittest".
# Unit tests are executed in parallel because we only care about correctness, not performance.
# This means that two different unit tests could be executing at the same time.
# In practice, figuring out the number to -j seems annoying and there doesn't appear to be a penalty for having too
# many tests queued up, so we'll use the magic number ${PX_TEST_PARALLELISM}.
# Footgun: Running tests in parallel causes wonderful breakages on OSX/clang. Not on Ubuntu/clang though.
# Footgun: labels passed to -L are regex. Give them very unique names.
add_custom_target(unittest
        # ctest
        # --resource-spec-file ${BUILD_SUPPORT_DATA_DIR}/ctest_resource_specs.json    # For controlling conflicting tests.
        ${UNITTEST_OUTPUT_ON_FAILURE}       # Whether to print output when a test fails.
        -j ${PX_TEST_PARALLELISM}       # Maximum number of parallel jobs.
        -L unittest                         # Run all tests that have a label like unittests. See footgun warning above.
        --no-compress-output                # Output verbosely so that it can be logged.
        -T Test                             # Run tests and log it to Testing/*/Test.xml.
        --timeout 3000                      # 3000 second timeout per test.
        USES_TERMINAL)

function(add_px_test
        TEST_NAME                   # The name of this test.
        TEST_SOURCES                # The CPP files for this test.
        TEST_LABEL                  # The label of this test. Will be added as a dependency of this label.
        SHOULD_EXCLUDE_FROM_ALL     # EXCLUDE_ALL if we should exclude from default ALL target, NO_EXCLUDE otherwise.
        SHOULD_UNITY_BUILD          # UNITY if we should unity build, NO_UNITY otherwise.
        )
    set(TEST_OUTPUT_DIR "${CMAKE_BINARY_DIR}/test")             # Output directory for tests.

    if (${SHOULD_EXCLUDE_FROM_ALL} STREQUAL "EXCLUDE_ALL")
        set(EXCLUDE_OPTION "EXCLUDE_FROM_ALL")
    elseif (${SHOULD_EXCLUDE_FROM_ALL} STREQUAL "NO_EXCLUDE")
        set(EXCLUDE_OPTION "")
    else ()
        message(FATAL_ERROR "Invalid option for SHOULD_EXCLUDE_FROM_ALL.")
    endif ()

    if (${SHOULD_UNITY_BUILD} STREQUAL "UNITY")
        set(UNITY_OPTION "ON")
    elseif (${SHOULD_UNITY_BUILD} STREQUAL "NO_UNITY")
        set(UNITY_OPTION "OFF")
    else ()
        message(FATAL_ERROR "Invalid option for SHOULD_UNITY_BUILD.")
    endif ()

    add_executable(${TEST_NAME} ${EXCLUDE_OPTION} ${TEST_SOURCES})

    target_compile_options(${TEST_NAME} PRIVATE "-Werror" "-Wall" "-fvisibility=hidden")
    target_link_libraries(${TEST_NAME} PRIVATE gmock_main)
    target_link_libraries(${TEST_NAME} PRIVATE gtest)
    target_link_libraries(${TEST_NAME} PRIVATE cfs)
    # if (${CFS_ENABLE_SHARED})
    #     target_link_libraries(${TEST_NAME} PRIVATE cfs)
    # else ()
    #     target_link_libraries(${TEST_NAME} PRIVATE cfs)
    # endif ()

    set_target_properties(${TEST_NAME} PROPERTIES
            CXX_EXTENSIONS OFF                                  # Disable compiler-specific extensions.
            ENABLE_EXPORTS ON                                   # Export for tpl.
            RUNTIME_OUTPUT_DIRECTORY "${TEST_OUTPUT_DIR}"       # Output the test binaries to this folder.
            UNITY_BUILD "${UNITY_OPTION}"                       # Possibly choose to use unity builds.
            )
    # Include the testing directories.
    target_include_directories(${TEST_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/test/include/)
    # Include the src directories.
    # target_include_directories(${TEST_NAME} PUBLIC ${CFS_INCLUDE_DIRECTORIES})
    # TODO(WAN): The "modern" gtest_discover_test has a ton of files. Favoring legacy add_test for now...
    # add_test(${TEST_NAME} ${BUILD_SUPPORT_DIR}/run-test.sh ${CMAKE_BINARY_DIR} test ${TEST_OUTPUT_DIR}/${TEST_NAME})
    # Label each test with TEST_LABEL so that ctest can run all the tests under the TEST_LABEL label later.
    # set_tests_properties(${TEST_NAME} PROPERTIES
    #         LABELS "${TEST_LABEL};${TEST_NAME}"                 # Label the test.
    #         ENVIRONMENT "PYTHONPATH=${PROJECT_SOURCE_DIR}"      # Set the PYTHONPATH to project root for self-driving.
    #         )
    # Add TEST_NAME as a dependency to TEST_LABEL. Note that TEST_LABEL must be a valid target!
    add_dependencies(${TEST_LABEL} ${TEST_NAME})
endfunction()


# file(GLOB_RECURSE PX_TEST_SOURCES
#         "test/common/*.cc"
#         "test/parser/*.cc"
#         "test/llvm/*.cc"
#         )

# option (MAKE_TESTS
#         "whether make test" OFF)

# if (${MAKE_TESTS})
#     foreach (PX_TEST_CC ${PX_TEST_SOURCES})
#         file(RELATIVE_PATH PX_TEST_CC_REL "${PROJECT_SOURCE_DIR}/test" ${PX_TEST_CC})
#         get_filename_component(PX_TEST_DIR ${PX_TEST_CC_REL} DIRECTORY)
#         get_filename_component(PX_TEST ${PX_TEST_CC} NAME_WE)

#         if (NOT ${PX_BUILD_TESTS})
#             set(EXCLUDE_OR_NOT "EXCLUDE_ALL")
#         elseif (${PX_USE_JUMBOTESTS})
#             set(EXCLUDE_OR_NOT "EXCLUDE_ALL")
#         else ()
#             set(EXCLUDE_OR_NOT "NO_EXCLUDE")
#         endif ()

#         add_px_test(${PX_TEST} ${PX_TEST_CC} unittest ${EXCLUDE_OR_NOT} NO_UNITY)
#     endforeach ()
# endif() # MAKE_TESTS
