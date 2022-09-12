# Third-party libraries may have substandard code.

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -w")


set_property(DIRECTORY PROPERTY EXCLUDE_FROM_ALL 1)

add_subdirectory (lz4-cmake)

