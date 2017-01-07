cmake_minimum_required(VERSION 3.1)

project(aclog)

# Binary output path
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Configurations
set(CMAKE_CONFIGURATION_TYPES Release CACHE STRING "" FORCE)

# /Zi = Generate debug info
# /EHsc = C++ exceptions only
set(CMAKE_CXX_FLAGS "/Zi /EHsc" CACHE STRING "" FORCE)

# Statically link CRT
foreach(flag_var CMAKE_CXX_FLAGS CMAKE_CXX_FLAGS_RELEASE)
    if(${flag_var} MATCHES "/MD")
        string(REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    endif(${flag_var} MATCHES "/MD")
endforeach(flag_var)

# Silence deprecation warnings
add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_CRT_NONSTDC_NO_DEPRECATE -D_SCL_SECURE_NO_WARNINGS)

# Source directories
add_subdirectory(src)

# Print out definitions
get_directory_property(COMPILEDEFS COMPILE_DEFINITIONS)
message("COMPILE_DEFINITIONS = ${COMPILEDEFS}")
