cmake_minimum_required (VERSION 3.12)
project(plm LANGUAGES C VERSION 0.3.0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 11)

include(CTest)  # Defines BUILD_TESTING and enables CTest when ON

if(BUILD_TESTING)
    add_subdirectory(test)
endif()

