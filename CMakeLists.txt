cmake_minimum_required (VERSION 3.12)

set(TARGET_NAME "plm-test")

project(${TARGET_NAME})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_C_STANDARD 90)

include_directories(BEFORE src/ )

add_executable(plm_bs-test test/plm_bs-test.c)
install(TARGETS plm_bs-test)
