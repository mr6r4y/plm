include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include/ )

set(SANITIZER "none" CACHE STRING
    "Runtime sanitizer: none, asan, or tsan")
set_property(CACHE SANITIZER
    PROPERTY STRINGS none asan tsan)

add_library(sanitizers INTERFACE)

if(NOT SANITIZER STREQUAL "none"
   AND NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    message(FATAL_ERROR
        "${SANITIZER} requires GCC or Clang")
endif()

if(SANITIZER STREQUAL "asan")
    target_compile_options(sanitizers INTERFACE
        -O1
        -g
        -fno-omit-frame-pointer
        -fno-optimize-sibling-calls
        -fsanitize=address
    )
    target_link_options(sanitizers INTERFACE
        -fsanitize=address
    )
elseif(SANITIZER STREQUAL "tsan")
    target_compile_options(sanitizers INTERFACE
        -O1
        -g
        -fno-omit-frame-pointer
        -fsanitize=thread
    )
    target_link_options(sanitizers INTERFACE
        -fsanitize=thread
    )
elseif(NOT SANITIZER STREQUAL "none")
    message(FATAL_ERROR
        "Unknown SANITIZER=${SANITIZER}")
endif()

find_package(cmocka REQUIRED CONFIG)

add_executable(plm_bs-test plm_bs-test.c)
target_link_libraries(plm_bs-test PRIVATE
    sanitizers
    ${CMOCKA_LIBRARY}
)
target_compile_definitions(plm_bs-test PRIVATE
    PLM_BS_TEST_VERBOSE=0
)

add_executable(plm_enc-test plm_enc-test.c)
target_link_libraries(plm_enc-test PRIVATE
    sanitizers
    ${CMOCKA_LIBRARY}
)

function(add_cmocka_unit_test target test_name)
    add_test(NAME ${test_name} COMMAND ${target} ${test_name})
    set_tests_properties(${test_name} PROPERTIES
        LABELS "unit"
        TIMEOUT 30
    )
endfunction()

add_cmocka_unit_test(plm_bs-test plm_bs_test_vmem)
add_cmocka_unit_test(plm_bs-test plm_bs_test_queue)
add_cmocka_unit_test(plm_enc-test plm_enc_test_hexdump)
add_cmocka_unit_test(plm_enc-test plm_enc_test_bin2hex_hex2bin)
