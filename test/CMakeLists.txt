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

add_executable(plm_bs-regression-test plm_bs-regression-test.c)
target_link_libraries(plm_bs-regression-test PRIVATE
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
add_cmocka_unit_test(plm_enc-test plm_enc_test_negative_rowsize_uses_default)

add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_stralloc_exhaustion)
add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_queue_slice_survives_growth)
add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_alloc_rejects_size_overflow)
add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_grow_rejects_size_overflow)
add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_mock_realloc_handles_oom)
add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_mock_realloc_shrink_returns_original)
add_cmocka_unit_test(plm_bs-regression-test plm_bs_test_alloc_returns_max_aligned_storage)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_test(NAME plm_enc_standalone_c11
        COMMAND ${CMAKE_C_COMPILER}
            -std=c11
            -pedantic-errors
            -Werror=implicit-function-declaration
            -Werror=format
            -I${PROJECT_SOURCE_DIR}/include
            -fsyntax-only
            ${CMAKE_CURRENT_SOURCE_DIR}/plm_enc-standalone-c11-test.c
    )
    set_tests_properties(plm_enc_standalone_c11 PROPERTIES
        LABELS "unit;compile"
        TIMEOUT 30
    )

    include(CheckLanguage)
    check_language(CXX)
    if(CMAKE_CXX_COMPILER)
        enable_language(CXX)
        add_test(NAME plm_headers_standalone_cxx17
            COMMAND ${CMAKE_CXX_COMPILER}
                -std=c++17
                -pedantic-errors
                -I${PROJECT_SOURCE_DIR}/include
                -fsyntax-only
                ${CMAKE_CURRENT_SOURCE_DIR}/plm-standalone-cxx17-test.cpp
        )
        set_tests_properties(plm_headers_standalone_cxx17 PROPERTIES
            LABELS "unit;compile"
            TIMEOUT 30
        )
    endif()
endif()
