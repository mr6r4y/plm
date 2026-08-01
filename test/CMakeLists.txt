include_directories(BEFORE ${PROJECT_SOURCE_DIR}/include/ )

find_package(cmocka REQUIRED CONFIG)

add_executable(plm_bs-test plm_bs-test.c)
target_link_libraries(plm_bs-test PRIVATE ${CMOCKA_LIBRARY})

add_executable(plm_enc-test plm_enc-test.c)
target_link_libraries(plm_enc-test PRIVATE ${CMOCKA_LIBRARY})

add_test(NAME plm_bs.unit COMMAND plm_bs-test)
add_test(NAME plm_enc.unit COMMAND plm_enc-test)

set_tests_properties(plm_bs.unit PROPERTIES
    LABELS "unit"
    TIMEOUT 30
)
set_tests_properties(plm_enc.unit PROPERTIES
    LABELS "unit"
    TIMEOUT 30
)
