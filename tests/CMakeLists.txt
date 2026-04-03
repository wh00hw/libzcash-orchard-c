add_executable(test_hwp test_hwp.c)
target_link_libraries(test_hwp PRIVATE zcash-orchard-c)
add_test(NAME test_hwp COMMAND test_hwp)

add_executable(test_orchard test_orchard.c)
target_link_libraries(test_orchard PRIVATE zcash-orchard-c)
add_test(NAME test_orchard COMMAND test_orchard)
