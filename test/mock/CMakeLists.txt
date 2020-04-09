
add_library(openssl_mock openssl_mock.cpp)
target_link_libraries(openssl_mock PRIVATE CppUTest CppUTestExt)
