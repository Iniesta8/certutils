if(DEFINED ENV{CPPUTEST_HOME})
    message(STATUS "Using CppUTest home: $ENV{CPPUTEST_HOME}")
    set(CPPUTEST_INCLUDE_DIRS $ENV{CPPUTEST_HOME}/include)
    set(CPPUTEST_LIBRARIES $ENV{CPPUTEST_HOME}/lib)
    set(CPPUTEST_LDFLAGS CppUTest CppUTestExt)
else()
    find_package(CppUTest)

    if(NOT CppUTest_FOUND)
        find_package(PkgConfig REQUIRED)
        pkg_search_module(CPPUTEST REQUIRED cpputest>=3.8)
    endif()

    if (CppUTest_FOUND)
        message(STATUS "Found CppUTest version ${CPPUTEST_VERSION}")
    endif()
endif()

add_executable(testapi test_api.c mock/openssl_mock.cpp)
target_link_libraries(testapi PRIVATE certutilslib)
target_link_libraries(testapi PRIVATE CppUTest)
target_link_libraries(testapi PRIVATE CppUTestExt)
add_test(NAME testapi COMMAND testapi WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

set(OPENSSL_MOCK_TESTS
    "certutils_info_correct_information_test")

foreach(TEST IN LISTS OPENSSL_MOCK_TESTS)
    message(${TEST})
    add_executable(${TEST} "${TEST}.cpp" mock/openssl_mock.cpp)
    target_link_libraries(${TEST} PRIVATE certutilslib)
    target_link_libraries(${TEST} PRIVATE CppUTest)
    target_link_libraries(${TEST} PRIVATE CppUTestExt)
    add_test(NAME ${TEST} COMMAND ${TEST} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
endforeach()

# Copy testfiles from source to binary directory
#add_custom_command(
#        TARGET testapi POST_BUILD
#        COMMAND cp -r ${CMAKE_SOURCE_DIR}/test/testfiles ${CMAKE_BINARY_DIR}/)
