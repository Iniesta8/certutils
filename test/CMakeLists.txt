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

add_subdirectory("mock")

add_executable(testapi test_api.c)
target_link_libraries(testapi PRIVATE certutilslib CppUTest openssl_mock)
add_test(NAME testapi COMMAND testapi)


add_executable(certutils_info_correct_information_test certutils_info_correct_information_test.cpp)
target_link_libraries(certutils_info_correct_information_test PRIVATE certutilslib CppUTest openssl_mock)
add_test(NAME certutils_info_correct_information_test COMMAND certutils_info_correct_information_test)
