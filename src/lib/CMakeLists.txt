set(LIBTARGET "certutilslib")

add_library(${LIBTARGET} SHARED info.c convert.c read.c helper.c type.c)
include_directories(${CMAKE_SOURCE_DIR}/include)

target_link_libraries(${LIBTARGET} PRIVATE ${OPENSSL_CRYPTO_LIBRARIES})

set_target_properties(${LIBTARGET} PROPERTIES OUTPUT_NAME "certutils")

target_compile_options(${LIBTARGET} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wnull-dereference -Wconversion)

install(TARGETS ${LIBTARGET} DESTINATION lib)
