set(EXECTARGET "certutils")

add_executable(${EXECTARGET} cli.c)

target_link_libraries(${EXECTARGET} PRIVATE certutilslib ${OPENSSL_CRYPTO_LIBRARIES})

target_compile_options(${EXECTARGET} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wnull-dereference -Wconversion)

install(TARGETS ${EXECTARGET} EXPORT ${EXECTARGET}-config DESTINATION bin)

add_subdirectory(lib)

