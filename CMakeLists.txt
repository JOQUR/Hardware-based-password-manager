cmake_minimum_required(VERSION 3.10)
project(linux_implementation)

enable_language(C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(TESTS   main_test)
enable_testing()

add_subdirectory(customer_bank)
add_subdirectory(circular_buffer)
add_subdirectory(AES)
add_subdirectory(ECDH)
add_executable(${PROJECT_NAME} main.c)
add_executable(${TESTS} ./test/test_main.c) 
target_include_directories(${PROJECT_NAME} PUBLIC ./debug)
target_link_libraries(${PROJECT_NAME} PUBLIC customer_bank)
target_link_libraries(${PROJECT_NAME} PUBLIC circular_buffer)
target_link_libraries(${PROJECT_NAME} PUBLIC AES)
target_link_libraries(${PROJECT_NAME} PUBLIC ecdh)
target_link_libraries(${PROJECT_NAME} PUBLIC cbor)

add_test(
    NAME ${TESTS} 
    COMMAND $<TARGET_FILE:main_test>)