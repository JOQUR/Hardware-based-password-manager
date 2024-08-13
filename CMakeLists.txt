cmake_minimum_required(VERSION 3.10)
project(linux_implementation)

enable_language(C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_definitions(COMPACT_DISABLE_ED25519)
add_compile_definitions(COMPACT_DISABLE_X25519_DERIVE)


add_subdirectory(customer_bank)
add_subdirectory(circular_buffer)
add_subdirectory(AES)
add_subdirectory(ECDH)
add_subdirectory(bitproto)
add_subdirectory(compact25519)
add_executable(${PROJECT_NAME} main.c ./messaging/proto_bp.c ./messaging/proto_bp.h)
target_include_directories(${PROJECT_NAME} PUBLIC ./debug)
target_link_libraries(${PROJECT_NAME} PUBLIC customer_bank)
target_link_libraries(${PROJECT_NAME} PUBLIC circular_buffer)
target_link_libraries(${PROJECT_NAME} PUBLIC AES)
target_link_libraries(${PROJECT_NAME} PUBLIC ecdh)
target_link_libraries(${PROJECT_NAME} PUBLIC cbor)
target_link_libraries(${PROJECT_NAME} PUBLIC bitproto)
target_link_libraries(${PROJECT_NAME} PUBLIC compact25519)
