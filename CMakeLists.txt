cmake_minimum_required(VERSION 3.10)
project(linux_implementation)

enable_language(C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_compile_definitions(COMPACT_DISABLE_ED25519)
add_compile_definitions(COMPACT_DISABLE_X25519_DERIVE)

set(src)
set(inc)

# Append new source file to compile
list(APPEND src  
        customer_bank/src/customer_bank.c 
        circular_buffer/src/circular_buffer.c
        messaging_bp/src/messaging_bp.c
        main.c
)

# Append new directory to include
list(APPEND inc  
        debug
        customer_bank/inc 
        circular_buffer/inc
        messaging_bp/inc
)
add_subdirectory(AES)
add_subdirectory(ECDH)
add_subdirectory(compact25519)
add_subdirectory(bitproto)

add_executable(${PROJECT_NAME} ${src} )
target_include_directories(${PROJECT_NAME} PUBLIC ${inc})
target_link_libraries(${PROJECT_NAME} PUBLIC AES)
target_link_libraries(${PROJECT_NAME} PUBLIC ecdh)
target_link_libraries(${PROJECT_NAME} PUBLIC cbor)
target_link_libraries(${PROJECT_NAME} PUBLIC bitproto)
target_link_libraries(${PROJECT_NAME} PUBLIC compact25519)
