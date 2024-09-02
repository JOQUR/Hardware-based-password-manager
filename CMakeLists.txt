cmake_minimum_required(VERSION 3.10)
project(linux_implementation)

enable_language(C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(EXE_NAME    ${PROJECT_NAME}-exec)
set(LIB_NAME    ${PROJECT_NAME}-lib)
set(SRV         ${PROJECT_NAME}-srv)

add_compile_definitions(COMPACT_DISABLE_ED25519)
add_compile_definitions(COMPACT_DISABLE_X25519_DERIVE)

set(src)
set(inc)

# Append new source file to compile
list(APPEND src  
        customer_bank/src/customer_bank.c 
        circular_buffer/src/circular_buffer.c
        messaging_bp/src/messaging_bp.c
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

add_executable(${EXE_NAME} main.c ${src} )
add_library(${LIB_NAME} ${src})
add_executable(${SRV} server_example.c ${src})

target_include_directories(${EXE_NAME} PUBLIC ${inc})
target_link_libraries(${EXE_NAME} PUBLIC AES)
target_link_libraries(${EXE_NAME} PUBLIC ecdh)
target_link_libraries(${EXE_NAME} PUBLIC cbor)
target_link_libraries(${EXE_NAME} PUBLIC bitproto)
target_link_libraries(${EXE_NAME} PUBLIC compact25519)

target_include_directories(${LIB_NAME} PUBLIC ${inc})
target_link_libraries(${LIB_NAME} PUBLIC AES)
target_link_libraries(${LIB_NAME} PUBLIC ecdh)
target_link_libraries(${LIB_NAME} PUBLIC cbor)
target_link_libraries(${LIB_NAME} PUBLIC bitproto)
target_link_libraries(${LIB_NAME} PUBLIC compact25519)

target_include_directories(${SRV} PUBLIC ${inc})
target_link_libraries(${SRV} PUBLIC AES)
target_link_libraries(${SRV} PUBLIC ecdh)
target_link_libraries(${SRV} PUBLIC cbor)
target_link_libraries(${SRV} PUBLIC bitproto)
target_link_libraries(${SRV} PUBLIC compact25519)