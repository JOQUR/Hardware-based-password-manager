CMAKE_MINIMUM_REQUIRED(VERSION 3.13)

project(HardwareBasedPasswordManager)


set(EXECUTABLE ${PROJECT_NAME}-srv)

set(SRC_FILES
        ${PROJECT_SOURCE_DIR}/AES/src/AES.c 
        ${PROJECT_SOURCE_DIR}/bitproto/src/bitproto.c 
        ${PROJECT_SOURCE_DIR}/circular_buffer/src/circular_buffer.c 
        ${PROJECT_SOURCE_DIR}/compact25519/src/compact25519.c 
        ${PROJECT_SOURCE_DIR}/customer_bank/src/customer_bank.c 
        ${PROJECT_SOURCE_DIR}/ECDH/src/ecdh.c 
        ${PROJECT_SOURCE_DIR}/messaging_bp/src/messaging_bp.c 
        ${PROJECT_SOURCE_DIR}/messenger/src/messenger.c 
        ${PROJECT_SOURCE_DIR}/user_store/src/user_store.c 
        ${PROJECT_SOURCE_DIR}/debug/debug.c
        ${PROJECT_SOURCE_DIR}/crypto_ctx/src/crypto_ctx.c
        ${PROJECT_SOURCE_DIR}/user_context/src/user_context.c
        ${PROJECT_SOURCE_DIR}/app/src/app.c
)

add_executable(${EXECUTABLE} server_example.c ${SRC_FILES})

target_include_directories(${EXECUTABLE} 
        PUBLIC ${PROJECT_SOURCE_DIR}/AES/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/bitproto/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/circular_buffer/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/compact25519/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/customer_bank/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/debug
        PUBLIC ${PROJECT_SOURCE_DIR}/utils
        PUBLIC ${PROJECT_SOURCE_DIR}/ECDH/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/messaging_bp/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/messenger/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/user_store/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/crypto_ctx/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/user_context/inc/
        PUBLIC ${PROJECT_SOURCE_DIR}/app/inc/
)

target_link_directories(${EXECUTABLE} PUBLIC
        ${PROJECT_SOURCE_DIR}/AES/src/AES.c
        ${PROJECT_SOURCE_DIR}/bitproto/src/bitproto.c
        ${PROJECT_SOURCE_DIR}/circular_buffer/src/circular_buffer.c
        ${PROJECT_SOURCE_DIR}/compact25519/src/compact25519.c
        ${PROJECT_SOURCE_DIR}/customer_bank/src/customer_bank.c
        ${PROJECT_SOURCE_DIR}/ECDH/src/ECDH.c
        ${PROJECT_SOURCE_DIR}/messaging_bp/src/messaging_bp.c
        ${PROJECT_SOURCE_DIR}/messenger/src/messenger.c
        ${PROJECT_SOURCE_DIR}/user_store/src/user_store.c
        ${PROJECT_SOURCE_DIR}/debug/debug.c
        ${PROJECT_SOURCE_DIR}/crypto_ctx/src/crypto_ctx.c
        ${PROJECT_SOURCE_DIR}/user_context/src/user_context.c
        ${PROJECT_SOURCE_DIR}/app/src/app.c
)