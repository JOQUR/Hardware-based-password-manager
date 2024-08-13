cmake_minimum_required(VERSION 3.10)
project(win_implementation)

enable_language(C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Set here name of the module
set(LIB_NAME messaging_bp)

set(MODULE_FILE ${PROJECT_SOURCE_DIR}/src/${LIB_NAME}.c ${PROJECT_SOURCE_DIR}/inc/${LIB_NAME}.h )
add_library(${LIB_NAME} STATIC ${MODULE_FILE})
target_include_directories(${LIB_NAME} PUBLIC 
                                        ../debug
                                        ../bitproto/inc)
