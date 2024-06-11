cmake_minimum_required(VERSION 3.10)
project(hardware-based-password-manager)

enable_language(C ASM)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
add_subdirectory(customer_bank)
add_subdirectory(circular_buffer)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
    add_executable(${PROJECT_NAME} windows_implementation/main.c)
elseif(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    add_executable(${PROJECT_NAME} windows_implementation/main.c)
endif()


target_include_directories(${PROJECT_NAME} PUBLIC ./debug)
target_link_libraries(${PROJECT_NAME} PUBLIC customer_bank)
target_link_libraries(${PROJECT_NAME} PUBLIC circular_buffer)

