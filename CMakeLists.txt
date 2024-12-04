cmake_minimum_required(VERSION 3.2)
project (test CUDA CXX)

# libraries
add_library(AES128 AES128.cpp)
add_library(AES_Serial AES_Serial.cpp)
add_library(AES_Parallel AES_Parallel.cpp AES_Parallel_kernel.cu)
target_link_libraries(AES_Serial AES128)
target_link_libraries(AES_Parallel AES128)

# executables
add_executable (test test.cpp)
target_link_libraries(test AES_Serial AES_Parallel AES128)
set_target_properties(test
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin"
)