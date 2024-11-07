cmake_minimum_required(VERSION 3.2)
project (test_serial CXX)

# libraries
add_library(AES128 AES128.cpp)
add_library(AES_Serial AES_Serial.cpp)
target_link_libraries(AES_Serial AES128)

# executables
add_executable (test_serial test_serial.cpp)
target_link_libraries(test_serial AES_Serial AES128)
set_target_properties(test_serial
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/bin"
)