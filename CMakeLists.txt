cmake_minimum_required(VERSION 3.2)
project (test_serial CXX)
add_executable (test_serial test_serial.cpp)
add_library(AES128 AES128.cpp)
target_link_libraries(test_serial AES128)
set_target_properties( ${PROJECT_NAME}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}"
)