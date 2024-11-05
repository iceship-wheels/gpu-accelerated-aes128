project (test_serial CXX)
add_executable (${PROJECT_NAME} test_serial.cpp)
set_target_properties( ${PROJECT_NAME}
    PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}"
)