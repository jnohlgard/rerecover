cmake_minimum_required(VERSION 3.25)
project(rerecover)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(vendorLIEF_submodule_dir "${CMAKE_CURRENT_LIST_DIR}/LIEF")
if (EXISTS "${vendorLIEF_submodule_dir}")
    # LIEF build config. Set the default options for LIEF's project setup
    option(LIEF_DOC "Build LIEF docs" OFF)
    option(LIEF_PYTHON_API "Build LIEF Python API" OFF)
    option(LIEF_EXAMPLES "Build LIEF examples" OFF)
    option(LIEF_TESTS "Build LIEF tests" OFF)
    mark_as_advanced(
            LIEF_DOC
            LIEF_PYTHON_API
            LIEF_EXAMPLES
            LIEF_TESTS
    )
    if (MSVC)
        set(LIEF_USE_CRT_RELEASE "MT" CACHE STRING "LIEF CRT option")
    endif ()
    add_subdirectory("${vendorLIEF_submodule_dir}")
endif ()

add_executable(rerecover main.cpp)
target_link_libraries(rerecover PRIVATE LIEF::LIEF)
