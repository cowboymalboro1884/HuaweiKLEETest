cmake_minimum_required(VERSION 3.0)

project(CWE114_Process_Control)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(CWE114_Process_Control
        Source.cpp
        )

target_link_libraries(CWE114_Process_Control
        dl
        )