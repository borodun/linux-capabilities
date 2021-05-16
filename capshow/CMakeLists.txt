cmake_minimum_required(VERSION 3.16)
project(capshow)

set(CMAKE_C_STANDARD 11)

add_executable(capshow main.c)
add_executable(demo1 demo1.c)

target_link_libraries(capshow cap)
