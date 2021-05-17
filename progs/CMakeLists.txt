cmake_minimum_required(VERSION 3.16)
project(Capabilities)

set(CMAKE_C_STANDARD 11)

add_executable(capshow capshow.c)
add_executable(set_ambient set_ambient.c)

target_link_libraries(capshow cap)
target_link_libraries(set_ambient cap-ng)
