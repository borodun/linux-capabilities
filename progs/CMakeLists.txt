cmake_minimum_required(VERSION 3.16)
project(Capabilities)

set(CMAKE_C_STANDARD 11)

add_executable(capshow capshow.c)
add_executable(capchange capchange.c)

target_link_libraries(capshow cap)
target_link_libraries(capchange cap-ng)
