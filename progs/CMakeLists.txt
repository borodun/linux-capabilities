cmake_minimum_required(VERSION 3.16)
project(Capabilities)

set(CMAKE_C_STANDARD 11)

add_executable(capshow capShow.c)
add_executable(capenv capEnviron.c)
add_executable(socket_test socketTest.c)

target_link_libraries(capshow cap)
target_link_libraries(capenv cap-ng)

