cmake_minimum_required(VERSION 3.0.0)
project(vigenere-ctf VERSION 0.1.0 LANGUAGES C CXX)

add_subdirectory(proto)
add_executable(vigenere-ctf main.cpp)
target_link_libraries(vigenere-ctf PRIVATE libvigenere_proto)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
