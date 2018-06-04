cmake_minimum_required(VERSION 2.8)

project(libumqtt C)

add_definitions(-O -Wall -Wextra -Werror --std=gnu99 -D_GNU_SOURCE -Wno-misleading-indentation -Wno-unused-parameter)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules/")

#set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(src)
add_subdirectory(example)
