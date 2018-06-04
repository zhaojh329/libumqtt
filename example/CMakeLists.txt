include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_BINARY_DIR}/src ${LIBUBOX_INCLUDE_DIR})

add_executable(helloworld helloworld.c)
target_link_libraries(helloworld umqtt ${LIBUBOX_LIBRARY})
