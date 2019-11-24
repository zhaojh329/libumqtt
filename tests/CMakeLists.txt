include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_SOURCE_DIR}/src/buffer ${CMAKE_BINARY_DIR}/src)

add_executable(github github_ci.c)
target_link_libraries(github umqtt ${LIBEV_LIBRARY})
