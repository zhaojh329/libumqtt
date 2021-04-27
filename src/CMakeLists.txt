# The version number.
set(UMQTT_VERSION_MAJOR 1)
set(UMQTT_VERSION_MINOR 1)
set(UMQTT_VERSION_PATCH 0)

aux_source_directory(. SOURCES)
list(APPEND SOURCES buffer/buffer.c)

if(BUILD_STATIC)
    if(SSL_SUPPORT)
        list(APPEND SOURCES ${SSL_SRC})
    endif()

    add_library(umqtt STATIC ${SOURCES})

    if(SSL_SUPPORT)
        target_compile_definitions(umqtt PRIVATE ${SSL_DEFINE})
        target_include_directories(umqtt PRIVATE ${SSL_INC})
    endif()
else()
    add_library(umqtt SHARED ${SOURCES})

    if(SSL_SUPPORT)
        target_link_libraries(umqtt PRIVATE ${SSL_TARGET})
    endif()

    target_link_libraries(umqtt PRIVATE ${LIBEV_LIBRARY})
    set_target_properties(umqtt PROPERTIES VERSION ${UMQTT_VERSION_MAJOR}.${UMQTT_VERSION_MINOR}.${UMQTT_VERSION_PATCH})
endif()

target_include_directories(umqtt PRIVATE ${CMAKE_CURRENT_BINARY_DIR} ${LIBEV_INCLUDE_DIR} buffer)

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_subdirectory(lua)

install(
    FILES
        log.h
        umqtt.h
        utils.h
        buffer/buffer.h
        ${CMAKE_CURRENT_BINARY_DIR}/config.h
    DESTINATION include/umqtt
)

install(
    TARGETS umqtt
    DESTINATION lib
)

message(STATUS "UMQTT_VERSION: ${UMQTT_VERSION_MAJOR}.${UMQTT_VERSION_MINOR}.${UMQTT_VERSION_PATCH}")
