
add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE -Wno-misleading-indentation)

# The version number.
set(UMQTT_VERSION_MAJOR 0)
set(UMQTT_VERSION_MINOR 1)
set(UMQTT_VERSION_PATCH 0)

# Check the third party Libraries
find_package(Libubox REQUIRED)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${LIBUBOX_INCLUDE_DIR})

set(EXTRA_LIBS ${LIBUBOX_LIBRARY} dl)
set(SOURCE_FILES umqtt.c log.c)

set(UMQTT_SSL_SUPPORT_CONFIG 1)
option(UMQTT_SSL_SUPPORT "SSL support" ON)

if(NOT UMQTT_SSL_SUPPORT)
    set(UMQTT_SSL_SUPPORT_CONFIG 0)
endif()

add_library(umqtt SHARED ${SOURCE_FILES})
set_target_properties(umqtt PROPERTIES VERSION ${UMQTT_VERSION_MAJOR}.${UMQTT_VERSION_MINOR}.${UMQTT_VERSION_PATCH})
target_link_libraries(umqtt ${EXTRA_LIBS})

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

install(
    FILES
	    ${CMAKE_CURRENT_BINARY_DIR}/config.h
	    ${CMAKE_CURRENT_SOURCE_DIR}/umqtt.h
    DESTINATION
    	include/umqtt
)

install(
    TARGETS umqtt LIBRARY
    DESTINATION lib
)

message("")
message(STATUS "UMQTT_VERSION: ${UMQTT_VERSION_MAJOR}.${UMQTT_VERSION_MINOR}.${UMQTT_VERSION_PATCH}")
message(STATUS "UMQTT_SSL_SUPPORT: ${UMQTT_SSL_SUPPORT}")
message("")
