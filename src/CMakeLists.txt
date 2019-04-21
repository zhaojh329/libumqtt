add_definitions(-O -Wall -Werror --std=gnu99 -D_GNU_SOURCE -Wno-misleading-indentation)

# The version number.
set(UMQTT_VERSION_MAJOR 0)
set(UMQTT_VERSION_MINOR 1)
set(UMQTT_VERSION_PATCH 0)

# Check the third party Libraries
find_package(Libev REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR} ${LIBEV_INCLUDE_DIR})

set(EXTRA_LIBS ${LIBEV_LIBRARY} dl)
set(SOURCE_FILES umqtt.c log.c utils.c buffer.c ssl.c)

set(UMQTT_SSL_SUPPORT_CONFIG 1)
option(UMQTT_SSL_SUPPORT "SSL support" ON)

option(UMQTT_USE_OPENSSL "Force select OpenSSL" OFF)
option(UMQTT_USE_WOLFSSL "Force select WolfSSL(CyaSSL)" OFF)
option(UMQTT_USE_MBEDTLS "Force select MbedTLS(PolarSSL)" OFF)

set(SSL_NAME OFF)
set(UMQTT_HAVE_OPENSSL_CONFIG 0)
set(UMQTT_HAVE_WOLFSSL_CONFIG 0)
set(UMQTT_HAVE_MBEDTLS_CONFIG 0)

if(NOT UMQTT_SSL_SUPPORT)
    set(UMQTT_SSL_SUPPORT_CONFIG 0)
else()
    find_package(OpenSSL)
    find_package(WolfSSL)
    find_package(MbedTLS)

    if(UMQTT_USE_OPENSSL)
        if (NOT OPENSSL_FOUND)
            set(UMQTT_SSL_SUPPORT OFF)
            message(WARNING "Force select OpenSSL, but not found it")
        endif()
    elseif(UMQTT_USE_WOLFSSL)
        if (NOT WOLFSSL_FOUND)
            set(UMQTT_SSL_SUPPORT OFF)
            message(WARNING "Force select WolfSSL(CyaSSL), but not found it")
        endif()
    elseif(UMQTT_USE_MBEDTLS)
        if (NOT MBEDTLS_FOUND)
            set(UMQTT_SSL_SUPPORT OFF)
            message(WARNING "Force select MbedTLS(PolarSSL), but not found it")
        endif()
    elseif(OPENSSL_FOUND)
        set(UMQTT_USE_OPENSSL ON)
    elseif(WOLFSSL_FOUND)
        set(UMQTT_USE_WOLFSSL ON)
    elseif(MBEDTLS_FOUND)
        set(UMQTT_USE_MBEDTLS ON)
    else()
        set(UMQTT_SSL_SUPPORT OFF)
        message(WARNING "No available SSL libraries found")
    endif()

    if(UMQTT_USE_OPENSSL)
        set(SSL_NAME "OpenSSL")
        set(SSL_INC ${OPENSSL_INCLUDE_DIR})
        set(SSL_LIB ${OPENSSL_LIBRARIES})
        set(UMQTT_HAVE_OPENSSL_CONFIG 1)
    elseif(UMQTT_USE_WOLFSSL)
        set(SSL_NAME "WolfSSL(CyaSSL)")
        set(SSL_INC ${WOLFSSL_INCLUDE_DIR})
        set(SSL_LIB ${WOLFSSL_LIBRARIES})
        set(UMQTT_HAVE_WOLFSSL_CONFIG 1)
    elseif(UMQTT_USE_MBEDTLS)
        set(SSL_NAME "MbedTLS(PolarSSL)")
        set(SSL_INC ${MBEDTLS_INCLUDE_DIR})
        set(SSL_LIB ${MBEDTLS_LIBRARIES})
        set(UMQTT_HAVE_MBEDTLS_CONFIG 1)
    endif()

    if(UMQTT_SSL_SUPPORT)
        include_directories(${SSL_INC})
        list(APPEND EXTRA_LIBS ${SSL_LIB})
        message(STATUS "Select ${SSL_NAME} as the SSL backend")
    else()
        set(SSL_NAME OFF)
        set(UMQTT_SSL_SUPPORT_CONFIG 0)
    endif()
endif()

add_library(umqtt SHARED ${SOURCE_FILES})
set_target_properties(umqtt PROPERTIES VERSION ${UMQTT_VERSION_MAJOR}.${UMQTT_VERSION_MINOR}.${UMQTT_VERSION_PATCH})
target_link_libraries(umqtt ${EXTRA_LIBS})

# configure a header file to pass some of the CMake settings to the source code
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

add_subdirectory(lua)

install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/log.h
        ${CMAKE_CURRENT_SOURCE_DIR}/ssl.h
        ${CMAKE_CURRENT_SOURCE_DIR}/umqtt.h
        ${CMAKE_CURRENT_SOURCE_DIR}/utils.h
        ${CMAKE_CURRENT_SOURCE_DIR}/buffer.h
        ${CMAKE_CURRENT_BINARY_DIR}/config.h
    DESTINATION
        include/umqtt
)

install(
    TARGETS umqtt LIBRARY
    DESTINATION lib
)

message(STATUS "UMQTT_VERSION: ${UMQTT_VERSION_MAJOR}.${UMQTT_VERSION_MINOR}.${UMQTT_VERSION_PATCH}")
message(STATUS "UMQTT_SSL_SUPPORT: ${SSL_NAME}")

