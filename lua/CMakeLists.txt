cmake_minimum_required(VERSION 2.8)

project(umqtt-lua C)

if(NOT LUA_CFLAGS)
	include(FindPkgConfig)
	pkg_search_module(LUA lua5.1 lua-5.1)
endif()

find_package(Libumqtt REQUIRED)
include_directories(${LIBUMQTT_INCLUDE_DIR})
add_definitions(${LUA_CFLAGS})

if(NOT LUAPATH)
	execute_process(
		COMMAND  lua -e "for k in string.gmatch(package.cpath .. \";\", \"([^;]+)/..so;\") do if k:sub(1,1) == \"/\" then print(k) break end end"
		OUTPUT_VARIABLE LUAPATH
		RESULT_VARIABLE LUA_CHECK_RES
		OUTPUT_STRIP_TRAILING_WHITESPACE
	)

	if(NOT ${LUA_CHECK_RES} EQUAL 0 OR "${LUAPATH}" EQUAL "")
		message(FATAL_ERROR "Lua was not found on your system")
	endif()
endif()

add_library(umqtt-lua MODULE umqtt-lua.c)
set_target_properties(umqtt-lua PROPERTIES
	OUTPUT_NAME umqtt
	PREFIX ""
)
target_link_libraries(umqtt-lua ${LIBUMQTT_LIBRARY} ${LIBUBOX_LIBRARY})

install(TARGETS umqtt-lua
	LIBRARY DESTINATION ${LUAPATH}
)
