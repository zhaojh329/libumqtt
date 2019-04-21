find_package(Lua)

set(UMQTT_LUA_SUPPORT_DEFAULT "ON")

if (NOT LUA_FOUND)
	set(BUILD_LUA_DEFAULT "OFF")
endif (NOT LUA_FOUND)

option(UMQTT_LUA_SUPPORT "Enable build of Lua module" ${UMQTT_LUA_SUPPORT_DEFAULT})

if(UMQTT_LUA_SUPPORT)
	include_directories(${LUA_INCLUDE_DIR})

	add_library(umqtt-lua MODULE umqtt_lua.c)
	set_target_properties(umqtt-lua PROPERTIES OUTPUT_NAME umqtt PREFIX "")

	target_link_libraries(umqtt-lua umqtt)

	install(TARGETS umqtt-lua
		LIBRARY DESTINATION lib/lua/${LUA_VERSION_MAJOR}.${LUA_VERSION_MINOR}
	)
endif(UMQTT_LUA_SUPPORT)
