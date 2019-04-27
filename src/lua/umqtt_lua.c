/*
 * Copyright (c) 2018 Petr Stetiar <ynezz@true.cz>
 * Copyright (C) 2019 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 * USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "umqtt_lua.h"

#define UMQTT_MT "uqmtt"

/* https://github.com/brimworks/lua-ev/blob/master/lua_ev.h#L33 */
#define EV_LOOP_MT    "ev{loop}"
#define EV_UNINITIALIZED_DEFAULT_LOOP (struct ev_loop *)1

static int umqtt_lua_version(lua_State *L)
{
    lua_pushinteger(L, UMQTT_VERSION_MAJOR);
    lua_pushinteger(L, UMQTT_VERSION_MINOR);
    lua_pushinteger(L, UMQTT_VERSION_PATCH);

    return 3;
}

static int umqtt_lua_return_code_string(lua_State *L)
{
	int code = luaL_checkint(L, -1);

#define CODE2S(x) case x: lua_pushstring(L, (#x) + 6); break;
    switch (code) {
    CODE2S(UMQTT_CONNECTION_ACCEPTED)
    CODE2S(UMQTT_UNACCEPTABLE_PROTOCOL)
    CODE2S(UMQTT_IDENTIFIER_REJECTED)
    CODE2S(UMQTT_SERVER_UNAVAILABLE)
    CODE2S(UMQTT_BAD_USERNAME_OR_PASSWORD)
    CODE2S(UMQTT_NOT_AUTHORIZED)
    default:
        lua_pushfstring(L, "Unknown return code: %d", code);
    }
#undef CODE2S
	
	return 1;
}

static void on_conack(struct umqtt_client *cli, bool sp, int code)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;

    cl->connected = true;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_conack_ref);
	if (!lua_isfunction(L, -1))
		return;
    
    lua_pushboolean(L, sp);
	lua_pushinteger(L, code);
    lua_call(L, 2, 0);
}

static void on_suback(struct umqtt_client *cli, uint8_t *granted_qos, int qos_count)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;
    int i;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_suback_ref);
	if (!lua_isfunction(L, -1))
		return;
    
    lua_newtable(L);

    for (i = 0; i < qos_count; i++) {
        lua_pushinteger(L, granted_qos[i]);
        lua_rawseti(L, -2, i + 1);
    }

    lua_call(L, 1, 0);
}

static void on_unsuback(struct umqtt_client *cli)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_unsuback_ref);
	if (!lua_isfunction(L, -1))
		return;
    
    lua_call(L, 0, 0);
}

static void on_publish(struct umqtt_client *cli, const char *topic, int topic_len,
    const void *payload, int payloadlen)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_publish_ref);
	if (!lua_isfunction(L, -1))
		return;
    
    lua_pushlstring(L, topic, topic_len);
    lua_pushlstring(L, payload, payloadlen);

    lua_call(L, 2, 0);
}

static void on_pingresp(struct umqtt_client *cli)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_pingresp_ref);
	if (!lua_isfunction(L, -1))
		return;

    lua_call(L, 0, 0);
}

static void on_error(struct umqtt_client *cli, int err, const char *msg)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;

    cl->connected = false;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_error_ref);
	if (!lua_isfunction(L, -1))
		return;

    lua_pushinteger(L, err);
    lua_pushstring(L, msg);

    lua_call(L, 2, 0);
}

static void on_close(struct umqtt_client *cli)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);
    lua_State *L = cl->L;

    cl->connected = false;

    lua_rawgeti(L, LUA_REGISTRYINDEX, cl->on_close_ref);
	if (!lua_isfunction(L, -1))
		return;

    lua_call(L, 0, 0);
}

static void on_net_connected(struct umqtt_client *cli)
{
    struct umqtt_client_lua *cl = container_of(cli, struct umqtt_client_lua, cli);

    if (cli->connect(cli, &cl->opts) < 0)
        ev_break(cli->loop, EVBREAK_ALL);
}

static const char *get_opt_string(lua_State *L, int index, const char *key)
{
    const char *value;

    lua_getfield(L, index, key);
    value = lua_tostring(L, -1);

    if (value)
        return strdup(value);
    return NULL;
}

static bool get_opt_boolean(lua_State *L, int index, const char *key)
{
    lua_getfield(L, index, key);
    return lua_toboolean(L, -1);
}

static int get_opt_integer(lua_State *L, int index, const char *key)
{
    lua_getfield(L, index, key);
    return lua_tointeger(L, -1);
}

static void parse_options(lua_State *L, const char **host, int *port, bool *ssl, struct umqtt_connect_opts *opts)
{
    lua_getfield(L, 1, "host");
    *host = lua_tostring(L, -1);
    *port = get_opt_integer(L, 1, "port");
    *ssl = get_opt_boolean(L, 1, "ssl");

    opts->clean_session = get_opt_boolean(L, 1, "clean_session");
    opts->keep_alive = get_opt_integer(L, 1, "keep_alive");
    opts->client_id = get_opt_string(L, 1, "client_id");
    opts->username = get_opt_string(L, 1, "username");
    opts->password = get_opt_string(L, 1, "password");

    lua_pop(L, 8);

    lua_getfield(L, 1, "will");
    if (lua_istable(L, -1)) {
        opts->will_topic = get_opt_string(L, 3, "topic");
        opts->will_message = get_opt_string(L, 3, "message");
        opts->will_qos = get_opt_integer(L, -3, "qos");
        opts->will_retain = get_opt_boolean(L, 1, "retain");
        lua_pop(L, 5);
    }
}

static int umqtt_lua_connect(lua_State *L)
{
    struct ev_loop *loop = NULL;
    struct umqtt_client_lua *cl;
    const char *host;
    bool ssl;
    int port;

    luaL_checktype(L, 1, LUA_TTABLE);

    if (lua_gettop(L) > 1) {
        struct ev_loop **tmp = luaL_checkudata(L, 2, EV_LOOP_MT);
        if (*tmp != EV_UNINITIALIZED_DEFAULT_LOOP)
            loop = *tmp;
    }

    cl = lua_newuserdata(L, sizeof(struct umqtt_client_lua));
    if (!cl) {
        lua_pushnil(L);
        lua_pushstring(L, "lua_newuserdata() failed");
        return 2;
    }

	memset(cl, 0, sizeof(struct umqtt_client_lua));

	luaL_getmetatable(L, UMQTT_MT);
	lua_setmetatable(L, -2);

    parse_options(L, &host, &port, &ssl, &cl->opts);

    if (umqtt_init(&cl->cli, loop, host, port, ssl) < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "umqtt_init() failed");
        return 2;
    }

    cl->L = L;
    cl->cli.on_net_connected = on_net_connected;
    cl->cli.on_conack = on_conack;
    cl->cli.on_suback = on_suback;
    cl->cli.on_unsuback = on_unsuback;
    cl->cli.on_publish = on_publish;
    cl->cli.on_pingresp = on_pingresp;
    cl->cli.on_error = on_error;
    cl->cli.on_close = on_close;

	return 1;
}

static int umqtt_lua_on(lua_State *L)
{
    struct umqtt_client_lua *cl = luaL_checkudata(L, 1, UMQTT_MT);
    const char *name = luaL_checkstring(L, 2);
    int ref;

    luaL_checktype(L, 3, LUA_TFUNCTION);

    ref = luaL_ref(L, LUA_REGISTRYINDEX);

    if (!strcmp(name, "conack"))
        cl->on_conack_ref = ref;
    else if (!strcmp(name, "suback"))
        cl->on_suback_ref = ref;
    else if (!strcmp(name, "unsuback"))
        cl->on_unsuback_ref = ref;
    else if (!strcmp(name, "publish"))
        cl->on_publish_ref = ref;
    else if (!strcmp(name, "pingresp"))
        cl->on_pingresp_ref = ref;
    else if (!strcmp(name, "error"))
        cl->on_error_ref = ref;
    else if (!strcmp(name, "close"))
        cl->on_close_ref = ref;
    else
        luaL_argcheck(L, false, 2, "available event name: conack suback unsuback publish pingresp error close");    

	return 0;
}

static int umqtt_lua_publish(lua_State *L)
{
    struct umqtt_client_lua *cl = luaL_checkudata(L, 1, UMQTT_MT);
    const char *topic;
    size_t payloadlen;
    const char *payload;
    int qos = UMQTT_QOS0;
    bool retain = false;

    if (!cl->connected) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "not connected");
		return 2;
	}

    topic = luaL_checkstring(L, 2);
    payload = luaL_checklstring(L, 3, &payloadlen);

    if (!lua_isnil(L, 4)) {
        luaL_checktype(L, 4, LUA_TTABLE);

        lua_getfield(L, 4, "qos");
        if (!lua_isnil(L, -1))
            qos = lua_tointeger(L, -1);
        
        lua_getfield(L, 4, "retain");
        retain = lua_toboolean(L, -1);
    }

    cl->cli.publish(&cl->cli, topic, payload, payloadlen, qos, retain);

    return 0;
}

static int umqtt_lua_subscribe(lua_State *L)
{
    struct umqtt_client_lua *cl = luaL_checkudata(L, 1, UMQTT_MT);
    struct umqtt_topic *topics;
    int n = lua_gettop(L) - 1;
    int i;

    if (!cl->connected) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "not connected");
		return 2;
	}

    if (n < 1) {
        lua_pushboolean(L, true);
        return 1;
    }

    topics = calloc(n, sizeof(struct umqtt_topic));

    for (i = 0; i < n; i++) {
        struct umqtt_topic *t = &topics[i];

        luaL_checktype(L, i + 2, LUA_TTABLE);

        lua_getfield(L, i + 2, "topic");
        if (!lua_isstring(L, -1))
            luaL_argerror(L, i + 2, "topic field represented by a string expected, got nil");
        t->topic = lua_tostring(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, i + 2, "qos");
        t->qos = lua_tointeger(L, -1);
        lua_pop(L, 1);
    }

    cl->cli.subscribe(&cl->cli, topics, n);

    free(topics);

    lua_pushboolean(L, true);
    return 1;
}

static int umqtt_lua_unsubscribe(lua_State *L)
{
    struct umqtt_client_lua *cl = luaL_checkudata(L, 1, UMQTT_MT);
    const char **topics;
    int n = lua_gettop(L) - 1;
    int i;

    if (!cl->connected) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "not connected");
		return 2;
	}

    if (n < 1) {
        lua_pushboolean(L, true);
        return 1;
    }

    topics = calloc(n, sizeof(char *));

    for (i = 0; i < n; i++)
        topics[i] = luaL_checkstring(L, i + 2);

    cl->cli.unsubscribe(&cl->cli, topics, n);

    free(topics);

    lua_pushboolean(L, true);
    return 1;

}

static int umqtt_lua_gc(lua_State *L)
{
	struct umqtt_client_lua *cl = luaL_checkudata(L, 1, UMQTT_MT);

    if (cl->connected) {
        struct umqtt_connect_opts *opts = &cl->opts;

        cl->cli.disconnect(&cl->cli);
        cl->connected = false;

        if (opts->client_id)
            free((char *)opts->client_id);
        if (opts->username)
            free((char *)opts->username);
        if (opts->password)
            free((char *)opts->password);
        if (opts->will_topic)
            free((char *)opts->will_topic);
        if (opts->will_message)
            free((char *)opts->will_message);

        cl->cli.free(&cl->cli);
    }

    return 0;
}

static const luaL_Reg umqtt_meta[] = {
    {"on", umqtt_lua_on},
    {"publish", umqtt_lua_publish},
    {"subscribe", umqtt_lua_subscribe},
    {"unsubscribe", umqtt_lua_unsubscribe},
    {"__gc", umqtt_lua_gc},
	{NULL, NULL}
};

static const luaL_Reg umqtt_fun[] = {
    {"connect", umqtt_lua_connect},
    {"version", umqtt_lua_version},
    {"return_code_string", umqtt_lua_return_code_string},
    {NULL, NULL}
};

int luaopen_umqtt(lua_State *L)
{
    /* metatable.__index = metatable */
    luaL_newmetatable(L, UMQTT_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, umqtt_meta, 0);

    lua_newtable(L);
    luaL_setfuncs(L, umqtt_fun, 0);

    return 1;
}
