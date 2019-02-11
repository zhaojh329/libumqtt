/*
 * Copyright (c) 2018 Petr Stetiar <ynezz@true.cz>
 *
 * SPDX-License-Identifier: LGPL-2.1 OR MIT OR Apache-2.0
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <lauxlib.h>

#include <libubox/utils.h>
#include <libubox/ulog.h>

#include "umqtt.h"

#define RECONNECT_INTERVAL 5

#define MODNAME "umqtt"
#define METANAME MODNAME ".meta"

#define LUA_TPUSH_STR(L, s, v) do { \
	lua_pushstring(L, s); \
	lua_pushstring(L, v); \
	lua_rawset(L, -3); \
} while (0);

#define LUA_TPUSH_NUM(L, s, v) do { \
	lua_pushstring(L, s); \
	lua_pushnumber(L, v); \
	lua_rawset(L, -3); \
} while (0);

struct umqtt_t {
	lua_State *L;
	bool connected;
	bool initialized;

	int port;
	const char *host;

	bool ssl_verify;
	bool ssl_enable;
	const char *ssl_crt_file;

	int ping_interval;
	int retry_interval;
	int reconnect_interval;

	struct umqtt_will will;
	struct umqtt_options options;
	struct umqtt_client client;
	struct uloop_timeout reconnect_timer;

	int on_conack_cb;
	int on_suback_cb;
	int on_publish_cb;
	int on_error_cb;
	int on_pong_cb;
	int on_close_cb;
	int on_reconnect_cb;
};

struct rcode_t {
	char *name;
	enum umqtt_return_code code;
} rcode_table[] = {
	{ "CONNECTION_ACCEPTED", UMQTT_CONNECTION_ACCEPTED },
	{ "UNACCEPTABLE_PROTOCOL", UMQTT_UNACCEPTABLE_PROTOCOL },
	{ "IDENTIFIER_REJECTED", UMQTT_IDENTIFIER_REJECTED },
	{ "SERVER_UNAVAILABLE", UMQTT_SERVER_UNAVAILABLE },
	{ "BAD_USERNAME_OR_PASSWORD", UMQTT_BAD_USERNAME_OR_PASSWORD },
	{ "NOT_AUTHORIZED", UMQTT_NOT_AUTHORIZED },
	{ NULL, 0 },
};

struct ecode_t {
	char *name;
	enum umqtt_error_code code;
} ecode_table[] = {
	{ "UMQTT_ERROR_WRITE", UMQTT_ERROR_WRITE },
	{ "UMQTT_ERROR_SSL", UMQTT_ERROR_SSL },
	{ "UMQTT_ERROR_SSL_INVALID_CERT", UMQTT_ERROR_SSL_INVALID_CERT },
	{ "UMQTT_ERROR_SSL_CN_MISMATCH", UMQTT_ERROR_SSL_CN_MISMATCH },
	{ "UMQTT_REMAINING_LENGTH_MISMATCH", UMQTT_REMAINING_LENGTH_MISMATCH },
	{ "UMQTT_REMAINING_LENGTH_OVERFLOW", UMQTT_REMAINING_LENGTH_OVERFLOW },
	{ "UMQTT_INVALID_PACKET", UMQTT_INVALID_PACKET },
	{ NULL, 0 },
};

static int umqtt_lua_return_code_string(lua_State *L)
{
	enum umqtt_return_code code = luaL_checkint(L, -1);

	for (struct rcode_t *rc = rcode_table; rc->name != NULL; rc++) {
		if (code == rc->code) {
			lua_pushstring(L, rc->name);
			return 1;
		}
	}

	lua_pushfstring(L, "unknown code: %d", code);
	return 1;
}

static int umqtt_lua_error_code_string(lua_State *L)
{
	enum umqtt_error_code code = luaL_checkint(L, -1);

	for (struct ecode_t *ec = ecode_table; ec->name != NULL; ec++) {
		if (code == ec->code) {
			lua_pushstring(L, ec->name);
			return 1;
		}
	}

	lua_pushfstring(L, "unknown code: %d", code);
	return 1;
}

static bool lua_topt_bool(lua_State *L, int t, const char *k, bool def)
{
	bool r = def;

	lua_getfield(L, t, k);
	if (lua_isboolean(L, -1))
		r = lua_toboolean(L, -1);
	lua_pop(L, 1);

	return r;
}

static const char* lua_topt_string(lua_State *L, int t, const char *k, const char *def)
{
	const char *r = def;

	lua_getfield(L, t, k);
	if (lua_isstring(L, -1))
		r = lua_tostring(L, -1);
	lua_pop(L, 1);

	return r;
}

static const char* lua_tcheck_string(lua_State *L, int t, const char *k)
{
	const char *r = NULL;

	lua_getfield(L, t, k);
	r = luaL_checkstring(L, -1);
	lua_pop(L, 1);

	return r;
}

static int lua_topt_int(lua_State *L, int t, const char *k, int def)
{
	int r = def;

	lua_getfield(L, t, k);
	r = luaL_optint(L, -1, def);
	lua_pop(L, 1);

	return r;
}

static void lua_push_constants(lua_State *L)
{
	for (struct rcode_t *rc = rcode_table; rc->name != NULL; rc++)
		LUA_TPUSH_NUM(L, rc->name, rc->code);

	for (struct ecode_t *ec = ecode_table; ec->name != NULL; ec++)
		LUA_TPUSH_NUM(L, ec->name, ec->code);
}

static const char* umqtt_tostring(struct umqtt_t *c)
{
	static char buf[512] = {0};

	snprintf(buf, sizeof(buf),
		"host: '%s' port: %d ssl_enable: %d ssl_verify: %d ssl_crt_file: '%s' "
		"client_id: '%s' username: '%s' password: '%s' clean_session: %d "
		"w.retain: %d w.topic: %s: w.payload: '%s' w.qos: %d "
		"retry_interval: %ds ping_interval: %ds reconnect_interval: %ds",
		c->host, c->port, c->ssl_enable, c->ssl_verify, c->ssl_crt_file,
		c->options.client_id, c->options.username, c->options.password,
		c->options.clean_session, c->will.retain, c->will.topic,
		c->will.payload, c->will.qos, c->retry_interval, c->ping_interval,
		c->reconnect_interval);

	return buf;
}

static int umqtt_lua_tostring(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);
	lua_pushstring(L, umqtt_tostring(u));
	return 1;
}

static void on_conack(struct umqtt_client *cl, bool sp, enum umqtt_return_code code)
{
    	struct umqtt_t *u = container_of(cl, struct umqtt_t, client);

	u->connected = true;
	uloop_timeout_cancel(&u->reconnect_timer);

	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_conack_cb);
	if (!lua_isfunction(u->L, -1))
		return;

	lua_pushboolean(u->L, sp);
	lua_pushinteger(u->L, code);
	lua_call(u->L, 2, 0);
}

static void on_suback(struct umqtt_client *cl, uint16_t mid, uint8_t *granted_qos, int qos_count)
{
	struct umqtt_t *u = container_of(cl, struct umqtt_t, client);

	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_suback_cb);
	if (!lua_isfunction(u->L, -1))
		return;

	lua_pushnumber(u->L, mid);
	for (int i = 0; i < qos_count; i++)
		lua_pushinteger(u->L, granted_qos[i]);
	lua_call(u->L, qos_count+1, 0);
}

static void on_publish(struct umqtt_client *cl, struct umqtt_message *msg)
{
	struct umqtt_t *u = container_of(cl, struct umqtt_t, client);

	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_publish_cb);
	if (!lua_isfunction(u->L, -1))
		return;

	lua_newtable(u->L);
	
	lua_pushinteger(u->L, msg->mid);
	lua_setfield(u->L, -2, "mid");
	
	lua_pushinteger(u->L, msg->dup);
	lua_setfield(u->L, -2, "dup");

	lua_pushinteger(u->L, msg->qos);
	lua_setfield(u->L, -2, "qos");

	lua_pushinteger(u->L, msg->retain);
	lua_setfield(u->L, -2, "retain");

	lua_pushstring(u->L, msg->topic);
	lua_setfield(u->L, -2, "topic");

	lua_pushlstring(u->L, msg->payload, msg->payloadlen);
	lua_setfield(u->L, -2, "payload");

	lua_call(u->L, 1, 0);
}

static void on_error(struct umqtt_client *cl)
{
	struct umqtt_t *u = container_of(cl, struct umqtt_t, client);

	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_error_cb);
	if (!lua_isfunction(u->L, -1))
		return;

	lua_pushinteger(u->L, cl->error);
	lua_call(u->L, 1, 0);
}

static void on_pong(struct umqtt_client *cl)
{
	struct umqtt_t *u = container_of(cl, struct umqtt_t, client);

	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_pong_cb);
	if (!lua_isfunction(u->L, -1))
		return;

	lua_call(u->L, 0, 0);
}

static void on_reconnect(struct umqtt_t *u)
{
	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_reconnect_cb);
	if (!lua_isfunction(u->L, -1))
		return;

	lua_call(u->L, 0, 0);
}

static void client_set_options(lua_State *L, struct umqtt_t *u)
{
	u->L = L;
	u->host = strdup(lua_tcheck_string(L, 1, "host"));
	u->port = lua_topt_int(L, 1, "port", 1883);
	
	lua_getfield(L, 1, "ssl");
	if (lua_istable(L, -1)) {
		u->ssl_enable = true;
		u->ssl_crt_file = strdup(lua_tcheck_string(L, -1, "cert_file"));
		u->ssl_verify = lua_topt_bool(L, -1, "verify", true);
	}
	lua_pop(L, 1);

	lua_getfield(L, 1, "will");
	if (lua_istable(L, -1)) {
		u->will.topic = strdup(lua_tcheck_string(L, -1, "topic"));
		u->will.payload = strdup(lua_tcheck_string(L, -1, "payload"));
		u->will.retain = lua_topt_bool(L, -1, "retain", false);
		u->will.qos = lua_topt_int(L, -1, "qos", 0);
	}
	lua_pop(L, 1);

	u->options.client_id = strdup(lua_topt_string(L, 1, "client_id", "umqtt-Lua-client"));
	u->options.username = strdup(lua_topt_string(L, 1, "username", NULL));
	u->options.password = strdup(lua_topt_string(L, 1, "password", NULL));
	u->options.clean_session = lua_topt_bool(L, 1, "clean_session", false);
	u->ping_interval = lua_topt_int(L, 1, "ping_interval", UMQTT_PING_INTERVAL);
	u->retry_interval = lua_topt_int(L, 1, "retry_interval", UMQTT_RETRY_INTERVAL);
	u->reconnect_interval = lua_topt_int(L, 1, "reconnect_interval", RECONNECT_INTERVAL);
}

static void on_close(struct umqtt_client *cl);
static int client_init_connect(struct umqtt_t *u, lua_State *L)
{
	int r = 0;

	r = umqtt_new_ssl(&u->client, u->host, u->port, u->ssl_enable, u->ssl_crt_file, u->ssl_verify);
	if (r < 0) {
		if (L) {
			lua_pushnil(L);
			lua_pushfstring(L, "umqtt_new_ssl() failed: %d", r);
		}

		return 2;
	}

	u->initialized = true;
        u->client.on_pong = on_pong;
        u->client.on_error = on_error;
        u->client.on_close = on_close;
        u->client.on_conack = on_conack;
        u->client.on_suback = on_suback;
        u->client.on_publish = on_publish;
	u->client.ping_timer_interval = u->ping_interval;
	u->client.retry_timer_interval = u->retry_interval;

	r = u->client.connect(&u->client, &u->options, &u->will);
        if (r < 0) {
		if (L) {
			lua_pushnil(L);
			lua_pushfstring(L, "umqtt_connect() failed: %d", r);
		}

		return 2;
	}

	return 0;
}

static void client_disconnect(struct umqtt_t *u)
{
	if (!u->connected)
		return;

	u->client.disconnect(&u->client);
	u->connected = false;
}

static void client_free(struct umqtt_t *u)
{
	if (!u->initialized)
		return;

	u->client.free(&u->client);
	u->initialized = false;
}

static void reconnect_timer_cb(struct uloop_timeout *t)
{
	struct umqtt_t *u = container_of(t, struct umqtt_t, reconnect_timer);

	on_reconnect(u);
	client_disconnect(u);
	client_free(u);

	client_init_connect(u, NULL);
	uloop_timeout_set(&u->reconnect_timer, u->reconnect_interval * 1000);
}

static void client_try_reconnect(struct umqtt_t *u)
{
	if (u->reconnect_interval == 0)
		return;

	u->reconnect_timer.cb = reconnect_timer_cb;
	uloop_timeout_set(&u->reconnect_timer, 100);
}

static void on_close(struct umqtt_client *cl)
{
	struct umqtt_t *u = container_of(cl, struct umqtt_t, client);

	lua_rawgeti(u->L, LUA_REGISTRYINDEX, u->on_close_cb);
	if (!lua_isfunction(u->L, -1))
		return;
	
	client_try_reconnect(u);
	lua_pushboolean(u->L, u->reconnect_interval > 0 ? true : false);
	lua_call(u->L, 1, 0);
}

static int umqtt_lua_connect(lua_State *L)
{
	int r = 0;
	struct umqtt_t *u = NULL;

	luaL_checktype(L, 1, LUA_TTABLE);

	u = lua_newuserdata(L, sizeof(*u));
	if (u == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, "lua_newuserdata() failed");
		return 2;
	}

	memset(u, 0, sizeof(*u));
	client_set_options(L, u);

	r = client_init_connect(u, L);
	if (r > 0) {
		if (u->reconnect_interval == 0)
			return r;

		lua_pop(L, r);
		client_try_reconnect(u);
	}

	luaL_getmetatable(L, METANAME);
	lua_setmetatable(L, -2);
	return 1;
}

static int umqtt_lua_disconnect(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);
	client_disconnect(u);
	return 0;
}

static int umqtt_lua_gc(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	client_disconnect(u);
	client_free(u);

	return 0;
}

static int umqtt_lua_on_conack(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");

	u->on_conack_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int umqtt_lua_on_suback(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");

	u->on_suback_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int umqtt_lua_on_publish(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");

	u->on_publish_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int umqtt_lua_on_pong(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");

	u->on_pong_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int umqtt_lua_on_close(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");	

	u->on_close_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int umqtt_lua_on_error(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");

	u->on_error_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int umqtt_lua_on_reconnect(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!lua_isfunction(L, 2))
		return luaL_argerror(L, 2, "provide callback function");

	u->on_reconnect_cb = luaL_ref(L, LUA_REGISTRYINDEX);
	return 0;
}

static int lua_table_size(lua_State *L)
{
	int size = 0;

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		size++;
		lua_pop(L, 1);
	}

	return size;
}

static int umqtt_lua_subscribe(lua_State *L)
{
	int r = 0;
	int i = 0;
	int tsize = 0;
	struct umqtt_topic *topics = NULL;
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!u->connected) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "not connected");
		return 2;
	}

	if (!lua_istable(L, 2))
		return luaL_argerror(L, 2, "provide table with topics");

	tsize = lua_table_size(L);
	topics = calloc(tsize, sizeof(*topics));

	if (tsize == 0) {
		lua_pushnumber(L, tsize);
		lua_pushnil(L);
		return 2;
	}

	lua_pushnil(L);
	while (lua_next(L, -2)) {
		struct umqtt_topic *t = &topics[i];

		if (!lua_istable(L, -1))
			return luaL_argerror(L, i, "topic should be table");

		t->qos = lua_topt_int(L, -1, "qos", 0);

		lua_getfield(L, -1, "topic");
		t->topic = (char *) luaL_checklstring(L, -1, (size_t *) &t->len);
		lua_pop(L, 1);

		lua_pop(L, 1);
		i++;
	}

	r = u->client.subscribe(&u->client, topics, tsize);
	if (r < 0) {
		lua_pushboolean(L, false);
		lua_pushfstring(L, "umqtt_subscribe() failed: %d", r);
		return 2;
	}

	lua_pushboolean(L, true);
	return 1;
}

static int umqtt_lua_publish(lua_State *L)
{
	int r = 0;
	uint8_t qos = 0;
	bool retain = false;
	size_t payloadlen = 0;
	const char *topic = NULL;
	const char *payload = NULL;
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);

	if (!u->connected) {
		lua_pushboolean(L, false);
		lua_pushstring(L, "not connected");
		return 2;
	}

	if (!lua_istable(L, 2))
		return luaL_argerror(L, 2, "provide table with topics");

	qos = lua_topt_int(L, 2, "qos", 0);
	retain = lua_topt_bool(L, 2, "retain", false);
	topic = lua_tcheck_string(L, 2, "topic");

	lua_getfield(L, 2, "payload");
	payload = (char *) luaL_checklstring(L, -1, &payloadlen);
	lua_pop(L, 1);

	r = u->client.publish(&u->client, topic, payloadlen, payload, qos, retain);
	if (r < 0) {
		lua_pushboolean(L, false);
		lua_pushfstring(L, "%d", r);
		return 2;
	}

	lua_pushboolean(L, true);
	return 1;
}

static int umqtt_lua_is_connected(lua_State *L)
{
	struct umqtt_t *u = luaL_checkudata(L, 1, METANAME);
	lua_pushboolean(L, u->connected);
	return 1;
}

static const luaL_Reg umqtt[] = {
	{ "connect", umqtt_lua_connect },
	{ "disconnect", umqtt_lua_disconnect },
	{ "subscribe", umqtt_lua_subscribe },
	{ "publish", umqtt_lua_publish },
	{ "on_connection", umqtt_lua_on_conack },
	{ "on_subscribe", umqtt_lua_on_suback },
	{ "on_publish", umqtt_lua_on_publish },
	{ "on_pong", umqtt_lua_on_pong },
	{ "on_close", umqtt_lua_on_close },
	{ "on_error", umqtt_lua_on_error },
	{ "on_reconnect", umqtt_lua_on_reconnect },
	{ "is_connected", umqtt_lua_is_connected },
	{ "error_code_string", umqtt_lua_error_code_string },
	{ "return_code_string", umqtt_lua_return_code_string },
	{ "__gc", umqtt_lua_gc },
	{ "__tostring", umqtt_lua_tostring },
	{ NULL, NULL },
};

int luaopen_umqtt(lua_State *L)
{
	/* create metatable */
	luaL_newmetatable(L, METANAME);

	/* metatable.__index = metatable */
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");

	/* fill metatable */
	luaL_register(L, NULL, umqtt);
	lua_pop(L, 1);

	/* create module */
	luaL_register(L, MODNAME, umqtt);
	lua_push_constants(L);
	LUA_TPUSH_STR(L, "_VERSION", UMQTT_VERSION_STRING);

	return 0;
}
