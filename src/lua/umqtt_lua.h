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

#ifndef __UMQTT_LUA_H
#define __UMQTT_LUA_H

#include <lauxlib.h>
#include <lualib.h>

#include "umqtt.h"

/* Compatibility defines */
#if LUA_VERSION_NUM <= 501

/* NOTE: this only works if nups == 0! */
#define luaL_setfuncs(L, fns, nups) luaL_register((L), NULL, (fns))

#endif

struct umqtt_client_lua {
    lua_State *L;

    struct umqtt_client cli;
    struct umqtt_connect_opts opts;
    bool connected;

    int on_conack_ref;
    int on_suback_ref;
    int on_unsuback_ref;
    int on_publish_ref;
    int on_pingresp_ref;
    int on_error_ref;
    int on_close_ref;
};

#endif