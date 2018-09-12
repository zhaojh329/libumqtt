/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
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

#ifndef _UMQTT_SSL_H
#define _UMQTT_SSL_H

#include <stdint.h>
#include <sys/types.h>

#include "config.h"

#if UMQTT_SSL_SUPPORT

struct umqtt_ssl_ctx;

int umqtt_ssl_init(struct umqtt_ssl_ctx **ctx, int sock);
int umqtt_ssl_handshake(struct umqtt_ssl_ctx *ctx);
void umqtt_ssl_free(struct umqtt_ssl_ctx *ctx);

int umqtt_ssl_read(int fd, void *buf, size_t count, void *arg);
int umqtt_ssl_write(int fd, void *buf, size_t count, void *arg);

#endif

#endif
