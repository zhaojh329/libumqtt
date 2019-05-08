/*
 * MIT License
 *
 * Copyright (c) 2019 Jianhui Zhao <jianhuizhao329@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
