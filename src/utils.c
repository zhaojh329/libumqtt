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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "log.h"
#include "utils.h"

static const char *port2str(int port)
{
    static char buffer[sizeof("65535\0")];

    if (port < 0 || port > 65535)
        return NULL;

    snprintf(buffer, sizeof(buffer), "%u", port);

    return buffer;
}

int tcp_connect(const char *host, int port, int flags, bool *inprogress, int *eai)
{
    int ret;
    int sock = -1;
    int addr_len;
    struct sockaddr *addr = NULL;
    struct addrinfo *result, *rp;
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_flags = AI_ADDRCONFIG
    };

    if (inprogress)
        *inprogress = false;

    ret = getaddrinfo(host, port2str(port), &hints, &result);
    if (ret) {
        if (ret == EAI_SYSTEM)
            return -1;
        *eai =  ret;
        return 0;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            addr = rp->ai_addr;
            addr_len = rp->ai_addrlen;
            break;
        }
    }

    if (!addr)
        goto free_addrinfo;

    sock = socket(AF_INET, SOCK_STREAM | flags, 0);
    if (sock < 0)
        goto free_addrinfo;

    if (connect(sock, addr, addr_len) < 0) {
        if (errno != EINPROGRESS) {
            close(sock);
            sock = -1;
        } else if (inprogress) {
            *inprogress = true;
        }
    }

free_addrinfo:
    freeaddrinfo(result);
    return sock;
}

