/*
 * Copyright (C) 2017 Jianhui Zhao <jianhuizhao329@gmail.com>
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _UMQTT_H
#define _UMQTT_H

#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/avl.h>

#include "config.h"

#if (UMQTT_SSL_SUPPORT)
#include <dlfcn.h>
#include <libubox/ustream-ssl.h>
#endif

#define UMQTT_PING_INTERVAL  30

#define UMQTT_MAX_REMLEN 268435455 

enum umqtt_packet_type {
    UMQTT_NO_PACKET,
    UMQTT_CONNECT_PACKET,
    UMQTT_CONNACK_PACKET,
    UMQTT_PUBLISH_PACKET,
    UMQTT_PUBACK_PACKET,
    UMQTT_PUBREC_PACKET,
    UMQTT_PUBREL_PACKET,
    UMQTT_PUBCOMP_PACKET,
    UMQTT_SUBSCRIBE_PACKET,
    UMQTT_SUBACK_PACKET,
    UMQTT_UNSUBSCRIBE_PACKET,
    UMQTT_UNSUBACK_PACKET,
    UMQTT_PINGREQ_PACKET,
    UMQTT_PINGRESP_PACKET,
    UMQTT_DISCONNECT_PACKET
};

enum umqtt_return_code {
    UMQTT_CONNECTION_ACCEPTED = 0,
    UMQTT_UNACCEPTABLE_PROTOCOL = 1,
    UMQTT_IDENTIFIER_REJECTED = 2,
    UMQTT_SERVER_UNAVAILABLE = 3,
    UMQTT_BAD_USERNAME_OR_PASSWORD = 4,
    UMQTT_NOT_AUTHORIZED = 5
};

enum umqtt_error_code {
    UMQTT_ERROR_WRITE,
    UMQTT_ERROR_SSL,
    UMQTT_ERROR_SSL_INVALID_CERT,
    UMQTT_ERROR_SSL_CN_MISMATCH,
    UMQTT_REMAINING_LENGTH_MISMATCH,
    UMQTT_REMAINING_LENGTH_OVERFLOW,
    UMQTT_INVALID_PACKET
};

enum parse_state {
    PARSE_STATE_FH,         /* Fixed header */
    PARSE_STATE_REMLEN,     /* Remaining Length */
    PARSE_STATE_VH,         /* Variable header */
    PARSE_STATE_PAYLOAD,    /* Payload */
    PARSE_STATE_DONE
};

struct umqtt_topic {
    uint16_t len;
    char *topic;
    uint8_t qos;
};

struct umqtt_message {
    bool dup;
    bool retain;
    uint8_t qos;
    uint16_t mid;
    char *topic;
    uint32_t len;
    const char *data;
    struct avl_node avl;
};

struct umqtt_packet {
    uint8_t type;
    uint32_t remlen;
    bool sp;    /*  Session Present */
    enum umqtt_return_code return_code;
    uint16_t mid;
    uint8_t qos[10];
    struct umqtt_message *msg;
};

struct umqtt_will {
    const char *topic;
    uint8_t qos;
    bool retain;
    const char *payload;
};

struct umqtt_options {
    bool clean_session;
    uint16_t keep_alive;
    const char *client_id;
    const char *username;
    const char *password;
};

struct umqtt_client {
    struct ustream *us;
    struct ustream_fd sfd;
    struct umqtt_packet pkt;
    struct uloop_timeout ping_timer;
    enum umqtt_error_code error;
    uint16_t last_mid;
    enum parse_state ps;
    bool wait_pingresp;
    struct avl_tree msgs;

#if (UMQTT_SSL_SUPPORT)
    bool ssl_require_validation;
    struct ustream_ssl ussl;
    struct ustream_ssl_ctx *ssl_ctx;
    const struct ustream_ssl_ops *ssl_ops;
#endif

    int (*connect)(struct umqtt_client *cl, struct umqtt_options *opts, struct umqtt_will *will);
    int (*subscribe)(struct umqtt_client *cl, struct umqtt_topic *topics, int num);
    int (*unsubscribe)(struct umqtt_client *cl, struct umqtt_topic *topics, int num);
    int (*publish)(struct umqtt_client *cl, const char *topic, const char *payload, uint8_t qos);
    void (*ping)(struct umqtt_client *cl);
    void (*disconnect)(struct umqtt_client *cl);
    void (*on_conack)(struct umqtt_client *cl, bool sp, enum umqtt_return_code code);
    void (*on_puback)(struct umqtt_client *cl, uint16_t mid);
    void (*on_pubrel)(struct umqtt_client *cl, uint16_t mid);
    void (*on_pubcomp)(struct umqtt_client *cl, uint16_t mid);
    void (*on_unsuback)(struct umqtt_client *cl, uint16_t mid);
    void (*on_suback)(struct umqtt_client *cl, uint16_t mid, uint8_t qos[], int num);
    void (*on_publish)(struct umqtt_client *cl, struct umqtt_message *msg);
    void (*on_error)(struct umqtt_client *cl);
    void (*on_close)(struct umqtt_client *cl);
    void (*free)(struct umqtt_client *cl);
};

struct umqtt_client *umqtt_new_ssl(const char *host, int port, bool ssl, const char *ca_crt_file, bool verify);

static inline struct umqtt_client *umqtt_new(const char *host, int port)
{
    return umqtt_new_ssl(host, port, false, NULL, false);
}

#endif
