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

#define UMQTT_KEEP_ALIVE 30
#define UMQTT_RETRY_INTERVAL  1
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
    PARSE_STATE_HANDLE      /* handle packet */
};

struct umqtt_topic {
    uint16_t len;
    char *topic;
    uint8_t qos;
};

enum umqtt_msg_state {
    umqtt_ms_invalid,
    umqtt_ms_publish_qos0,
    umqtt_ms_publish_qos1,
    umqtt_ms_wait_for_puback,
    umqtt_ms_publish_qos2,
    umqtt_ms_wait_for_pubrec,
    umqtt_ms_resend_pubrel,
    umqtt_ms_wait_for_pubrel,
    umqtt_ms_resend_pubcomp,
    umqtt_ms_wait_for_pubcomp,
    umqtt_ms_send_pubrec,
    umqtt_ms_queued
};

struct umqtt_message {
    time_t timestamp;
    enum umqtt_msg_state state;
    bool dup;
    bool retain;
    uint8_t qos;
    uint16_t mid;
    char *topic;
    uint32_t payloadlen;
    void *payload;
    struct avl_node avl;
};

struct umqtt_packet {
    uint8_t type;
    uint32_t remlen;
    uint16_t mid;
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
    struct uloop_timeout retry_timer;
    int ping_timer_interval;
    int retry_timer_interval;
    enum umqtt_error_code error;
    enum parse_state ps;
    bool wait_pingresp;
    struct avl_tree in_queue;
    struct avl_tree out_queue;

#if (UMQTT_SSL_SUPPORT)
    bool ssl_require_validation;
    struct ustream_ssl ussl;
    struct ustream_ssl_ctx *ssl_ctx;
    const struct ustream_ssl_ops *ssl_ops;
#endif

    int (*connect)(struct umqtt_client *cl, struct umqtt_options *opts, struct umqtt_will *will);
    int (*subscribe)(struct umqtt_client *cl, struct umqtt_topic *topics, int num);
    int (*unsubscribe)(struct umqtt_client *cl, struct umqtt_topic *topics, int num);
    int (*publish)(struct umqtt_client *cl, const char *topic, uint32_t payloadlen, const void *payload, uint8_t qos, bool retain);
    void (*ping)(struct umqtt_client *cl);
    void (*disconnect)(struct umqtt_client *cl);
    void (*on_conack)(struct umqtt_client *cl, bool sp, enum umqtt_return_code code);
    void (*on_suback)(struct umqtt_client *cl, uint16_t mid, uint8_t *granted_qos, int qos_count);
    void (*on_publish)(struct umqtt_client *cl, struct umqtt_message *msg);
    void (*on_error)(struct umqtt_client *cl);
    void (*on_close)(struct umqtt_client *cl);
    void (*on_pong)(struct umqtt_client *cl);
    void (*free)(struct umqtt_client *cl);
};

struct umqtt_client *umqtt_new_ssl(const char *host, int port, bool ssl, const char *ca_crt_file, bool verify);

static inline struct umqtt_client *umqtt_new(const char *host, int port)
{
    return umqtt_new_ssl(host, port, false, NULL, false);
}

#endif
