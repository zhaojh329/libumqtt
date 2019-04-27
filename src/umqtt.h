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

#include <ev.h>
#include <stdint.h>
#include <stdbool.h>

#include "log.h"
#include "utils.h"
#include "config.h"
#include "buffer.h"

#define UMQTT_PKT_HDR_LEN   1
#define UMQTT_PKT_MID_LEN   2
#define UMQTT_PKT_TOPIC_LEN 2

#define UMQTT_KEEP_ALIVE_DEFAULT    30
#define UMQTT_MAX_CONNECT_TIME      5  /* second */

#define UMQTT_MAX_REMLEN            268435455

/* MQTT Control Packet type */
enum {
    UMQTT_CONNECT = 1,  /* Client request to connect to Server */
    UMQTT_CONNACK,      /* Connect acknowledgment */
    UMQTT_PUBLISH,      /* Publish message */
    UMQTT_PUBACK,       /* Publish acknowledgment */
    UMQTT_PUBREC,       /* Publish received (assured delivery part 1) */
    UMQTT_PUBREL,       /* Publish release (assured delivery part 2) */
    UMQTT_PUBCOMP,      /* Publish complete (assured delivery part 3) */
    UMQTT_SUBSCRIBE,    /* Client subscribe request */
    UMQTT_SUBACK,       /* Subscribe acknowledgment */
    UMQTT_UNSUBSCRIBE,  /* Unsubscribe request */
    UMQTT_UNSUBACK,     /* Unsubscribe acknowledgment */
    UMQTT_PINGREQ,      /* PING request */
    UMQTT_PINGRESP,     /* PING response */
    UMQTT_DISCONNECT    /* Client is disconnecting */
};

/* Connect Return code */
enum {
    UMQTT_CONNECTION_ACCEPTED,      /* Connection accepted */
    UMQTT_UNACCEPTABLE_PROTOCOL,    /* Connection Refused, unacceptable protocol version */
    UMQTT_IDENTIFIER_REJECTED,      /* Connection Refused, identifier rejected */
    UMQTT_SERVER_UNAVAILABLE,       /* Connection Refused, Server unavailable */
    UMQTT_BAD_USERNAME_OR_PASSWORD, /* Connection Refused, bad user name or password */
    UMQTT_NOT_AUTHORIZED            /* Connection Refused, not authorized */
};

enum {
    UMQTT_QOS0,
    UMQTT_QOS1,
    UMQTT_QOS2
};

/* Parse result code */
enum {
    UMQTT_PARSE_PEND,   /* Not a complete MQTT packet, need more data */
    UMQTT_PARSE_OK      /* Parse complete, it's a complete MQTT packet */
};

/* State of the MQTT client */
enum {
    UMQTT_STATE_CONNECTING,     /* Socket connection in progress */
    UMQTT_STATE_SSL_HANDSHAKE,  /* SSL handshake in progress */
    UMQTT_STATE_PARSE_FH,       /* Parse fixed header */
    UMQTT_STATE_PARSE_REMLEN,   /* Parse remaining Length */
    UMQTT_STATE_HANDLE_PACKET   /* Handle packet */
};

enum {
    UMQTT_ERROR_SSL_HANDSHAKE,
    UMQTT_ERROR_SSL_INVALID_CERT,
    UMQTT_REMAINING_LENGTH_MISMATCH,
    UMQTT_REMAINING_LENGTH_OVERFLOW,
    UMQTT_INVALID_PACKET,
    UMQTT_ERROR_CONNECT,
    UMQTT_ERROR_IO,
    UMQTT_ERROR_PING_TIMEOUT
};

enum {
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

struct umqtt_packet {
    uint8_t type;
    uint8_t flags;
    uint32_t remlen;
    struct umqtt_message *msg;
};

struct umqtt_connect_opts {
    bool clean_session;
    uint16_t keep_alive;
    const char *client_id;
    const char *username;
    const char *password;

    const char *will_topic;
    const char *will_message;
    uint8_t will_qos;
    bool will_retain;
};

struct umqtt_topic {
    const char *topic;
    uint8_t qos;
};

struct umqtt_client {
    int sock;
    struct ev_loop *loop;
    struct ev_io ior;
    struct ev_io iow;
    struct buffer rb;
    struct buffer wb;
    int state;
    void *ssl;              /* Context wrap of openssl, wolfssl and mbedtls */

    ev_tstamp start_time;   /* Time stamp of begin connect */
    ev_tstamp last_ping;    /* Time stamp of last ping */
    int ntimeout;           /* Number of timeouts */

    struct ev_timer timer;

    bool connection_accepted;       /* Received the conack packet and returns UMQTT_CONNECTION_ACCEPTED */
    struct umqtt_packet pkt;
    uint16_t keep_alive;
    bool wait_pingresp;             /* Wait PINGRESP */
    uint8_t mid[65536];            /* used to generate message id */

    int (*connect)(struct umqtt_client *cl, struct umqtt_connect_opts *opts);
    int (*subscribe)(struct umqtt_client *cl, struct umqtt_topic *topics, int num);
    int (*unsubscribe)(struct umqtt_client *cl, const char **topics, int num);
    int (*publish)(struct umqtt_client *cl, const char *topic, const void *payload, uint32_t payloadlen,
        uint8_t qos, bool retain);
    void (*ping)(struct umqtt_client *cl);
    void (*disconnect)(struct umqtt_client *cl);
	void (*free)(struct umqtt_client *cl);

    void (*on_net_connected)(struct umqtt_client *cl);
    void (*on_conack)(struct umqtt_client *cl, bool sp, int code);
    void (*on_suback)(struct umqtt_client *cl, uint8_t *granted_qos, int qos_count);
    void (*on_unsuback)(struct umqtt_client *cl);
    void (*on_publish)(struct umqtt_client *cl, const char *topic, int topic_len,
            const void *payload, int payloadlen);
    void (*on_error)(struct umqtt_client *cl, int err, const char *msg);
    void (*on_close)(struct umqtt_client *cl);
    void (*on_pingresp)(struct umqtt_client *cl);
};

int umqtt_init(struct umqtt_client *cl, struct ev_loop *loop, const char *host, int port, bool ssl);
struct umqtt_client *umqtt_new(struct ev_loop *loop, const char *host, int port, bool ssl);

#endif
