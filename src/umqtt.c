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

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <glob.h>
#include <arpa/inet.h>
#include <libubox/usock.h>
#include <libubox/utils.h>

#include "umqtt.h"
#include "log.h"
#include "helpers.h"

static void umqtt_free(struct umqtt_client *cl)
{
    uloop_timeout_cancel(&cl->ping_timer);
    ustream_free(&cl->sfd.stream);
    shutdown(cl->sfd.fd.fd, SHUT_RDWR);
    close(cl->sfd.fd.fd);
#if (UMQTT_SSL_SUPPORT)
    if (cl->ssl_ops && cl->ssl_ctx)
        cl->ssl_ops->context_free(cl->ssl_ctx);
#endif
    free(cl);
}

static inline void umqtt_error(struct umqtt_client *cl, int error)
{
    cl->us->eof = true;
    cl->error = error;
    ustream_state_change(cl->us);
}

static void dispach_message(struct umqtt_client *cl)
{
    struct umqtt_packet *pkt = &cl->pkt;

    switch (pkt->type) {
    case UMQTT_CONNACK_PACKET:
        if (cl->on_conack)
            cl->on_conack(cl, pkt->connect_code);
        if (!pkt->connect_code)
            uloop_timeout_set(&cl->ping_timer, UMQTT_PING_INTERVAL * 1000);
        break;
    case UMQTT_PUBACK_PACKET:
        if (cl->on_puback)
            cl->on_puback(cl, pkt->mid);
        break;
    case UMQTT_SUBACK_PACKET:
        if (cl->on_suback)
            cl->on_suback(cl, pkt->mid, pkt->qos, pkt->remlen - 2);
        break;
    case UMQTT_PUBLISH_PACKET:
        if (cl->on_publish)
            cl->on_publish(cl, pkt->topic, &pkt->payload);
        free(pkt->topic);
        ustream_consume(cl->us, pkt->payload.len);
        break;
    case UMQTT_PUBREL_PACKET:
        if (cl->on_pubrel)
            cl->on_pubrel(cl, pkt->mid);
        break;
    case UMQTT_PUBCOMP_PACKET:
        if (cl->on_pubcomp)
            cl->on_pubcomp(cl, pkt->mid);
        break;
    case UMQTT_UNSUBACK_PACKET:
        if (cl->on_unsuback)
            cl->on_unsuback(cl, pkt->mid);
        break;
    case UMQTT_PINGRESP_PACKET:
        cl->wait_pingresp = false;
        uloop_timeout_set(&cl->ping_timer, UMQTT_PING_INTERVAL * 1000);
        break;
    default:
        umqtt_log_err("Invalid packet:%d\n", pkt->type);
        umqtt_error(cl, UMQTT_INVALID_PACKET);
        break;
    }
}

static void parse_fixed_header(struct umqtt_client *cl, uint8_t *data, int len)
{
    struct umqtt_packet *pkt = &cl->pkt;
    bool more_remlen;

    if (len < 2)
        return;

    memset(pkt, 0, sizeof(*pkt));

    pkt->type = data[0] >> 4;
    pkt->remlen = data[1] & 0x7F;
    more_remlen = data[1] & 0x80;

    if (more_remlen)
        cl->ps = PARSE_STATE_REMLEN;
    else if (pkt->remlen > 0)
        cl->ps = PARSE_STATE_VH;
    else
        cl->ps = PARSE_STATE_DONE;

    switch (pkt->type) {
    case UMQTT_CONNACK_PACKET:
    case UMQTT_PUBACK_PACKET:
    case UMQTT_PUBREL_PACKET:
    case UMQTT_PUBCOMP_PACKET:
        if (more_remlen || pkt->remlen != 2)
            cl->error = UMQTT_REMAINING_LENGTH_MISMATCH;
        break;
    case UMQTT_PUBLISH_PACKET:
        pkt->payload.dup = data[0] & 0x08;
        pkt->payload.qos = (data[0] >> 1) & 0x03;
        pkt->payload.retain = data[0] & 0x01;
    default:
        break;
    }

    ustream_consume(cl->us, 2);
}

static void parse_remaining_ength(struct umqtt_client *cl, uint8_t *data, int len)
{
    int parsed = 0;
    struct umqtt_packet *pkt = &cl->pkt;

    while (parsed++ < len) {
        pkt->remlen = (pkt->remlen << 6) + (*data & 0X7F);
        if ((*data & 0x80) == 0) {
            cl->ps = PARSE_STATE_VH;
            break;
        }

        if (pkt->remlen > UMQTT_MAX_REMLEN) {
            cl->error = UMQTT_REMAINING_LENGTH_OVERFLOW;
            break;
        }
        data++;
    }
    ustream_consume(cl->us, parsed);
}

static void parse_variable_header(struct umqtt_client *cl, uint8_t *data, int len)
{
    int parsed = 0;
    struct umqtt_packet *pkt = &cl->pkt;

    switch (pkt->type) {
    case UMQTT_CONNACK_PACKET:
        if (len < 2)
            return;
        pkt->session_present = data[0] & 0x01;
        pkt->connect_code = data[1];
        cl->ps = PARSE_STATE_DONE;
        parsed = 2;
        break;
    case UMQTT_SUBACK_PACKET:
    case UMQTT_PUBACK_PACKET:
    case UMQTT_PUBREL_PACKET:
    case UMQTT_PUBCOMP_PACKET:
    case UMQTT_UNSUBACK_PACKET:
        if (len < 2)
            return;
        pkt->mid = (data[0] << 8) | data[1];
        parsed = 2;
        if (pkt->type == UMQTT_SUBACK_PACKET)
            cl->ps = PARSE_STATE_PAYLOAD;
        else
            cl->ps = PARSE_STATE_DONE;
        break;
    case UMQTT_PUBLISH_PACKET:
        if (len < 2)
            return;
        parsed = 2 + (data[0] << 8) + data[1];
        if (pkt->payload.qos > 0)
            parsed += 2;
        if (len < parsed)
            return;

        len = (data[0] << 8) + data[1];
        data += 2;
        pkt->topic = strndup((const char *)data, len);
        data += len;
        if (pkt->payload.qos > 0)
            pkt->payload.mid = (data[0] << 8) + data[1];
        pkt->payload.len = pkt->remlen - parsed;
        cl->ps = PARSE_STATE_PAYLOAD;
        break;
    default:
        umqtt_log_err("Invalid packet:%d\n", pkt->type);
        umqtt_error(cl, UMQTT_INVALID_PACKET);
        break;
    }
    ustream_consume(cl->us, parsed);
}

static void parse_payload(struct umqtt_client *cl, uint8_t *data, int len)
{
    int parsed = 0;
    struct umqtt_packet *pkt = &cl->pkt;

    switch (pkt->type) {
    case UMQTT_SUBACK_PACKET:
        if (len < pkt->remlen - 2)
            return;
        memcpy(pkt->qos, data, pkt->remlen - 2);
        cl->ps = PARSE_STATE_DONE;
        parsed = pkt->remlen - 2;
        break;
    case UMQTT_PUBLISH_PACKET:
        if (len < pkt->payload.len)
            return;
        pkt->payload.data = (const char *)data;
        cl->ps = PARSE_STATE_DONE;
        break;
    default:
        umqtt_log_err("Invalid packet:%d\n", pkt->type);
        exit(1);
        break;
    }
    ustream_consume(cl->us, parsed);
}

static inline void __umqtt_notify_read(struct umqtt_client *cl, struct ustream *s)
{
    uint8_t *data;
    int len;

    while (!cl->error) {
        data = (uint8_t *)ustream_get_read_buf(s, &len);
        if (!data || !len) {
            if (cl->ps == PARSE_STATE_DONE) {
                dispach_message(cl);
                cl->ps = PARSE_STATE_FH;
            }
            return;
        }

        switch (cl->ps) {
        case PARSE_STATE_FH:
            parse_fixed_header(cl, data, len);
            break;
        case PARSE_STATE_REMLEN:
            parse_remaining_ength(cl, data, len);
            break;
        case PARSE_STATE_VH:
            parse_variable_header(cl, data, len);
            break;
        case PARSE_STATE_PAYLOAD:
            parse_payload(cl, data, len);
            break;
        case PARSE_STATE_DONE:
            dispach_message(cl);
            cl->ps = PARSE_STATE_FH;
            break;
        default:
            umqtt_log_err("Never come here\n");
            break;
        }
    }

    if (cl->error)
        umqtt_error(cl, cl->error);
}

static inline void __umqtt_notify_state(struct umqtt_client *cl, struct ustream *s)
{
    if (!cl->error && s->write_error)
        cl->error = UMQTT_ERROR_WRITE;

    if (!cl->error) {
        if (!s->eof || s->w.data_bytes)
            return;
    }

    if (cl->error && cl->on_error)
        cl->on_error(cl);

    if (cl->on_close)
        cl->on_close(cl);
}

static inline void umqtt_notify_read(struct ustream *s, int bytes)
{
    struct umqtt_client *cl = container_of(s, struct umqtt_client, sfd.stream);
    __umqtt_notify_read(cl, s);
}

static inline void umqtt_notify_state(struct ustream *s)
{
    struct umqtt_client *cl = container_of(s, struct umqtt_client, sfd.stream);
    __umqtt_notify_state(cl, s);
}

#if (UMQTT_SSL_SUPPORT)
static inline void umqtt_ssl_notify_read(struct ustream *s, int bytes)
{
    struct umqtt_client *cl = container_of(s, struct umqtt_client, ussl.stream);
    __umqtt_notify_read(cl, s);
}

static inline void umqtt_ssl_notify_state(struct ustream *s)
{
    struct umqtt_client *cl = container_of(s, struct umqtt_client, ussl.stream);
    __umqtt_notify_state(cl, s);
}

static void umqtt_ssl_notify_error(struct ustream_ssl *ssl, int error, const char *str)
{
    struct umqtt_client *cl = container_of(ssl, struct umqtt_client, ussl);
    umqtt_error(cl, UMQTT_ERROR_SSL);
    umqtt_log_err("ssl error:%d:%s", error, str);
}

static void umqtt_ssl_notify_verify_error(struct ustream_ssl *ssl, int error, const char *str)
{
    struct umqtt_client *cl = container_of(ssl, struct umqtt_client, ussl);

    if (!cl->ssl_require_validation)
        return;

    umqtt_error(cl, UMQTT_ERROR_SSL_INVALID_CERT);
    umqtt_log_err("ssl error:%d:%s", error, str);
}

static void umqtt_ssl_notify_connected(struct ustream_ssl *ssl)
{
    struct umqtt_client *cl = container_of(ssl, struct umqtt_client, ussl);

    if (!cl->ssl_require_validation)
        return;

    if (!cl->ussl.valid_cn) {
        umqtt_error(cl, UMQTT_ERROR_SSL_CN_MISMATCH);
        umqtt_log_err("ssl error: cn mismatch");
    }
}

static const struct ustream_ssl_ops *init_ustream_ssl()
{
    void *dlh;
    struct ustream_ssl_ops *ops;

    dlh = dlopen("libustream-ssl.so", RTLD_LAZY | RTLD_LOCAL);
    if (!dlh) {
        umqtt_log_err("Failed to load ustream-ssl library: %s", dlerror());
        return NULL;
    }

    ops = dlsym(dlh, "ustream_ssl_ops");
    if (!ops) {
        umqtt_log_err("Could not find required symbol 'ustream_ssl_ops' in ustream-ssl library");
        return NULL;
    }

    return ops;
}

#endif

static void umqtt_encode_remlen(uint32_t remlen, uint8_t **buf)
{
    do {
        **buf = remlen % 128;
        remlen /= 128;
        if (remlen)
            **buf |= 128;
        (*buf)++;
    } while (remlen > 0);
}

static int umqtt_connect(struct umqtt_client *cl, struct umqtt_options *opts, struct umqtt_will *will)
{
    uint8_t *buf, *p;
    uint8_t flags = 0;
    uint32_t remlen = 10;

    remlen += strlen(opts->client_id) + 2;

    if (opts->clean_session)
        UMQTT_SET_BITS(flags, 1, 1);

    if (will) {
        remlen += strlen(will->topic) + 2 + strlen(will->payload) + 2;
        UMQTT_SET_BITS(flags, 1, 2);
        UMQTT_SET_BITS(flags, will->qos, 3);
        UMQTT_SET_BITS(flags, will->retain, 5);
    }

    if (opts->username) {
        remlen += strlen(opts->username) + 2;
        UMQTT_SET_BITS(flags, 1, 7);
        if (opts->password) {
            remlen += strlen(opts->password) + 2;
            UMQTT_SET_BITS(flags, 1, 6);
        }
    }

    if (remlen > UMQTT_MAX_REMLEN) {
        umqtt_log_err("remaining length overflow\n");
        return -1;
    }

    p = buf = malloc(remlen + 2);
    if (!buf) {
        umqtt_log_serr("malloc\n");
        return -1;
    }

    *p++ = (UMQTT_CONNECT_PACKET << 4) | 0x00;
    umqtt_encode_remlen(remlen, &p);

    /* version string */
    UMQTT_PUT_STRING(p, 4, "MQTT");

    *p++ = 0x04;    /* version number */
    *p++ = flags;

    UMQTT_PUT_U16(p, opts->keep_alive);
    UMQTT_PUT_STRING(p, strlen(opts->client_id), opts->client_id);

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

int umqtt_subscribe(struct umqtt_client *cl, struct umqtt_topic *topics, int num)
{
    uint8_t *buf, *p;
    uint32_t remlen = 2;
    int i;

    for (i = 0; i < num; i++)
        remlen += 2 + topics[i].len + 1;

    if (remlen > UMQTT_MAX_REMLEN) {
        umqtt_log_err("remaining length overflow\n");
        return -1;
    }

    p = buf = malloc(remlen + 2);
    if (!buf) {
        umqtt_log_serr("malloc\n");
        return -1;
    }

    *p++ = (UMQTT_SUBSCRIBE_PACKET << 4) | 0x02;
    umqtt_encode_remlen(remlen, &p);

    cl->last_mid++;
    UMQTT_PUT_U16(p, cl->last_mid);

    for (i = 0; i < num; i++) {
        UMQTT_PUT_STRING(p, topics[i].len, topics[i].topic);
        *p++ = topics[i].qos;
    }

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

int umqtt_unsubscribe(struct umqtt_client *cl, struct umqtt_topic *topics, int num)
{
    uint8_t *buf, *p;
    uint32_t remlen = 2;
    int i;

    for (i = 0; i < num; i++)
        remlen += 2 + topics[i].len;

    if (remlen > UMQTT_MAX_REMLEN) {
        umqtt_log_err("remaining length overflow\n");
        return -1;
    }

    p = buf = malloc(remlen + 2);
    if (!buf) {
        umqtt_log_serr("malloc\n");
        return -1;
    }

    *p++ = (UMQTT_UNSUBSCRIBE_PACKET << 4) | 0x02;
    umqtt_encode_remlen(remlen, &p);

    cl->last_mid++;
    UMQTT_PUT_U16(p, cl->last_mid);

    for (i = 0; i < num; i++) {
        UMQTT_PUT_STRING(p, topics[i].len, topics[i].topic);
    }

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

int umqtt_publish(struct umqtt_client *cl, const char *topic, const char *payload, uint8_t qos)
{
    uint8_t *buf, *p;
    uint32_t remlen = 2 + strlen(topic) + strlen(payload);

    if (qos > 0)
        remlen += 2;

    if (remlen > UMQTT_MAX_REMLEN) {
        umqtt_log_err("remaining length overflow\n");
        return -1;
    }

    p = buf = malloc(remlen + 2);
    if (!buf) {
        umqtt_log_serr("malloc\n");
        return -1;
    }

    *p++ = (UMQTT_PUBLISH_PACKET << 4) | (qos << 1);
    umqtt_encode_remlen(remlen, &p);

    UMQTT_PUT_STRING(p, strlen(topic), topic);

    if (qos > 0) {
        cl->last_mid++;
        UMQTT_PUT_U16(p, cl->last_mid);
    }

    memcpy(p, payload, strlen(payload));

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

static void umqtt_disconnect(struct umqtt_client *cl)
{
    uint8_t buf[] = {0xE0, 0x00};
    ustream_write(cl->us, (const char *)buf, 2, false);
    umqtt_error(cl, 0);
}

static void umqtt_ping(struct umqtt_client *cl)
{
    uint8_t buf[] = {0xC0, 0x00};
    ustream_write(cl->us, (const char *)buf, 2, false);
}

static void umqtt_ping_cb(struct uloop_timeout *timeout)
{
    struct umqtt_client *cl = container_of(timeout, struct umqtt_client, ping_timer);

    if (cl->wait_pingresp) {
        umqtt_log_err("Ping server, no response\n");
        cl->disconnect(cl);
        return;
    }
    cl->ping(cl);
    cl->wait_pingresp = true;
    uloop_timeout_set(&cl->ping_timer, 1 * 1000);
}

struct umqtt_client *umqtt_new_ssl(const char *host, int port, bool ssl, const char *ca_crt_file, bool verify)
{
    struct umqtt_client *cl = NULL;
    int sock;

    sock = usock(USOCK_TCP | USOCK_NOCLOEXEC, host, usock_port(port));
    if (sock < 0) {
        umqtt_log_serr("usock");
        goto err;
    }

    cl = calloc(1, sizeof(struct umqtt_client));
    if (!cl) {
        umqtt_log_serr("calloc");
        goto err;
    }

    cl->free = umqtt_free;
    cl->connect = umqtt_connect;
    cl->subscribe = umqtt_subscribe;
    cl->unsubscribe = umqtt_unsubscribe;
    cl->publish = umqtt_publish;
    cl->ping = umqtt_ping;
    cl->disconnect = umqtt_disconnect;

    cl->ping_timer.cb = umqtt_ping_cb;

    ustream_fd_init(&cl->sfd, sock);

    if (ssl) {
#if (UMQTT_SSL_SUPPORT)
        cl->ssl_ops = init_ustream_ssl();
        if (!cl->ssl_ops) {
            umqtt_log_err("SSL support not available,please install one of the libustream-ssl-* libraries");
            goto err;
        }

        cl->ssl_ctx = cl->ssl_ops->context_new(false);
        if (!cl->ssl_ctx) {
            umqtt_log_err("ustream_ssl_context_new");
            goto err;
        }

        if (ca_crt_file) {
            if (cl->ssl_ops->context_add_ca_crt_file(cl->ssl_ctx, ca_crt_file)) {
                umqtt_log_err("Load CA certificates failed");
                goto err;
            }
        } else if (verify) {
            int i;
            glob_t gl;

            cl->ssl_require_validation = true;

            if (!glob("/etc/ssl/certs/*.crt", 0, NULL, &gl)) {
                for (i = 0; i < gl.gl_pathc; i++)
                    cl->ssl_ops->context_add_ca_crt_file(cl->ssl_ctx, gl.gl_pathv[i]);
                globfree(&gl);
            }
        }

        cl->us = &cl->ussl.stream;
        cl->us->string_data = true;
        cl->us->notify_read = umqtt_ssl_notify_read;
        cl->us->notify_state = umqtt_ssl_notify_state;
        cl->ussl.notify_error = umqtt_ssl_notify_error;
        cl->ussl.notify_verify_error = umqtt_ssl_notify_verify_error;
        cl->ussl.notify_connected = umqtt_ssl_notify_connected;
        cl->ussl.server_name = host;
        cl->ssl_ops->init(&cl->ussl, &cl->sfd.stream, cl->ssl_ctx, false);
        cl->ssl_ops->set_peer_cn(&cl->ussl, host);
#else
        umqtt_log_err("SSL support not available");
        return NULL;
#endif
    } else {
        cl->us = &cl->sfd.stream;
        cl->us->string_data = true;
        cl->us->notify_read = umqtt_notify_read;
        cl->us->notify_state = umqtt_notify_state;
    }

    return cl;

err:
    if (cl)
        cl->free(cl);

    return NULL;    
}
