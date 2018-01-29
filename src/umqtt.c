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

static void umqtt_message_free(struct umqtt_message *msg, bool out)
{
    if (msg->topic)
        free(msg->topic);
    if (out && msg->payload)
        free(msg->payload);
    free(msg);
}

static void umqtt_free(struct umqtt_client *cl)
{
    struct umqtt_message *msg, *tmp;

    uloop_timeout_cancel(&cl->ping_timer);
    uloop_timeout_cancel(&cl->retry_timer);
    ustream_free(&cl->sfd.stream);
    shutdown(cl->sfd.fd.fd, SHUT_RDWR);
    close(cl->sfd.fd.fd);
#if (UMQTT_SSL_SUPPORT)
    if (cl->ssl_ops && cl->ssl_ctx)
        cl->ssl_ops->context_free(cl->ssl_ctx);
#endif
    avl_remove_all_elements(&cl->in_queue, msg, avl, tmp)
        umqtt_message_free(msg, false);
    avl_remove_all_elements(&cl->out_queue, msg, avl, tmp)
        umqtt_message_free(msg, true);
    free(cl);
}

static inline void umqtt_error(struct umqtt_client *cl, int error)
{
    cl->us->eof = true;
    cl->error = error;
    ustream_state_change(cl->us);
}

static void send_pubxx(struct umqtt_client *cl, uint8_t header, uint16_t mid)
{
    uint8_t buf[4] = {header, 0x02};

    *((uint16_t *)&buf[2]) = htons(mid);
    ustream_write(cl->us, (const char *)buf, 4, false);
}

static inline void send_puback(struct umqtt_client *cl, uint16_t mid)
{
    send_pubxx(cl, 0x40, mid);
}

static inline void send_pubrec(struct umqtt_client *cl, uint16_t mid)
{
    send_pubxx(cl, 0x50, mid);
}
static inline void send_pubrel(struct umqtt_client *cl, uint16_t mid)
{
    send_pubxx(cl, 0x62, mid);
}

static inline void send_pubcomp(struct umqtt_client *cl, uint16_t mid)
{
    send_pubxx(cl, 0x70, mid);
}

static void handle_conack(struct umqtt_client *cl, uint8_t *data)
{
    bool sp = data[0] & 0x01;    /* Session Present */
    int return_code =  data[1];

    if (return_code == UMQTT_CONNECTION_ACCEPTED) {
        uloop_timeout_set(&cl->ping_timer, UMQTT_PING_INTERVAL * 1000);
        uloop_timeout_set(&cl->retry_timer, 1000);
    }

    if (cl->on_conack)
        cl->on_conack(cl, sp, return_code);
}

static void handle_pubackcomp(struct umqtt_client *cl, uint8_t *data)
{
    uint16_t mid = (data[0] << 8) | data[1];
    struct umqtt_message *msg;

    msg = avl_find_element(&cl->out_queue, &mid, msg, avl);
    if (msg) {
        avl_delete(&cl->out_queue, &msg->avl);
        umqtt_message_free(msg, true);
    }
}

static void handle_pubrec(struct umqtt_client *cl, uint8_t *data)
{
    uint16_t mid = (data[0] << 8) | data[1];
    struct umqtt_message *msg;

    send_pubrel(cl, mid);

    msg = avl_find_element(&cl->out_queue, &mid, msg, avl);
    if (msg) {        
        
        free(msg->topic);
        msg->topic = NULL;
        free(msg->payload);
        msg->payload = NULL;
        msg->timestamp = time(NULL);
        msg->state = umqtt_ms_wait_for_pubcomp;
    }
}

static void handle_pubrel(struct umqtt_client *cl, uint8_t *data)
{
    uint16_t mid = (data[0] << 8) | data[1];
    struct umqtt_message *msg;

    send_pubcomp(cl, mid);

    msg = avl_find_element(&cl->in_queue, &mid, msg, avl);
    if (msg) {
        if (cl->on_publish)
            cl->on_publish(cl, msg);
        
        avl_delete(&cl->in_queue, &msg->avl);
        umqtt_message_free(msg, false);
    }
}

static void handle_suback(struct umqtt_client *cl, uint8_t *data)
{
    struct umqtt_packet *pkt = &cl->pkt;
    if (cl->on_suback) {
        uint16_t mid = (data[0] << 8) | data[1];
        cl->on_suback(cl, mid, data + 2, pkt->remlen - 2);
    }
}

static void handle_publish(struct umqtt_client *cl, uint8_t *data)
{
    struct umqtt_packet *pkt = &cl->pkt;
    int len = (data[0] << 8) + data[1];

    data += 2;
    pkt->msg->topic = strndup((const char *)data, len);
    data += len;
    if (pkt->msg->qos > 0) {
        struct umqtt_message *msg;

        pkt->msg->mid = (data[0] << 8) + data[1];
        len += 2;
        data += 2;

        msg = avl_find_element(&cl->in_queue, &pkt->msg->mid, msg, avl);
        if (msg) {
            umqtt_log_err("Duplicate PUBLISH received:(q%d, m%d, '%s')\n", pkt->msg->qos, pkt->msg->mid, pkt->msg->topic);
            free(pkt->msg);
            return;
        }
    }
    pkt->msg->payloadlen = pkt->remlen - len - 2;
    pkt->msg->payload = data;

    if (pkt->msg->qos == 2) {
        pkt->msg->avl.key = &pkt->msg->mid;
        pkt->msg->state = umqtt_ms_wait_for_pubrel;
        avl_insert(&cl->in_queue, &pkt->msg->avl);
        send_pubrec(cl, pkt->msg->mid);
    } else {
        if (pkt->msg->qos == 1)
            send_puback(cl, pkt->msg->mid);

        if (cl->on_publish)
            cl->on_publish(cl, pkt->msg);
        umqtt_message_free(pkt->msg, false);
    }
}

static bool handle_packet(struct umqtt_client *cl, uint8_t *data, int len)
{
    struct umqtt_packet *pkt = &cl->pkt;

    if (len < pkt->remlen)
        return false;

    switch (pkt->type) {
    case UMQTT_CONNACK_PACKET:
        handle_conack(cl, data);
        break;
    case UMQTT_PUBACK_PACKET:
    case UMQTT_PUBCOMP_PACKET:
        handle_pubackcomp(cl, data);
        break;
    case UMQTT_PUBREC_PACKET:
        handle_pubrec(cl, data);
        break;
    case UMQTT_PUBREL_PACKET:
        handle_pubrel(cl, data);
        break;
    case UMQTT_SUBACK_PACKET:
        handle_suback(cl, data);
        break;
    case UMQTT_UNSUBACK_PACKET:
        break;
    case UMQTT_PUBLISH_PACKET:
        handle_publish(cl, data);
        break;
    default:
        break;
    }

    cl->ps = PARSE_STATE_FH;
    ustream_consume(cl->us, len);
    return true;
}

static bool parse_fixed_header(struct umqtt_client *cl, uint8_t *data, int len)
{
    struct umqtt_packet *pkt = &cl->pkt;
    bool more_remlen;

    if (len < 2)
        return false;

    memset(pkt, 0, sizeof(*pkt));

    pkt->type = data[0] >> 4;
    pkt->remlen = data[1] & 0x7F;
    more_remlen = data[1] & 0x80;

    if (more_remlen)
        cl->ps = PARSE_STATE_REMLEN;
    else if (pkt->remlen > 0)
        cl->ps = PARSE_STATE_HANDLE;
    else
        cl->ps = PARSE_STATE_FH;

    switch (pkt->type) {
    case UMQTT_PINGRESP_PACKET:
        cl->wait_pingresp = false;
        uloop_timeout_set(&cl->ping_timer, UMQTT_PING_INTERVAL * 1000);
        break;
    case UMQTT_CONNACK_PACKET:
    case UMQTT_PUBACK_PACKET:
    case UMQTT_PUBREL_PACKET:
    case UMQTT_PUBCOMP_PACKET:
        if (more_remlen || pkt->remlen != 2)
            cl->error = UMQTT_REMAINING_LENGTH_MISMATCH;
        break;
    case UMQTT_PUBLISH_PACKET: {
            pkt->msg = calloc(1, sizeof(struct umqtt_message));
            pkt->msg->dup = data[0] & 0x08;
            pkt->msg->qos = (data[0] >> 1) & 0x03;
            pkt->msg->retain = data[0] & 0x01;
            break;
        }
    default:
        break;
    }

    ustream_consume(cl->us, 2);
    return true;
}

static bool parse_remaining_ength(struct umqtt_client *cl, uint8_t *data, int len)
{
    int parsed = 0;
    struct umqtt_packet *pkt = &cl->pkt;

    while (parsed++ < len) {
        pkt->remlen = (pkt->remlen << 6) + (*data & 0X7F);
        if ((*data & 0x80) == 0) {
            cl->ps = PARSE_STATE_HANDLE;
            break;
        }

        if (pkt->remlen > UMQTT_MAX_REMLEN) {
            cl->error = UMQTT_REMAINING_LENGTH_OVERFLOW;
            break;
        }
        data++;
    }
    ustream_consume(cl->us, parsed);
    return true;
}

typedef bool (*parse_cb_t)(struct umqtt_client *cl, uint8_t *data, int len);
static parse_cb_t parse_cbs[] = {
    [PARSE_STATE_FH] = parse_fixed_header,
    [PARSE_STATE_REMLEN] = parse_remaining_ength,
    [PARSE_STATE_HANDLE] = handle_packet
};

static inline void __umqtt_notify_read(struct umqtt_client *cl, struct ustream *s)
{
    void *data;
    int len;

    do {
        data = ustream_get_read_buf(s, &len);
        if (!data || !len)
            return;

        if (cl->ps >= ARRAY_SIZE(parse_cbs) || !parse_cbs[cl->ps])
            return;

        if (!parse_cbs[cl->ps](cl, data, len))
            break;
    } while(1);

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
        if (will->topic)
            remlen += strlen(will->topic) + 2;
        if (will->payload)
            remlen += strlen(will->payload) + 2;
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

    if (will) {
        UMQTT_PUT_STRING(p, strlen(will->topic), will->topic);
        UMQTT_PUT_STRING(p, strlen(will->payload), will->payload);
    }

    if (opts->username)
        UMQTT_PUT_STRING(p, strlen(opts->username), opts->username);

    if (opts->password)
        UMQTT_PUT_STRING(p, strlen(opts->password), opts->password);

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

static uint16_t get_unused_mid(struct umqtt_client *cl)
{
    uint16_t mid = 1;
    struct umqtt_message *msg;

    avl_for_each_element(&cl->out_queue, msg, avl) {
        if (msg->mid == mid)
            mid++;
    }

    return mid;
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

    UMQTT_PUT_U16(p, get_unused_mid(cl));

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

    UMQTT_PUT_U16(p, get_unused_mid(cl));

    for (i = 0; i < num; i++) {
        UMQTT_PUT_STRING(p, topics[i].len, topics[i].topic);
    }

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

static int __umqtt_publish(struct umqtt_client *cl, uint16_t mid, const char *topic, uint32_t payloadlen,
    const void *payload, uint8_t qos, bool retain, bool dup)
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

    *p++ = (UMQTT_PUBLISH_PACKET << 4) | (qos << 1) | retain;
    umqtt_encode_remlen(remlen, &p);

    UMQTT_PUT_STRING(p, strlen(topic), topic);

    if (qos > 0)
        UMQTT_PUT_U16(p, mid);

    memcpy(p, payload, strlen(payload));

    ustream_write(cl->us, (const char *)buf, remlen + 2, false);
    free(buf);
    return 0;
}

int umqtt_publish(struct umqtt_client *cl, const char *topic, uint32_t payloadlen,
    const void *payload, uint8_t qos, bool retain)
{
    uint16_t mid = 0;
    struct umqtt_message *msg;

    if (qos > 0)
         mid = get_unused_mid(cl);

    if (__umqtt_publish(cl, mid, topic, payloadlen, payload, qos, retain, false) < 0)
        return -1;

    if (qos > 0) {
        msg = calloc(1, sizeof(struct umqtt_message));
        if (!msg) {
            umqtt_log_serr("calloc");
            return -1;
        }

        msg->payload = malloc(payloadlen);
        if (!msg->payload) {
            umqtt_log_serr("malloc");
            umqtt_message_free(msg, true);
            return -1;
        }
        msg->payloadlen = payloadlen;
        memcpy(msg->payload, payload, payloadlen);

        msg->timestamp = time(NULL);
        msg->state = (qos == 1) ? umqtt_ms_wait_for_puback : umqtt_ms_wait_for_pubrec;
        msg->retain = retain;
        msg->qos = qos;
        msg->mid = mid;
        msg->topic = strdup(topic);
        msg->avl.key = &msg->mid;
        avl_insert(&cl->out_queue, &msg->avl);
    }

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


static void umqtt_retry(struct umqtt_client *cl, struct avl_tree *queue)
{
    time_t now = time(NULL);
    struct umqtt_message *msg;

    avl_for_each_element(queue, msg, avl) {
        if (now - msg->timestamp > 2) {
            switch (msg->state) {
            case umqtt_ms_wait_for_puback:
            case umqtt_ms_wait_for_pubrec:
                msg->timestamp = now;
                __umqtt_publish(cl, msg->mid, msg->topic, msg->payloadlen, msg->payload, msg->qos, msg->retain, true);
                break;
            case umqtt_ms_wait_for_pubrel:
                msg->timestamp = now;
                send_pubrec(cl, msg->mid);
                break;
            case umqtt_ms_wait_for_pubcomp:
                msg->timestamp = now;
                send_pubrel(cl, msg->mid);
                break;
            default:
                break;
            }
        }
    }
}

static void umqtt_retry_cb(struct uloop_timeout *timeout)
{
    struct umqtt_client *cl = container_of(timeout, struct umqtt_client, retry_timer);

    umqtt_retry(cl, &cl->in_queue);
    umqtt_retry(cl, &cl->out_queue);
    uloop_timeout_set(&cl->retry_timer, 1000);
}

static int avl_pkt_cmp(const void *k1, const void *k2, void *ptr)
{
    return *(uint16_t *)k1 - *(uint16_t *)k2;
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
    cl->retry_timer.cb = umqtt_retry_cb;

    ustream_fd_init(&cl->sfd, sock);

    avl_init(&cl->in_queue, avl_pkt_cmp, false, NULL);
    avl_init(&cl->out_queue, avl_pkt_cmp, false, NULL);

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