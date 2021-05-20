/*
 * Copyright (C) 2017 Jianhui Zhao <zhaojh329@gmail.com>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "umqtt.h"

#define RECONNECT_INTERVAL  5

struct config {
    const char *host;
    int port;
    bool ssl;
    bool auto_reconnect;
    struct umqtt_connect_opts options;
};

static struct ev_timer reconnect_timer;

static struct config cfg = {
    .host = "localhost",
    .port = 1883,
    .options = {
        .keep_alive = 30,
        .clean_session = true,
        .username = "test",
        .password = "123456",
        .will_topic = "will",
        .will_message = "will test"
    }
};

static void start_reconnect(struct ev_loop *loop)
{
    if (!cfg.auto_reconnect) {
        ev_break(loop, EVBREAK_ALL);
        return;
    }

    ev_timer_set(&reconnect_timer, RECONNECT_INTERVAL, 0.0);
    ev_timer_start(loop, &reconnect_timer);
}

static void on_conack(struct umqtt_client *cl, bool sp, int code)
{
    struct umqtt_topic topics[] = {
        {
            .topic = "test1",
            .qos = UMQTT_QOS0
        },
        {
            .topic = "test2",
            .qos = UMQTT_QOS1
        },
        {
            .topic = "test3",
            .qos = UMQTT_QOS2
        }
    };

    if (code != UMQTT_CONNECTION_ACCEPTED) {
        log_err("Connect failed:%d\n", code);
        return;
    }

    log_info("on_conack:  Session Present(%d)  code(%u)\n", sp, code);

    /* Session Present */
    if (!sp)
        cl->subscribe(cl, topics, ARRAY_SIZE(topics));

    cl->publish(cl, "test4", "hello world", strlen("hello world"), 2, false);
}

static void on_suback(struct umqtt_client *cl, uint8_t *granted_qos, int qos_count)
{
    int i;

    printf("on_suback, qos(");
    for (i = 0; i < qos_count; i++)
        printf("%d ", granted_qos[i]);
    printf("\b)\n");
}

static void on_unsuback(struct umqtt_client *cl)
{
    log_info("on_unsuback\n");
    log_info("Normal quit\n");

    ev_break(cl->loop, EVBREAK_ALL);
}


static void on_publish(struct umqtt_client *cl, const char *topic, int topic_len,
    const void *payload, int payloadlen)
{
    log_info("on_publish: topic:[%.*s] payload:[%.*s]\n", topic_len, topic,
        payloadlen, (char *)payload);
}

static void on_pingresp(struct umqtt_client *cl)
{
}

static void on_error(struct umqtt_client *cl, int err, const char *msg)
{
    log_err("on_error: %d: %s\n", err, msg);

    reconnect_timer.data = NULL;

    start_reconnect(cl->loop);
    free(cl);
}

static void on_close(struct umqtt_client *cl)
{
    log_info("on_close\n");

    reconnect_timer.data = NULL;

    start_reconnect(cl->loop);
    free(cl);
}

static void on_net_connected(struct umqtt_client *cl)
{
    log_info("on_net_connected\n");

    if (cl->connect(cl, &cfg.options) < 0) {
        log_err("connect failed\n");

        reconnect_timer.data = NULL;

        start_reconnect(cl->loop);
        free(cl);
    }
}

static void do_connect(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    struct umqtt_client *cl;

    cl = umqtt_new(loop, cfg.host, cfg.port, cfg.ssl);
    if (!cl) {
        start_reconnect(loop);
        return;
    }

    cl->on_net_connected = on_net_connected;
    cl->on_conack = on_conack;
    cl->on_suback = on_suback;
    cl->on_unsuback = on_unsuback;
    cl->on_publish = on_publish;
    cl->on_pingresp = on_pingresp;
    cl->on_error = on_error;
    cl->on_close = on_close;

    reconnect_timer.data = cl;

    log_info("Start connect...\n");
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    struct umqtt_client *cl = reconnect_timer.data;

    if (cl) {
        cl->free(cl);
        free(cl);
    }
    ev_break(loop, EVBREAK_ALL);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
        "      -h host      # Default is 'localhost'\n"
        "      -p port      # Default is 1883\n"
        "      -i ClientId  # Default is 'libumqtt-Test\n"
        "      -s           # Use ssl\n"
        "      -C           # CA certificate to verify peer against\n"
        "      -c           # Certificate file to use\n"
        "      -k           # Private key file to use\n"
        "      -u           # Username\n"
        "      -P           # Password\n"
        "      -a           # Auto reconnect to the server\n"
        "      -d           # enable debug messages\n"
        , prog);
    exit(1);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_signal signal_watcher;
    char client_id[128] = "";
    int opt;

    while ((opt = getopt(argc, argv, "h:i:p:sC:c:k:au:P:d")) != -1) {
        switch (opt) {
        case 'h':
            cfg.host = optarg;
            break;
        case 'p':
            cfg.port = atoi(optarg);
            break;
#ifdef SSL_SUPPORT
        case 's':
            cfg.ssl = true;
            break;
        case 'C':
            if (umqtt_load_ca_crt_file(optarg))
                log_err("load ca crt file fail\n");
            break;
        case 'c':
            if (umqtt_load_crt_file(optarg))
                log_err("load crt file fail\n");
            break;
        case 'k':
            if (umqtt_load_key_file(optarg))
                log_err("load key fail\n");
            break;
#endif
        case 'a':
            cfg.auto_reconnect = true;
            break;
        case 'i':
            cfg.options.client_id = optarg;
            break;
        case 'u':
            cfg.options.username = optarg;
            break;
        case 'P':
            cfg.options.password = optarg;
            break;
        case 'd':
            log_level(LOG_DEBUG);
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    if (!cfg.options.client_id) {
        srand(time(NULL));
        sprintf(client_id, "libumqtt-Test-%05d", rand());
        cfg.options.client_id = client_id;
    }

    ev_signal_init(&signal_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher);

    ev_timer_init(&reconnect_timer, do_connect, 0.1, 0.0);
    ev_timer_start(loop, &reconnect_timer);

    log_info("libumqttc version %s\n", UMQTT_VERSION_STRING);

    ev_run(loop, 0);

    ev_default_destroy();

    return 0;
}

