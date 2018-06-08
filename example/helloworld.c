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

#include <umqtt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libubox/utils.h>
#include <libubox/ulog.h>

#define RECONNECT_INTERVAL  5

struct config {
    bool auto_reconnect;
    bool ssl_verify;
    const char *host;
    int port;
    bool ssl;
    const char *crt_file;
    struct umqtt_options options;
    struct umqtt_will will;
};

static struct uloop_timeout reconnect_timer;
static struct umqtt_client *gcl;
static struct config cfg = {
    .ssl_verify = true,
    .host = "localhost",
    .port = 1883,
    .options = {
        .keep_alive = 30,
        .client_id = "libumqtt-Test",
        .clean_session = true,
        .username = "test",
        .password = "123456"
    },
    .will = {
        .topic = "will",
        .payload = "will test"
    }
};

static void on_conack(struct umqtt_client *cl, bool sp, enum umqtt_return_code code)
{
    struct umqtt_topic topics[] = {
        {
            .len = strlen("test1"),
            .topic = "test1",
            .qos = 0x00
        },{
            .len = strlen("test2"),
            .topic = "test2",
            .qos = 0x01
        },{
            .len = strlen("test3"),
            .topic = "test3",
            .qos = 0x02
        }
    };

    if (code != UMQTT_CONNECTION_ACCEPTED) {
        ULOG_ERR("Connect failed:%d\n", code);
        return;
    }

    ULOG_INFO("on_conack:  Session Present(%d)  code(%u)\n", sp, code);

    if (!sp)
        cl->subscribe(cl, topics, ARRAY_SIZE(topics));

    cl->publish(cl, "test4", strlen("hello world"), "hello world", 2, false);
}

static void on_suback(struct umqtt_client *cl, uint16_t mid, uint8_t *granted_qos, int qos_count)
{
    int i;

    ULOG_INFO("on_suback mid(%u), qos(", mid);
    for (i = 0; i < qos_count; i++)
        ULOG_INFO("%d ", granted_qos[i]);
    ULOG_INFO("\b)\n");
}

static void on_publish(struct umqtt_client *cl, struct umqtt_message *msg)
{
    ULOG_INFO("on_publish: mid(%d) dup(%d) qos(%d) retain(%d) topic(%s) [%.*s]\n",
        msg->mid, msg->dup, msg->qos, msg->retain, msg->topic, msg->payloadlen, msg->payload);
}

static void on_error(struct umqtt_client *cl)
{
    ULOG_INFO("on_error: %u\n", cl->error);
}

static void on_close(struct umqtt_client *cl)
{
    ULOG_INFO("on_close\n");

    if (cfg.auto_reconnect) {
        gcl->free(gcl);
        gcl = NULL;
        uloop_timeout_set(&reconnect_timer, RECONNECT_INTERVAL * 1000);
    } else {
        uloop_end();
    }
}

static void do_connect(struct uloop_timeout *utm)
{
    gcl = umqtt_new_ssl(cfg.host, cfg.port, cfg.ssl, cfg.crt_file, cfg.ssl_verify);
    if (gcl) {
        gcl->on_conack = on_conack;
        gcl->on_suback = on_suback;
        gcl->on_publish = on_publish;
        gcl->on_error = on_error;
        gcl->on_close = on_close;

        if (gcl->connect(gcl, &cfg.options, &cfg.will) < 0) {
            ULOG_ERR("connect failed\n");
            uloop_end();
        }
        return;
    }

    if (uloop_cancelled || !cfg.auto_reconnect)
        uloop_end();
    else
        uloop_timeout_set(&reconnect_timer, RECONNECT_INTERVAL * 1000);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
        "      -h host      # Default is 'localhost'\n"
        "      -p port      # Default is 1883\n"
        "      -c file      # Load CA certificates from file\n"
        "      -n           # don't validate the server's certificate\n"
        "      -s           # Use ssl\n"
        "      -a           # Auto reconnect to the server\n"
        , prog);
    exit(1);
}

int main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "h:p:nc:sa")) != -1) {
        switch (opt)
        {
        case 'h':
            cfg.host = optarg;
            break;
        case 'p':
            cfg.port = atoi(optarg);
            break;
        case 's':
            cfg.ssl = true;
            break;
        case 'n':
            cfg.ssl_verify = false;
            break;
        case 'c':
            cfg.crt_file = optarg;
            break;
        case 'a':
            cfg.auto_reconnect = true;
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    ULOG_INFO("libumqttc version %s\n", UMQTT_VERSION_STRING);

    uloop_init();

    reconnect_timer.cb = do_connect;
    uloop_timeout_set(&reconnect_timer, 100);

    uloop_run();

    if (gcl)
        gcl->free(gcl);

    uloop_done();
    
    return 0;
}
