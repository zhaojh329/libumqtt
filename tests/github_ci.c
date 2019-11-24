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

// NOTE: For encryption, specify -s on the commandline (e.g. ./example/example -s)
static struct config cfg = {
    .host = "localhost",
    .port = 1883,
    .options = {
        .keep_alive = 30,
        .clean_session = true,
        .username = "test",
        .password = "123456", // This is literally the most used password in the world. Do not use it for real.
        .will_topic = "will",
        .will_message = "This is An Example Last Will and Testament"
    }
};

static void start_reconnect(struct ev_loop *loop)
{
    if (!cfg.auto_reconnect) {
        fprintf(stdout, "Not Attempting Reconnect!!!\n"); // I Think Github Removes STDERR By Default!!!
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
        fprintf(stdout, "Connection Failed!!!"); // I Think Github Removes STDERR By Default!!!
        umqtt_log_err("Connect failed:%d\n", code);
        return;
    }

    umqtt_log_info("on_conack:  Session Present(%d)  code(%u)\n", sp, code);

    /* Session Present */
    if (!sp)
        cl->subscribe(cl, topics, ARRAY_SIZE(topics));

    fprintf(stdout, "Sending to test4!!!\n"); // I Think Github Removes STDERR By Default!!!
    cl->publish(cl, "test4", "hello world", strlen("hello world"), 2, false);
    exit(1); // Quit After Send!!!
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
    umqtt_log_info("on_unsuback\n");
    umqtt_log_info("Normal quit\n");

    ev_break(cl->loop, EVBREAK_ALL);
}


static void on_publish(struct umqtt_client *cl, const char *topic, int topic_len,
    const void *payload, int payloadlen)
{
    fprintf(stdout, "Published %s To Topic %s!!!\n", (char *) payload, topic); // I Think Github Removes STDERR By Default!!!
    umqtt_log_info("on_publish: topic:[%.*s] payload:[%.*s]\n", topic_len, topic,
        payloadlen, (char *)payload);
}

static void on_pingresp(struct umqtt_client *cl)
{
  fprintf(stdout, "Received Ping From Server!!!\n"); // I Think Github Removes STDERR By Default!!!
}

static void on_error(struct umqtt_client *cl, int err, const char *msg)
{
    fprintf(stdout, "MQTT Error %d: %s\n", err, msg); // I Think Github Removes STDERR By Default!!!
    umqtt_log_err("on_error: %d: %s\n", err, msg);

    start_reconnect(cl->loop);
    free(cl);
}

static void on_close(struct umqtt_client *cl)
{
    fprintf(stdout, "MQTT Closed!!!\n"); // I Think Github Removes STDERR By Default!!!
    umqtt_log_info("on_close\n");

    start_reconnect(cl->loop);
    free(cl);
}

static void on_net_connected(struct umqtt_client *cl)
{
    fprintf(stdout, "Attempt Connection!!!\n"); // I Think Github Removes STDERR By Default!!!
    umqtt_log_info("on_net_connected\n");

    if (cl->connect(cl, &cfg.options) < 0) {
        fprintf(stdout, "Connection Failed!!!\n"); // I Think Github Removes STDERR By Default!!!
        umqtt_log_err("connect failed\n");

        start_reconnect(cl->loop);
        free(cl);
    }
}

static void do_connect(struct ev_loop *loop, struct ev_timer *w, int revents)
{
    fprintf(stdout, "Attempt MQTT Start!!!\n"); // I Think Github Removes STDERR By Default!!!
    struct umqtt_client *cl;

    cl = umqtt_new(loop, cfg.host, cfg.port, cfg.ssl); // This is the problem line of code in Github's CI Test
    if (!cl) {
        fprintf(stdout, "Failed To Create Client!!!\n"); // I Think Github Removes STDERR By Default!!!
        start_reconnect(loop);
        return;
    }

    fprintf(stdout, "Setup Client Callbacks!!!\n"); // I Think Github Removes STDERR By Default!!!
    cl->on_net_connected = on_net_connected;
    cl->on_conack = on_conack;
    cl->on_suback = on_suback;
    cl->on_unsuback = on_unsuback;
    cl->on_publish = on_publish;
    cl->on_pingresp = on_pingresp;
    cl->on_error = on_error;
    cl->on_close = on_close;

    fprintf(stdout, "MQTT Start!!!\n"); // I Think Github Removes STDERR By Default!!!
    umqtt_log_info("Start connect...\n");
}

static void signal_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
    ev_break(loop, EVBREAK_ALL);
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [option]\n"
        "      -h host      # Default is 'localhost'\n"
        "      -p port      # Default is 1883\n"
        "      -i ClientId  # Default is 'libumqtt-github-tests'\n"
        "      -s           # Use ssl\n"
        "      -a           # Auto reconnect to the server\n"
        "      -d           # enable debug messages\n"
        , prog);
    exit(0);
}

int main(int argc, char **argv)
{
    struct ev_loop *loop = EV_DEFAULT;
    struct ev_signal signal_watcher;
    int opt;

    while ((opt = getopt(argc, argv, "h:i:p:sadz")) != -1) {
        switch (opt) {
        case 'h':
            cfg.host = optarg;
            break;
        case 'p':
            cfg.port = atoi(optarg);
            break;
        case 's':
            cfg.ssl = true;
            break;
        case 'a':
            cfg.auto_reconnect = true;
            break;
        case 'i':
            cfg.options.client_id = optarg;
            break;
        case 'd':
            umqtt_log_threshold(LOG_DEBUG);
            break;
        default: /* '?' */
            usage(argv[0]);
        }
    }

    // Get Secrets From Github CI
    cfg.options.username = getenv("mqtt_username");
    cfg.options.password = getenv("mqtt_password");

    // fprintf(stdout, "Fake Hostname: %s\n", cfg.host);
    // fprintf(stdout, "Fake Username: %s\n", getenv("mqtt_username"));
    // fprintf(stdout, "Fake Password: %s\n", getenv("mqtt_password"));

    fprintf(stdout, "Fake Data Block Test: FakeData\n"); // Yep, Manually Put In To Test Github Blocking In Logs

    if (!cfg.options.client_id)
        cfg.options.client_id = "libumqtt-github-tests";

    ev_signal_init(&signal_watcher, signal_cb, SIGINT);
    ev_signal_start(loop, &signal_watcher);

    ev_timer_init(&reconnect_timer, do_connect, 0.1, 0.0);
    ev_timer_start(loop, &reconnect_timer);

    umqtt_log_info("libumqttc version %s\n", UMQTT_VERSION_STRING);

    fprintf(stdout, "Start Loop!!!\n"); // I Think Github Removes STDERR By Default!!!
    ev_run(loop, 0);
    fprintf(stdout, "End Loop!!!\n"); // I Think Github Removes STDERR By Default!!!

    exit(-1);
    return 0;
}
