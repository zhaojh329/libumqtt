/*
 * MIT License
 *
 * Copyright (c) 2019 Jianhui Zhao <zhaojh329@gmail.com>
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
 
#ifndef _UMQTT_LOG_H
#define _UMQTT_LOG_H

#include <syslog.h>
#include <string.h>

void umqtt_log_threshold(int threshold);
void umqtt_log_close();

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define umqtt_log(priority, fmt...) __umqtt_log(__FILENAME__, __LINE__, priority, fmt)

#define umqtt_log_debug(fmt...)     umqtt_log(LOG_DEBUG, fmt)
#define umqtt_log_info(fmt...)      umqtt_log(LOG_INFO, fmt)
#define umqtt_log_warn(fmt...)      umqtt_log(LOG_WARNING, fmt)
#define umqtt_log_err(fmt...)       umqtt_log(LOG_ERR, fmt)

void  __umqtt_log(const char *filename, int line, int priority, const char *fmt, ...);

#endif
