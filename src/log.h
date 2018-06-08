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
 
#ifndef _LOG_H
#define _LOG_H

#include <errno.h>
#include <libubox/ulog.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

/*
 * Use the syslog output log and include the name and number of rows at the call
 */
#define umqtt_log(priority, syserr, fmt...) __umqtt_log(__FILENAME__, __LINE__, priority, syserr, fmt)

#define umqtt_log_debug(fmt...)     umqtt_log(LOG_DEBUG, 0, fmt)
#define umqtt_log_info(fmt...)      umqtt_log(LOG_INFO, 0, fmt)
#define umqtt_log_err(fmt...)       umqtt_log(LOG_ERR, 0, fmt)
 #define umqtt_log_serr(fmt...)     umqtt_log(LOG_ERR, errno, fmt)

void  __umqtt_log(const char *filename, int line, int priority, int syserr, const char *fmt, ...);

#endif
