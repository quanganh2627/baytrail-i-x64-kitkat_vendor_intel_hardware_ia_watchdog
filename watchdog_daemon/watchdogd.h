/**
 * Copyright 2009 - 2010 (c) Intel Corporation. All rights reserved.

 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://www.apache.org/licenses/LICENSE-2.0

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Filename:	watchdogd.h */

#ifndef _WATCHDOGD_H
#define _WATCHDOGD_H

#define	WATCHDOG_IOCTL_BASE	'W'
#define	WDIOC_SETTIMEOUT	_IOWR(WATCHDOG_IOCTL_BASE, 6, int)

#define WATCH_SOCKET		"/data/misc/watch_socket"
#define WATCHDOG_DEVICE 	"/dev/watchdog"

/* Flags used to open watchdog device */
#define WATCHDOG_FLAGS O_RDWR | O_NONBLOCK | O_SYNC | O_EXCL

/* Maximum backlog for new client requests */
#define WDOG_CLIENT_BACKLOG	5

#define WMSG_MAX		80	/* Maximum watchdog message size from device */
#define CLIENT_READ_BUFFER_SIZE 80	/* read buffer for client reads */
#define CLIENT_ID_SIZE		20	/* Maximum size for a client ID string */
#define MAX_BAD_READ		8	/* Maximum times for bad read from client */

/* maximum size of accumulated error messages from client processes */
#define ERRMSG_SIZE	256

typedef struct {
	int	c_uid;
	char	c_sid[CLIENT_ID_SIZE];
} client_resp_t;

/* Identification of messages between daemon and clients */
#define ENQUIRY			'\x05'
#define ACK			'\x06'

/**
 * This is the default time to system reset. Once the timer is
 * started (device is opened), the timer will start. At about
 * this time (DEFULT_TIME) minus DEFAULT_SOFT_TO_HARD_MARGIN,
 * a keep alive request will be made available for read from
 * the device. Upon receipt of that keep alive request, this
 * daemon must respond with a keep alive response within
 * the DEFAULT_SOFT_TO_HARD_MARGIN time. If not, the system
 * will be reset by the timer.
 */
#define DEFAULT_TIME		75

/**
 * The DEFAULT_SOFT_TO_HARD_MARGIN is the ammount of time between
 * the timer interrupt (which is used to send out the keep_alive
 * requests) and the time at which the system would be reset if
 * all the keep-alives are not received - please be sure that this
 * constant is set to the same value as the similarly named constant
 * in the watchdog driver source code.
 */
#define DEFAULT_SOFT_TO_HARD_MARGIN 15

/* This is only for compiling in the kboot space */
#ifndef __ANDROID__
#define ANDROID_LOG_ERROR "Error: "
#define ANDROID_LOG_INFO "Information: "
#define __android_log_print(error, tag, args...) \
	printf(tag); \
	printf(":  "); \
	printf(error); \
	printf(args);
#endif /* __ANDROID__ */
#endif /* _WATCHDOGD_H */
