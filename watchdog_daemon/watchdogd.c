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

/* Filename:	watchdogd.c */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <android/log.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>

#include "watchdogd.h"

/* This is used by the Android logging system */
#define LOG_TAG "ia_watchdog"

static int watch_read_fd;

/* Maximum fd; global so that anyone can bump it up if they have to */
static int	max_fd = 0;

/* Global for wfd for signal capture */
static int	global_wfd = 0;

/* Following record s kept for each client process */
typedef struct {
	int	cfd;
	int	responded;
	char	id[CLIENT_ID_SIZE];
	int	zero_reads;
} client_rec_t;

/* Function allocates and zeroes out initial client table */
client_rec_t *Create_Client_Table(int MaxClients) {
	client_rec_t	*clients = NULL;

	/* Allocate memory for client table */
	clients = calloc(MaxClients, sizeof(client_rec_t));
	if (clients == NULL) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Create_Client_Table: Unable to allocate memory\n");
		exit (1);
	}
	return clients;
}; /* End of Create_Client_Table */

int Open_Watchdog_Device(void)
{

	/* Normal operation, just open Watchdog Device */

	watch_read_fd = open(WATCHDOG_DEVICE, WATCHDOG_FLAGS);
	if (watch_read_fd == -1) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Watchdog Daemon Disabled, Unable to open %s\n",
			WATCHDOG_DEVICE);
		return (-1);
	} else {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Open_Watchdog_Device: %s, file descriptor: %d\n",
			WATCHDOG_DEVICE, watch_read_fd);
	}

	if (watch_read_fd > max_fd)
		max_fd = watch_read_fd;

	return watch_read_fd;

}; /* End of Open_Watchdog_Device Function */

/* Function: Close_Watchdog_Device
 * Close connections to Watchdog Device. This should cause a system
 * reset. Hence this function is not expected to return to the caller.
 *
 * Parameters:	None
 *
 * Return:	None
 */

void Close_Watchdog_Device(void)
{

	__android_log_print(ANDROID_LOG_INFO, LOG_TAG,
	"Forcing System Reset by closing Watchdog Device");
	close (watch_read_fd);
	exit(-1);

}; /* End of Close_Watchdog_Device Function */


/* Function: Read_Watchdog_Device
 * Reads Watchdog Device to clear out last refresh request
 *
 * Parmeters:	wfd		File descriptor for Watchdog Device
 *
 * Return:	None
 */
void Read_Watchdog_Device(int wfd) {

	int	rsize;
	char	rbuf[WMSG_MAX];

	rsize = read(wfd, rbuf, WMSG_MAX);
	if (rsize < 0) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Error reading Watchdog Device");
	};

} /* End of Read_Watchdog_Device Function */

int Create_Socket()
{
	int			sfd;
	int			stat_ret;
	int			bind_res;

	struct sockaddr_un	addr;
	struct stat		sockstat;

	sfd = socket(AF_LOCAL, SOCK_STREAM, 0);

	if (sfd > max_fd)
		max_fd = sfd;

	/* Check to see if the socket bind point already exists */
	stat_ret = stat(WATCH_SOCKET, &sockstat);
	if (stat_ret == 0) {
		/* Bind already exists, so unlink (i.e. delete) it */
		(void) unlink(WATCH_SOCKET);
	}


	/* Bind the socket to a local name */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = PF_LOCAL;
	strncpy(addr.sun_path, WATCH_SOCKET,
		sizeof(addr.sun_path) - 1);

	bind_res = bind(sfd, (struct sockaddr *) &addr,
		sizeof(addr.sun_family) + strlen(addr.sun_path));
	if (bind_res != 0) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Watchdog Disabled, Unable to bind socket to %s: %s\n",
			 WATCH_SOCKET,
			 strerror(errno));
		return (-1);
	}

	return sfd;
};

void Client_Read(int z, client_rec_t *clients)
{
	int		n;
	int		cfd = clients[z].cfd;
	char		buf[CLIENT_READ_BUFFER_SIZE];
	client_resp_t	*resp = (client_resp_t *)&buf;

	/**
	 * This read is from a client that is included in a select
	 * call at about lines 660 to 670. An iteration loop at line
	 * 685 does the FD_SET for the cfd for each active client.
	 * At about line 715, there is a loop. For each client that
	 * is active, the call to this Client_Read is made; for those
	 * that are not set, this Client_Read is not called. Therefore,
	 * this read should return. That client was from an accept;
	 * and then an fcntl to force NOWAIT (at about line 566)
	 */
	n=read(cfd,buf,CLIENT_READ_BUFFER_SIZE);
	if (n == 0) {
		/* Count times this client gave a zero response */
		if (MAX_BAD_READ <= clients[z].zero_reads++) {
			/* Client not responding correctly. Force Reset  */
			/* by closing all connections to Watchdog Device */
			Close_Watchdog_Device();
		}
		/* Treat as no-response from the client */
		clients[z].responded = false;
		return;

	}
	if (n == -1) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Error reading socket");
		return;
	}

	/* Check the client's response */
	if (cfd == resp->c_uid) {
		/* Client is on the right socket. Check ID string */
		if (clients[z].id[0] == 0) {
			/* Client's first response, copy ID string */
			strncpy(clients[z].id,resp->c_sid,CLIENT_ID_SIZE);
			clients[z].id[CLIENT_ID_SIZE-1] = 0;
		} else {
			if (strncmp(clients[z].id,resp->c_sid,CLIENT_ID_SIZE)) {
				__android_log_print(ANDROID_LOG_INFO, LOG_TAG,
				"Client ID change, old: %s  new: %s\n",
			 		clients[z].id, resp->c_sid);
				return;
			}
		}
	} else {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Client %s sent wrong ID code\n", clients[z].id);
		return;
	}
	/* Client response was OK, mark client as having responded */
	clients[z].responded = true;
	/* Zero the zero_response_count */
	clients[z].zero_reads = 0;

	return;

}; /* End of Client_Read Function */

/* Function: Start_Client_Check
 * Initiates check on clients by:
 *    - Clearing client response fields in Client Table,
 *    - Sending ENQUIRY byte to all the client sockets in Client Table
 *
 * Parameters:	clients		Pointer to Client Table
 * 		MaxClients	Number of enties in Client Table
 *
 * Return:	None
 */
void Start_Client_Check(client_rec_t *clients, int MaxClients) {

	int		z;
	char		enq_msg[2] = {ENQUIRY, 0};
	ssize_t		wsize;
	int		client_count = 0;

	for (z=0 ; z < MaxClients; z++) {
		if (clients[z].cfd != 0) {
			clients[z].responded = false;

			/* Send keep-alive request to each client */

			wsize = write(clients[z].cfd,enq_msg,1);
			client_count++;
			if (wsize != 1) {
				__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
					"Problem writing to client socket: %s\n",
					strerror(errno));
			}
		} else {
			clients[z].responded = true;
		}
	}
	return;
} /* End of Start_Client_Check Function */

/* Function: All_CLients_Responded
 * Scans Client Table to see if all the known clients have responsed
 * to the latest health ENQUIRY.
 *
 * Parameters:	clients		Pointer to Client Table
 * 		MaxClients	Number of enties in Client Table
 *
 * Return:	true  -> All valid clients have responded
 * 		false -> One or more clients has not responded
 */
int All_Clients_Responded(client_rec_t *clients, int MaxClients)
{
	int		z;
	int		resp_sum = true;

	for (z = 0; z < MaxClients; z++) {
		if (clients[z].cfd != 0)
			resp_sum = resp_sum && clients[z].responded;
	}
	return resp_sum;
}; /* End of All_Clients_Responded function */


/* Function: Set_Watchdog_Threshold
 * Sets the Watchdog Timer Drivers Reset threshold
 *
 * Parameters:
 * wfd		-> File Descriptor for Watchdog Timer Device
 * Reset	-> Time to wait before reseting system, if countdown is
 * 		   not refreshed before this time expires.
 *
 * Return:	None
 */
void Set_Watchdog_Threshold(int wfd, int reset)
{

	int	ioctl_res = 0;
	int	my_reset;

	/* Use values for normal operation */
	my_reset = reset;

	ioctl_res = ioctl(wfd, WDIOC_SETTIMEOUT, &my_reset);
	if (ioctl_res != 0) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Unable to Set Watchdog Timer Threshold: %s\n",
			strerror(errno));
	}
	return;

}; /* End of Set_Watchdog_Threshold function */

/* Function: Refresh_Watchdog
 * Refreshes hardware watchdog timer by writing to Watchdog Timer device.
 *
 * Parameters:	wfd		File Descriptor for opened Watchdog Device
 *
 * Return:	None
 */
void Refresh_Watchdog(int wfd) {

	int	wres;
	char	rbuf[2] = "R";

	wres = 0;
	wres = write(wfd, rbuf, 1);
	if (wres <= 0) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Unable to refresh Watchdog Timer: %s\n",
			strerror(errno));
	}
	return;
}; /* End of Refresh_Watchdog */

/* Function: Catch_sigterm
 * Handler for SIGTERM signals.
 * This function forces a file system sync, to minimze chances of
 * file system corruption and returns without terminating watchdogd.
 * Terminating watchdogd could interfere with an orderly shutdown
 * and syncing of the file systems.
 *
 * Parameters:	sig	Signal number
 *
 * Return:	void
 */
void Catch_sigterm (int sig)
{
	/* Force the file system sync */
	system("sync");

	__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"caught sig %x\n", sig);
	/* Assuming this SIGTERM is part of a shutdown, refresh the  */
	/* the watchdog timer, to provide a predictable time window  */
	/* for the shutdown.					     */
	Refresh_Watchdog(global_wfd);
	/* Return without terminating, to delay possible HW reset by */
	/* watchdog device driver, as long as possible.              */
	return;
};

/* Function: Init_Signal_Handlers
 * Initialize local signal handlers, to intercept POSIX signals.
 * Registers signal handler for SIGTERM.
 *
 * Parameters:	None
 *
 * Return:	None
 */
void Init_Signal_Handlers()
{
	void	*old_sig = NULL;

	/* Register handler to catch SIGTERM */
	old_sig = signal(SIGTERM, Catch_sigterm);

}; /* End of Init_Signal_Handlers */

/* Function: Timeout_Alert
 * Log a Timeout Warning message.  If a montored process check is
 * in progress, include ID strings of any processes which have
 * not responded yet.
 *
 * Parameters:
 * 	check_in_progress -> If true a montored process check is in progress
 * 	clients		  -> Pointer to Client Table.
 * 	MaxClients	  -> Max records in Client Table.
 *
 * Return:
 * 	void
 *
 */
void Timeout_Alert(int check_in_progress, client_rec_t *clients, int MaxClients)
{
	int	z;
	size_t	e_size;
	char	err_msg[ERRMSG_SIZE] = "";

	err_msg[0] = 0;
	if (check_in_progress) {
		strncat(err_msg,
			"Processes Not Responding: ",
			ERRMSG_SIZE);
		/* Scan for unresponsive processes */
		for (z=0; z < MaxClients; z++) {
			if (!clients[z].responded) {
				e_size = strlen(err_msg);
				strncat(err_msg,
					clients[z].id,
					ERRMSG_SIZE-e_size);
				errno = EBUSY;
				exit(-1);
			}
			err_msg[ERRMSG_SIZE-1] = 0;
			__android_log_print(ANDROID_LOG_INFO, LOG_TAG,
			"%s", err_msg);
			/* Client(s) not responding, exit to force reset */
			/* When Watchdog driver is able to force a reset */
			/* change to just log and wait for that reset   */
		}
	} else {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Watchdog Device Not Requesting Refresh");
	}

}; /* End of Timeout_Alert function */


/* Function: New_Client
 * Accepts a new client connection on the server socket and performs
 * new client handshake to exchange ID information with the new client.
 *
 * Parameters:
 * 	sfd 	 -> File Descriptor Server Socket
 * 	clients	 -> Pointer to Client Table. The new client's information
 * 		    will be inserted in this table
 *
 * Return:	Unique ID of new client
 *
 */
int Accept_New_Client(int sfd, client_rec_t *clients, int max_client)
{
	int			ncfd;
	socklen_t		client_len;
	struct sockaddr_un	client_addr;
	char			wbuf[3];
	int			wsize;
	int			z;
	int			res;

	/* Accept the connection */
	client_len = sizeof(client_addr);
	ncfd = accept(sfd,
		(struct sockaddr *)&client_addr,
		&client_len);

	if (ncfd == -1) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Error accepting connection\n");
		exit (1);
	}

	if (ncfd > max_fd)
		max_fd = ncfd;

	res = fcntl(ncfd, F_SETFL, O_NONBLOCK);
	if (res) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Cannot do fcntl to set nonblock on socket\n");
		close(ncfd);
		return (-1);
	}

	for (z=0; z < max_client; z++) {
		/* Scan for first empty entry in client table */
		if (clients[z].cfd == 0) break;
	}
	if (z == max_client) {
		/* Client table full, return error */
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"Client table full. max_client: %d\n", max_client);
		close(ncfd);
		return (-1);
	}

	/* Add the new client to the client list */
	clients[z].cfd = ncfd;
	clients[z].responded = true;
	clients[z].id[0] = 0;
	clients[z].zero_reads = 0;

	/* Send ID information to the New Client */
	wbuf[0]= ACK;
	wbuf[1]= ncfd;
	wbuf[2]= 0;
	wsize = write(ncfd, wbuf, 2);
	if (wsize != 2) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			 "Error writing to client socket: %s\n",
				 strerror(errno));
		close(ncfd);
		return (-1);
	}
	return ncfd;

}; /* End of Accept_New_Client Function */


/********** Start of Main *********/
int main (int argc, char *argv[])
{

	int			MaxClients = 10;     /* Max # of clients */
	/**
	 * The default ResetTimeout is 5 seconds. This
	 * default value is also set in the watchdog
	 * driver. It is established as a constant value
	 * in the driver by the name of DEFAULT_TIME
	 * Please keep this constant the same as the one
	 * in the driver.
	 */
	int			ResetTimeout = DEFAULT_TIME;
	int			SelectTimeout;
	int			arg_x;
	int			lres, z, n;
	int			sfd;	/* File Descriptors */
	int			wfd;
	int			NumClients = 0;
	int			keep_alive_count = 0;

	fd_set			rx_set;
	struct timeval		tout;
	client_rec_t		*clients = NULL;

	/* State variables */
	int		check_in_progress = false;

	while ((arg_x = getopt(argc, argv, "c:C:t:T:")) != -1) {
		switch (arg_x) {
		case 'c':
		case 'C':
			MaxClients = atoi(optarg);
			break;
		case 't':
		case 'T':
			ResetTimeout = atoi(optarg);
			if (ResetTimeout < DEFAULT_SOFT_TO_HARD_MARGIN+1) {
				__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
				"cannot have timer value of less than\n");
				__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
				"DEFAULT_SOFT_TO_HARD_MARGIN (%d) plus 1\n",
					DEFAULT_SOFT_TO_HARD_MARGIN);
				exit (-1);
			}
			break;
		default:
			__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"invalid parameters\n");
			exit (-1);
		}
	}

	/**
	 * Please note that once the device is open, it cannot be
	 * closed without forcing an immediate system reset.
	 * Therefore, any errors either need to be caught and
	 * handled within the main executing loop of this daemon or
	 * if they are considered fatal, simply allowed to exit this
	 * daemon, which will force and immedate hard reset of the
	 * platform.
	 */
	wfd = Open_Watchdog_Device();
	if ( wfd == -1 ) exit (-1);

	global_wfd = wfd;

	Set_Watchdog_Threshold(wfd, ResetTimeout);

	/* Switch our environment over to taret root file system */
	/* So all our log files, sockets, etc are created in the */
	/* target file system and be available after pivot root  */

	/* Setup handlers for all the signals we can handle */
	Init_Signal_Handlers();

	/* This is the socket that new clients use to register */
	sfd = Create_Socket();

	/* Create the listen queue for the socket */
	lres = listen(sfd,WDOG_CLIENT_BACKLOG);
	if (lres < 0) {
		__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
		"Socket listen error %s\n", strerror(errno));
		exit (-1);
	}

	if (wfd > sfd)
		max_fd = wfd;

	/* Create/Initialize the Client Table */
	clients = Create_Client_Table(MaxClients);

	/**
	 * Set initial timeout for logging reset warning; please note
	 * that this time is DEFAULT_SOFT_TO_HARD_MARGIN seconds prior
	 * to the time at which the system will be reset if the keep
	 * alive messages are not received from all client prcesses.
	 * Please be sure that this constant is kept the same as the
	 * constant by the same name in the watchdog driver source code
	 */
	SelectTimeout = ResetTimeout -
		DEFAULT_SOFT_TO_HARD_MARGIN;

	tout.tv_sec = SelectTimeout;
	tout.tv_usec = 0;

	/* Start server loop */
	for (;;) {

		/* Create file descriptor set for select() */
		FD_ZERO(&rx_set);
		FD_SET(sfd, &rx_set);
		FD_SET(wfd, &rx_set);

		for (z=0; z<MaxClients; z++) {
			if (clients[z].cfd != 0) {
				FD_SET(clients[z].cfd, &rx_set);
			}
		}

		/* Use select to wait for something */
		n = select(max_fd+1,&rx_set,NULL,NULL,&tout);
		if (n == -1) {
			__android_log_print(ANDROID_LOG_ERROR, LOG_TAG,
			"select error\n");
			exit(1);
		} else if (!n) {
			/* select timed out, do check and go back to select */
			Timeout_Alert(check_in_progress,
					clients,
					MaxClients);
			if (check_in_progress) {
				tout.tv_sec = SelectTimeout;
				tout.tv_usec = 0;
			} else {
				tout.tv_sec = DEFAULT_SOFT_TO_HARD_MARGIN - 1;
				tout.tv_usec = 0;
			continue;
			}
		}


		/* Check for read action on Watchdog device */
		__android_log_print(ANDROID_LOG_INFO, LOG_TAG,
			"IF_ISSET on wfd is %x\n",
			FD_ISSET(wfd,&rx_set));

		if (FD_ISSET(wfd,&rx_set)) {
			/* Watchdog Keep Alive Request */
			Read_Watchdog_Device(wfd);

			Start_Client_Check(clients, MaxClients);
			/* Set warning timeout for client check */
			tout.tv_sec = DEFAULT_SOFT_TO_HARD_MARGIN - 1;
			tout.tv_usec = 0;

			check_in_progress = true;
			/* Increment Keep Alive Request Count */
			keep_alive_count++;
		}

		if (FD_ISSET(sfd,&rx_set)) {

			/* Setup New Client Connection */
			if (MaxClients > NumClients) {
				Accept_New_Client(sfd,clients,MaxClients);
			}
		}

		/* Check for client responses to ENQUIRY */

		for (z=0; z<MaxClients; z++) {

			if (FD_ISSET(clients[z].cfd,&rx_set)) {
				Client_Read(z, clients);
			}
		}
		/* If a client check is in progress, check for responses */
		if (check_in_progress) {

			if (All_Clients_Responded(clients, MaxClients)) {
				Refresh_Watchdog(wfd);
				check_in_progress = false;
				/* Reset the select timeout warning */
				tout.tv_sec = SelectTimeout;
				tout.tv_usec = 0;
			}

		}

	} /* End of Server loop */

	/* Leaving the Server loop means a system reset. */
	exit (0);
};
