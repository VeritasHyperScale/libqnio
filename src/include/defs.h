/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef QNIODEFS_HEADER_DEFINED
#define QNIODEFS_HEADER_DEFINED    1

#include <stdio.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/eventfd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "types.h"
#include "datastruct.h"
#include "list.h"
#include "io_iov.h"

#ifdef DEBUG_QNIO
#define nioDbg(fmt, ...) {\
        time_t t = time(0); \
        char buf[9] = {0}; \
        strftime(buf, 9, "%H:%M:%S", localtime(&t)); \
        fprintf(stderr, "[%s: %lu] %d: %s():\t" fmt "\n",\
		buf, pthread_self(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}
#else
#define nioDbg(fmt, ...) ((void)0)
#endif /* DEBUG_QNIO */

#endif /* QNIOEFS_HEADER_DEFINED */
