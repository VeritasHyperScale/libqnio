/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "defs.h"

void
set_close_on_exec(int fd)
{
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int
make_socket_non_blocking(int sfd)
{
    int flags, s;
    int nodelay = 1;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        nioDbg("fcntl error");
        return (-1);
    }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        nioDbg("fcntl error");
        return (-1);
    }
    setsockopt(sfd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    return (0);
}

int
compare_key(const void *x, const void *y)
{
    return (strcmp((const char *)x, (const char *)y));
}

int
compare_int(const void *x, const void *y)
{
    return ((*(int *)x) - (*(int *)y));
}
