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
#include "qnio.h"

static int
read_socket(struct endpoint *endpoint, void *buf, size_t len)
{
    assert(endpoint->sock != -1);
    return (recv(endpoint->sock, buf, len, 0));
}

static int
write_socket(struct endpoint *endpoint, const void *buf, size_t len)
{
    assert(endpoint->sock != -1);
    return (send(endpoint->sock, buf, len, 0));
}

static int
readv_socket(struct endpoint *endpoint, struct iovec *vec, int count) 
{
    assert(endpoint->sock != -1);
    return (readv(endpoint->sock, vec, count));
}

static int
writev_socket(struct endpoint *endpoint, struct iovec *vec, int count)
{
    assert(endpoint->sock != -1);
    return (writev(endpoint->sock, vec, count));
}


static void
close_socket(struct endpoint *endpoint)
{
    assert(endpoint->sock != -1);
    (void)close(endpoint->sock);
}

const struct io_class io_socket = {
    "socket",
    read_socket,
    write_socket,
    close_socket,
    readv_socket,
    writev_socket
};
