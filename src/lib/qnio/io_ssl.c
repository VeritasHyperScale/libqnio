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
read_ssl(struct endpoint *endpoint, void *buf, size_t len)
{
    assert(endpoint->ssl != NULL);
    return (SSL_read(endpoint->ssl, buf, len));
}

static int
write_ssl(struct endpoint *endpoint, const void *buf, size_t len)
{
    assert(endpoint->ssl != NULL);
    return (SSL_write(endpoint->ssl, buf, len));
}

static int
readv_ssl(struct endpoint *endpoint, struct iovec *vec, int count) 
{
    int i, total_count = 0;

    assert(endpoint->ssl != NULL);
    for (i=0; i<count; i++) {
        total_count += SSL_read(endpoint->ssl, vec[i].iov_base,
                                vec[i].iov_len);
    }
    return total_count;
}

static int
writev_ssl(struct endpoint *endpoint, struct iovec *vec, int count)
{
    int i, total_count = 0;

    assert(endpoint->ssl != NULL);
    for (i=0; i<count; i++) {
        total_count += SSL_write(endpoint->ssl, vec[i].iov_base,
                                 vec[i].iov_len);
    }
    return total_count;
}


static void
close_ssl(struct endpoint *endpoint)
{
    assert(endpoint->sock != -1);
    SSL_free(endpoint->ssl);
    close(endpoint->sock);
}

const struct io_class io_ssl = {
    "ssl",
    read_ssl,
    write_ssl,
    close_ssl,
    readv_ssl,
    writev_ssl
};
