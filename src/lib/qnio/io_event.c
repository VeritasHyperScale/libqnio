/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <sys/eventfd.h>

#include "defs.h"

static int
read_event(struct endpoint *endpoint, void *buf, size_t len)
{
    eventfd_t val;

    assert(endpoint->sock != -1);
    return (eventfd_read(endpoint->sock, &val));
}

static int
write_event(struct endpoint *endpoint, const void *buf, size_t len)
{
    assert(endpoint->sock != -1);
    return (eventfd_write(endpoint->sock, 1));
}

static void
close_event(struct endpoint *endpoint)
{
    assert(endpoint->sock != -1);
    (void)close(endpoint->sock);
}

const struct io_class io_event = {
    "event",
    read_event,
    write_event,
    close_event
};
