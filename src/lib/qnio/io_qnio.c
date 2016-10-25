/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <pthread.h>
#include "qnio.h"
#include "defs.h"

static int
write_qnio(struct endpoint *endpoint, const void *buf, size_t len)
{
    return (0);
}

static int
read_qnio(struct endpoint *endpoint, void *buf, size_t len)
{
    return (0);
}

static void
close_qnio(struct endpoint *endpoint)
{
    return;
}

const struct io_class io_qnio = {
    "qnio",
    read_qnio,
    write_qnio,
    close_qnio
};
