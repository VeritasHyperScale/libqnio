/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef IO_HEADER_INCLUDED
#define IO_HEADER_INCLUDED    1

#include <assert.h>
#include <stddef.h>
#include "types.h"

/*
 *  Opcode for driver well defined interfaces. Well defined
 *  interface use 0x1FFF to 0xFFFF, only last four bit can change.
 *  We will use OPCODE_SHIFT to fetch last four bit and use that
 *  as index.
 */
#define IOR_READ_REQUEST            0x1FFF
#define IOR_WRITE_REQUEST           0x2FFF

#define IOR_SOURCE_TAG_APPIO     0x00000100 /* Tag specific to APP-I/O (QEMU) */

/*
 * I/O buffer descriptor
 */
struct io
{
    qnio_byte_t *buf;         /* IO Buffer			*/
    size_t     size;        /* IO buffer size		*/
    size_t     head;        /* Bytes read			*/
    size_t     tail;        /* Bytes written		*/
    size_t     total;       /* Total bytes read		*/
};

static __inline void
io_clear(struct io *io)
{
    io->total = io->tail = io->head = 0;
}

static __inline qnio_byte_t *
io_space(struct io *io)
{
    return (io->buf + io->head);
}

static __inline qnio_byte_t *
io_data(struct io *io)
{
    return (io->buf + io->tail);
}

static __inline size_t
io_space_len(const struct io *io)
{
    return (io->size - io->head);
}

static __inline size_t
io_data_len(const struct io *io)
{
    return (io->head - io->tail);
}

static __inline void
io_inc_tail(struct io *io, size_t n)
{
    io->tail += n;
    if (io->tail == io->head)
    {
        io->head = io->tail = 0;
    }
}

static __inline void
io_inc_head(struct io *io, size_t n)
{
    io->head += n;
    io->total += n;
}

static __inline void
io_reset(struct io *io)
{
    memmove(io->buf, io_data(io), io_data_len(io));
    io->head = io_data_len(io);
    io->tail = 0;
}

static __inline void
io_assign(struct io *io, struct iovec *vec)
{
    io->buf = vec->iov_base;
    io->head = vec->iov_len;
    io->size = io->total = vec->iov_len;
    io->tail = 0;
}

#endif /* IO_HEADER_INCLUDED */
