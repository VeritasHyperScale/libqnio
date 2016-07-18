/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef IO_IOV_HEADER_INCLUDED
#define IO_IOV_HEADER_INCLUDED

#include <assert.h>
#include <stddef.h>
#include "types.h"
#include "qnio.h"

#define IO_IOV_MAX                  1024+1

/*
 * IOV I/O buffer descriptor
 */
struct io_iov
{
    struct iovec bufs[IO_IOV_MAX];
    struct iovec *start;
    size_t start_index;
    size_t count;
    size_t total;
};

static __inline void
io_iov_clear(struct io_iov *iov)
{
    iov->start = &iov->bufs[0];
    iov->total = iov->start_index = iov->count = 0;
}

static __inline void
io_iov_add(struct io_iov *iov, struct iovec *vec)
{
    if(iov->count == IO_IOV_MAX)
    {
        return;
    }
    iov->bufs[iov->count].iov_base = vec->iov_base;
    iov->bufs[iov->count].iov_len = vec->iov_len;
    iov->total += vec->iov_len;
    iov->count++;
}

static __inline void
io_iov_wrote(struct io_iov *iov, size_t n)
{
    iov->total -= n;

    while(n != 0)
    {
        if( n >= iov->start->iov_len)
        {
            n -= iov->start->iov_len;
            iov->start_index++;
            iov->start = &iov->bufs[iov->start_index];
        }
        else
        {
            iov->start->iov_base += n;
            iov->start->iov_len = (iov->start->iov_len - n);
            break;
        }
    }
}

static __inline int
io_iov_count(struct io_iov *iov)
{
    return (iov->count - iov->start_index);
}

static __inline size_t
io_iov_data_len(struct io_iov *iov)
{
    return iov->total;
}

#endif /* IO_IOV_HEADER_INCLUDED */
