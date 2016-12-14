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

#define IO_IOV_MAX                  1024+1

/*
 * IOV I/O buffer descriptor
 */

struct io_iov
{
    struct iovec iovec[IO_IOV_MAX];
    struct iovec *cur_iovec;
    int iovec_cnt;
    int cur_index;
    size_t iosize;
    size_t cur_offset;
};

static __inline void
io_iov_clear(struct io_iov *iov)
{
    iov->cur_iovec = &iov->iovec[0];
    iov->cur_index = iov->iovec_cnt = 0;
    iov->iosize = iov->cur_offset = 0;
}

static __inline void
io_iov_add(struct io_iov *iov, struct iovec *vec)
{
    if(iov->iovec_cnt == IO_IOV_MAX) {
        return;
    }
    iov->iovec[iov->iovec_cnt].iov_base = vec->iov_base;
    iov->iovec[iov->iovec_cnt].iov_len = vec->iov_len;
    iov->iosize += vec->iov_len;
    iov->iovec_cnt++;
}

static __inline void
io_iov_forword(struct io_iov *iov, size_t n)
{
    iov->cur_offset += n;
    while(n != 0) {
        if( n >= iov->cur_iovec->iov_len) {
            n -= iov->cur_iovec->iov_len;
            iov->cur_index++;
            iov->cur_iovec = &iov->iovec[iov->cur_index];
        } else {
            iov->cur_iovec->iov_base += n;
            iov->cur_iovec->iov_len = (iov->cur_iovec->iov_len - n);
            break;
        }
    }
}

static __inline int
io_iov_count(struct io_iov *iov)
{
    return (iov->iovec_cnt - iov->cur_index);
}

static __inline size_t
io_iov_remaining_payload(struct io_iov *iov)
{
    return iov->iosize - iov->cur_offset;
}

#endif /* IO_IOV_HEADER_INCLUDED */
