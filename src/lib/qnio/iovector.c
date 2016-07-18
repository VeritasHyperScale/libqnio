/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/uio.h>
#include "datastruct.h"

QNIO_API_(io_vector *)
new_io_vector(int size, io_destructor fn)
{
    io_vector *ivec;

    size = size < 8 ? 8 : size;
    ivec = (io_vector *)malloc(sizeof (io_vector));
    memset(ivec, 0, sizeof (io_vector));
    ivec->_iovec = (struct iovec *)malloc(sizeof (struct iovec) * size);
    memset(ivec->_iovec, 0, (sizeof (struct iovec) * size));
    ivec->_max = size;
    ivec->_dtor = fn;
    return (ivec);
}

QNIO_API_(void)
io_vector_delete(io_vector * ivec)
{
    if (ivec->_iovec)
    {
        free(ivec->_iovec);
    }

    free(ivec);
}

QNIO_API_(void)
io_vector_dup(io_vector * src, io_vector * dest)
{
    if (dest->_max < src->_count)
    {
        dest->_iovec = (struct iovec *)realloc(dest->_iovec,
                                                 sizeof (struct iovec) *
                                                 src->_max);
    }
    memcpy(dest->_iovec, src->_iovec, sizeof (struct iovec) * src->_count);
    dest->_count = src->_count;
    dest->_dtor = src->_dtor;
    dest->_total_size = src->_total_size;
}

QNIO_API_(void)
io_vector_insert_at(io_vector * ivec, struct iovec vec, int idx)
{
    if (idx >= ivec->_max)
    {
        ivec->_iovec = (struct iovec *)realloc(ivec->_iovec,
                                                 sizeof (struct iovec) *
                                                 (idx + 1));
        memset(&ivec->_iovec[ivec->_max], 0,
               (sizeof (void *) * (idx - ivec->_max + 1)));
        ivec->_max = idx + 1;
    }
    ivec->_iovec[idx] = vec;
    ivec->_count++;
}

QNIO_API_(void)
io_vector_insert(io_vector * ivec, struct iovec vec, int idx)
{
    int tmp = ivec->_max * 2;

    if (ivec->_count == ivec->_max)
    {
        if (ivec->_max == 0)
        {
            ivec->_iovec = (struct iovec *)malloc(sizeof (struct iovec) * 8);
            tmp = 8;
        }
        else
        {
            ivec->_iovec =
                (struct iovec *)realloc(ivec->_iovec,
                                          sizeof (struct iovec) * tmp);
        }
        ivec->_max = tmp;
    }
    memmove(&(ivec->_iovec[idx + 1]),
            &(ivec->_iovec[idx]), (ivec->_count - idx) * sizeof (struct iovec));
    ivec->_iovec[idx] = vec;
    ivec->_count++;
    ivec->_total_size += vec.iov_len;
}

QNIO_API_(struct iovec)
io_vector_remove(io_vector *ivec, int idx)
{
    struct iovec tmp;

    tmp = ivec->_iovec[idx];
    memmove(&(ivec->_iovec[idx]),
            &(ivec->_iovec[idx + 1]),
            (ivec->_count - idx - 1) * sizeof (struct iovec));
    ivec->_iovec[(ivec->_count) - 1] = (struct iovec) {NULL, 0 };
    ivec->_count--;
    ivec->_total_size -= tmp.iov_len;
    return (tmp);
}

QNIO_API_(struct iovec)
io_vector_at(io_vector *ivec, int idx)
{
    return (ivec->_iovec[idx]);
}

QNIO_API_(void)
io_vector_pushfront(io_vector * ivec, struct iovec vec)
{
    io_vector_insert(ivec, vec, 0);
}

QNIO_API_(void)
io_vector_pushback(io_vector * ivec, struct iovec vec)
{
    int tmp = ivec->_max * 2;

    if (ivec->_count == ivec->_max)
    {
        ivec->_iovec =
            (struct iovec *)realloc(ivec->_iovec, sizeof (struct iovec) *
                                      tmp);
        ivec->_max = tmp;
    }
    ivec->_iovec[ivec->_count] = vec;
    ivec->_count++;
    ivec->_total_size += vec.iov_len;
}

QNIO_API_(struct iovec)
io_vector_popfront(io_vector *ivec)
{
    return (io_vector_remove(ivec, 0));
}

QNIO_API_(struct iovec)
io_vector_popback(io_vector *ivec)
{
    return (io_vector_remove(ivec, (ivec->_count) - 1));
}

QNIO_API_(void)
io_vector_clear(io_vector * ivec, io_destructor fn)
{
    int i;

    if (ivec->_count)
    {
        if (fn)
        {
            for (i = 0; i < ivec->_count; i++)
            {
                fn(ivec->_iovec[i]);
            }
        }
        i = ivec->_count;
        ivec->_count = 0;
        ivec->_total_size = 0;
        memset(ivec->_iovec, 0, sizeof (struct iovec) * i);
    }
}

QNIO_API_(void)
io_vector_destroy(io_vector * ivec)
{
    if (ivec->_dtor)
    {
        io_vector_clear(ivec, ivec->_dtor);
    }

    io_vector_delete(ivec);
}

QNIO_API_(int)
io_vector_count(io_vector * ivec)
{
    return (ivec->_count);
}

QNIO_API_(int)
io_vector_size(io_vector * ivec)
{
    return (ivec->_total_size);
}

QNIO_API_(struct iovec *)
io_vector_addr(io_vector * ivec)
{
    return (ivec->_iovec);
}
