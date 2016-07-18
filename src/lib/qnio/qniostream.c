/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "datastruct.h"


QNIO_API_(qnio_stream *) new_qnio_stream(size_t size)
{
    qnio_stream *stream;

    stream = (qnio_stream *)malloc(sizeof (qnio_stream));
    if (!size)
    {
        size = 256;
    }
    stream->buffer = (unsigned char *)malloc(size);
    stream->max = size;
    stream->pos = 0;
    stream->size = 0;
    return (stream);
}

QNIO_API_(size_t)
qnio_write_stream(qnio_stream * stream, unsigned char *buffer, size_t size)
{
    size_t grow_to;
    size_t vsize = size + 1;    /* Allocate for an extra NULL */

    if (vsize > (stream->max - stream->pos))
    {
        /*
         * We need to create space, let us double it
         */
        grow_to = stream->max > vsize ? stream->max : vsize;

        grow_to += stream->max;
        stream->buffer = (unsigned char *)realloc(stream->buffer, grow_to);
        if (stream->buffer == NULL)
        {
            return (0);
        }
        stream->max = grow_to;
    }
    /*
     * We have enough space
     */
    memcpy(&(stream->buffer[stream->pos]), buffer, size);
    stream->pos += size;
    stream->buffer[stream->pos] = '\0';
    /*
     * The size of the stream does not need to include NULL, which is
     * optional
     */
    stream->size = (stream->size > stream->pos ? stream->size : stream->pos);
    return (size);
}

QNIO_API_(int) qnio_print_stream(int fd, qnio_stream * stream)
{
    size_t x = 0;
    size_t count = stream->size;

    while (x != count)
    {
        x = write(fd, stream->buffer, (unsigned int)count);
        if (x != count)
        {
            count -= x;
        }
    }
    return (0);
}

QNIO_API_(void) qnio_delete_stream(qnio_stream * stream)
{
    if (stream->buffer)
    {
        free(stream->buffer);
    }
    free(stream);
}

/* This routine is safe in the sense that it does not use a fixed buffer size */
QNIO_API_(size_t) qnio_vprintf_stream(qnio_stream * stream, const char *fmt, ...)
{
    size_t  size = 1024;
    size_t  rc = 0;
    va_list ap;

    while (rc == 0)
    {
        va_start(ap, fmt);
        rc = qnio_get_vprintf_size(fmt, &size, ap);
        va_end(ap);
    }
    va_start(ap, fmt);
    rc = qnio_vprintf_stream_va(stream, size, fmt, ap);
    va_end(ap);
    return (rc);
}

QNIO_API_(size_t)
qnio_vprintf_stream_va(qnio_stream * stream, size_t size, const char *fmt,
                     va_list ap)
{
    char  *buff = NULL;
    size_t rc;

    buff = (char *)malloc(size + 1);
#ifdef WIN32
    rc = _vsnprintf(buff, size, fmt, ap);
#else
    rc = vsnprintf(buff, size, fmt, ap);
#endif
    buff[rc] = '\0';
    qnio_write_stream(stream, (unsigned char *)buff, rc);

    free(buff);
    return ((size_t)rc);
}

QNIO_API_(size_t) qnio_get_vprintf_size(const char *fmt, size_t * size,
                                    va_list ap)
{
    char *buff = NULL;
    int   rc = -1;

    buff = (char *)malloc(*size + 1);
    rc = vsnprintf(buff, *size, fmt, ap);
    free(buff);
    if (rc > (int)(*size))
    {
        (*size) *= rc;
        return (0);
    }
    return ((size_t)rc);
}
