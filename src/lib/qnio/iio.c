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
#include "iio.h"

void
iio_free_io_pool_buf(struct qnio_msg *msg)
{
    if (msg->io_buf == NULL) {
        return;
    }

    if(msg->buf_source == BUF_SRC_USER) {
        nioDbg("not freeing user io buffer");
        return;
    }

    nioDbg("Msg buffer is being freed msgid=%ld %p",
           msg->hinfo.cookie, msg->io_buf);
    if (msg->buf_source == BUF_SRC_POOL) {
        slab_put(msg->io_pool, msg->io_buf);
    } else {
        /* msg->buf_source == BUF_SRC_MALLOC */
        free(msg->io_buf);
    }
    return;
}

struct qnio_msg *
iio_message_alloc(slab_t *msg_pool)
{
    struct qnio_msg *msg;

    msg = (struct qnio_msg *) slab_get(msg_pool);
    memset(msg, 0, sizeof (struct qnio_msg));
    msg->msg_pool = msg_pool;
    return msg;
}

void
iio_message_free(struct qnio_msg *msg)
{
    slab_t *msg_pool;

    assert(msg && msg->msg_pool);
    nioDbg("Msg is returned back to pool msgid=%ld %p", msg->hinfo.cookie,msg);
    msg_pool = msg->msg_pool;
    if (msg->send) {
        io_vector_delete(msg->send);
    }
    if (msg->recv) {
        io_vector_delete(msg->recv);
    }
    iio_free_io_pool_buf(msg);
    slab_put(msg_pool, msg);
    return;
}
