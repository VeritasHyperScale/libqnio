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

static void
iio_message_clear(struct qnio_msg *msg)
{
    msg->hinfo = (const struct qnio_header){ 0 };
    msg->buf_source = 0;
    msg->resp_ready = 0;
    msg->ctx = NULL;
    memset(msg->header, 0, HEADER_LEN);
    msg->msg_pool = NULL;
    msg->io_pool = NULL;
    msg->user_ctx = 0;
    msg->lnode = (const struct list_head) { 0 };
    msg->send = NULL;
    msg->recv = NULL;
    msg->io_buf = NULL;
    msg->io_blob = NULL;
    msg->reserved = NULL;
    return;
}

void
iio_free_io_pool_buf(struct qnio_msg *msg)
{
    if(msg->buf_source == BUF_SRC_USER) {
        nioDbg("not freeing user io buffer");
        return;
    }

    if(msg->io_buf != NULL) {
        nioDbg("Msg buffer is being freed msgid=%ld %p",
               msg->hinfo.cookie, msg->io_buf);
        if (msg->buf_source == BUF_SRC_POOL) {
            slab_put(msg->io_pool, msg->io_buf);
        } else {
            /* msg->buf_source == BUF_SRC_MALLOC */
            free(msg->io_buf);
        }
    }
    return;
}

struct qnio_msg *
iio_message_alloc(slab_t *msg_pool)
{
    struct qnio_msg *msg;

    msg = (struct qnio_msg *) slab_get(msg_pool);
    iio_message_clear(msg);
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
