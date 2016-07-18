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
dispatch(struct endpoint *endpoint, const void *buf, size_t len)
{
    struct qnio_msg  *msg;
    struct endpoint *rem;
    struct iovec     resp;
    struct iovec     req;

    rem = &(endpoint->conn->rem);

    nioDbg("In dispatch flags = [%ld] and size = [%ld]", rem->hinfo.flags, rem->hinfo.payload_size);
    if (rem->hinfo.flags & QNIO_FLAG_REQ
          || rem->hinfo.flags & QNIO_FLAG_SYNC_REQ)     /* server side dispatch */
    {
        msg = (struct qnio_msg *)slab_get(&endpoint->conn->msg_pool);
        clear_msg(msg);
        msg->io_pool = &endpoint->conn->io_buf_pool;
        memcpy(&msg->hinfo, &rem->hinfo, sizeof(struct qnio_header));
        nioDbg("Msg is born on server side msgid=%ld %p buffer pointer %p",msg->hinfo.cookie, msg, buf);

        msg->ctx = rem->conn;

        msg->send = NULL;
        msg->io_buf = (qnio_byte_t *) buf;
        if (msg->hinfo.payload_size <= IO_POOL_BUF_SIZE)
        {
            msg->buf_source = BUF_SRC_POOL;
        }

        if (msg->hinfo.payload_size > 0)
        {
            if(msg->hinfo.data_type == DATA_TYPE_RAW 
                || msg->hinfo.data_type == DATA_TYPE_PS)
            {
                msg->send = new_io_vector(1, NULL);
                req.iov_base = (void *)buf;
                req.iov_len = len;
                io_vector_pushback(msg->send, req);
            }
        } 

        if ((rem->hinfo.flags & QNIO_FLAG_REQ_NEED_RESP) || 
            (rem->hinfo.flags & QNIO_FLAG_REQ_NEED_ACK))
        {
            pthread_mutex_lock(&endpoint->conn->msg_lock);
            LIST_ADD(&endpoint->conn->msgs, &msg->lnode);
            pthread_mutex_unlock(&endpoint->conn->msg_lock);
        }
        endpoint->conn->ctx->notify(msg);
    }
    else if ((rem->hinfo.flags & QNIO_FLAG_RESP)
             || (rem->hinfo.flags & QNIO_FLAG_ACK)      
             || (rem->hinfo.flags & QNIO_FLAG_SYNC_RESP))      
    {
        msg = (struct qnio_msg *)rem->hinfo.cookie;
        nioDbg("Msg is recvd from wire on client side msgid=%ld",msg->hinfo.cookie);
        LIST_DEL(&msg->lnode);
        nioDbg("Msg removed from pending list msgid=%ld",msg->hinfo.cookie);
        msg->io_buf = (qnio_byte_t *)buf;
        msg->hinfo.io_nbytes = rem->hinfo.io_nbytes;
        msg->hinfo.io_remote_hdl = rem->hinfo.io_remote_hdl;
        msg->hinfo.io_remote_flags = rem->hinfo.io_remote_flags;
        msg->hinfo.err = rem->hinfo.err;
        if (msg->recv == NULL && len > 0)
        {
            msg->recv = new_io_vector(1, NULL);
            resp.iov_base = (void *)buf;
            resp.iov_len = len;
            io_vector_pushback(msg->recv, resp);
        }

        if(rem->hinfo.flags & QNIO_FLAG_SYNC_RESP)
        {
            nioDbg("Waking up thread waiting for sync response");
            ck_pr_store_int(&msg->resp_ready, 1);
        }
        else
        {
            endpoint->conn->ctx->notify(msg);
        }
    }
    return (len);
}

static int
read_qnio(struct endpoint *endpoint, void *buf, size_t len)
{
    return (0);
}

static void
close_qnio(struct endpoint *endpoint)
{
}

const struct io_class io_qnio = {
    "qnio",
    read_qnio,
    dispatch,
    close_qnio
};
