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

qnio_error_t
qnio_free_io_pool_buf(struct qnio_msg *msg)
{
    if(msg->buf_source == BUF_SRC_USER) {
        nioDbg("not freeing user io buffer");
        return QNIOERROR_SUCCESS;
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
    return QNIOERROR_SUCCESS;
}

/*
 * Called when channel gets disconnected.
 * Set error state and call notify (io_done) for each
 * message with pending response.
 */
void
flush_pending_messages(struct conn *c)
{
    struct qnio_msg *msg = NULL;
    list_t *list, *tmplist;

    nioDbg("Flush all pending messages");
    LIST_FOREACH_SAFE(&c->msgs, list, tmplist) {
        msg = LIST_ENTRY(list, struct qnio_msg, lnode);
        LIST_DEL(&msg->lnode);
        msg->hinfo.err = QNIOERROR_HUP;
        if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ) {
            ck_pr_store_int(&msg->resp_ready, 1);
        }
        else if(c->ctx->notify) {
            c->ctx->notify(msg);
        }
    }
}

/*
 * Flushes all messages from
 * the local send queue corresponding to the given connection.
 * Calls notify (io_done) for each of the messages
 * and removes the message from the map.
 */
void
flush_message_queue(struct conn *c)
{
    struct qnio_msg          *msg = NULL;

    nioDbg("Flush all pending messages from queue");
    while(safe_fifo_size(&c->fifo_q) > 0) {
        msg = (struct qnio_msg *) safe_fifo_dequeue(&c->fifo_q);
        if(msg == NULL) {
            break;
        }
        msg->hinfo.err = QNIOERROR_HUP;
        if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ) {
            ck_pr_store_int(&msg->resp_ready, 1);
        } else if(c->ctx->notify) {
            c->ctx->notify(msg);
        }
    }
}

void
mark_pending_noconn(struct conn *c)
{
    struct qnio_msg *msg = NULL;
    list_t *list, *tmplist;

    nioDbg("Mark pending messages as QNIO_FLAG_NOCONN");
    pthread_mutex_lock(&c->msg_lock);
    LIST_FOREACH_SAFE(&c->msgs, list, tmplist) {
        msg = LIST_ENTRY(list, struct qnio_msg, lnode);
        ck_pr_or_64(&msg->hinfo.flags, QNIO_FLAG_NOCONN);
    }
    pthread_mutex_unlock(&c->msg_lock);
}

void
disconnect(struct conn *c)
{
    if (c == NULL) {
        return;
    }

    nioDbg("Disconnecting network conn = [%d]", c->rem.sock);
    if (c->rem.io_class != NULL) {
        c->rem.io_class->close(&c->rem);
    }
    if (c->ev.io_class != NULL) {
        c->ev.io_class->close(&c->ev);
    }
    nioDbg("Freeing memory resources associated with connection");
    slab_free(&c->msg_pool);
    slab_free(&c->io_buf_pool);
    safe_fifo_free(&c->fifo_q);
    pthread_mutex_destroy(&c->msg_lock);
    free(c);
    return;
}

void
reset_read_state(struct NSReadInfo *rinfo)
{
    rinfo->state = NSRS_READ_START;

    rinfo->hinfo.payload_size = 0;
    rinfo->hinfo.cookie = -1;
    rinfo->hinfo.crc = 0;

    io_iov_clear(&rinfo->iovec);
    rinfo->buf = NULL;
    rinfo->buf_source = BUF_SRC_NONE;
}

void
reset_write_state(struct NSWriteInfo *winfo)
{
   winfo->state = NSWS_WRITE_START;
   io_iov_clear(&winfo->iovec); 
}

/*
 * Process message on server.
 */
static void process_server_message(struct conn *conn)
{
    struct NSReadInfo *rinfo;
    struct qnio_msg  *msg;
    struct iovec     req;

    rinfo = &conn->rinfo;
    nioDbg("process_server_message: flags = [%ld] and size = [%ld]",
           rinfo->hinfo.flags, rinfo->hinfo.payload_size);
    msg = (struct qnio_msg *)slab_get(&conn->msg_pool);
    clear_msg(msg);
    msg->io_pool = &conn->io_buf_pool;
    memcpy(&msg->hinfo, &rinfo->hinfo, sizeof(struct qnio_header));
    nioDbg("Msg is born on server side msgid=%ld %p buffer pointer %p",
           msg->hinfo.cookie, msg, buf);
    msg->ctx = conn;
    msg->send = NULL;
    msg->io_buf = rinfo->buf;
    msg->buf_source = rinfo->buf_source;
    if (msg->hinfo.payload_size > 0) {
        if(msg->hinfo.data_type == DATA_TYPE_RAW ||
           msg->hinfo.data_type == DATA_TYPE_PS) {
            msg->send = new_io_vector(1, NULL);
            req.iov_base = (void *)msg->io_buf;
            req.iov_len = msg->hinfo.payload_size;
            io_vector_pushback(msg->send, req);
        }
    } 

    if ((rinfo->hinfo.flags & QNIO_FLAG_REQ_NEED_RESP) || 
         (rinfo->hinfo.flags & QNIO_FLAG_REQ_NEED_ACK)) {
        pthread_mutex_lock(&conn->msg_lock);
        LIST_ADD(&conn->msgs, &msg->lnode);
        pthread_mutex_unlock(&conn->msg_lock);
    }
    conn->ctx->notify(msg);
    return;
}

/*
 * Process message on client.
 */
static void process_client_message(struct conn *conn)
{
    struct NSReadInfo *rinfo;
    struct qnio_msg *msg;
    struct iovec resp;

    rinfo = &conn->rinfo;
    msg = (struct qnio_msg *)rinfo->hinfo.cookie;
    nioDbg("Msg is recvd from wire on client side msgid=%ld", msg->hinfo.cookie);
    LIST_DEL(&msg->lnode);
    nioDbg("Msg removed from pending list msgid=%ld", msg->hinfo.cookie);
    msg->io_buf = rinfo->buf;
    msg->buf_source = rinfo->buf_source;
    msg->hinfo.io_nbytes = rinfo->hinfo.io_nbytes;
    msg->hinfo.io_remote_hdl = rinfo->hinfo.io_remote_hdl;
    msg->hinfo.io_remote_flags = rinfo->hinfo.io_remote_flags;
    msg->hinfo.err = rinfo->hinfo.err;
    if (msg->recv == NULL && rinfo->hinfo.payload_size > 0) {
        msg->recv = new_io_vector(1, NULL);
        resp.iov_base = (void *)msg->io_buf;
        resp.iov_len = rinfo->hinfo.payload_size;
        io_vector_pushback(msg->recv, resp);
    }

    if(rinfo->hinfo.flags & QNIO_FLAG_SYNC_RESP) {
        nioDbg("Waking up thread waiting for sync response");
        ck_pr_store_int(&msg->resp_ready, 1);
    } else {
        conn->ctx->notify(msg);
    }
    return;
}

/*
 * Parse the header and setup I/O buffers
 * to read the payload.
 */
static inline int
process_header(struct conn *conn)
{
    struct NSReadInfo *rinfo;
    struct channel *channel;
    struct qnio_header *hinfo;
    qnio_byte_t *header_buf;
    struct qnio_msg *msg = NULL;
    struct iovec iov;
    uint64_t aligned_size;
    int i;
    int err = QNIOERROR_SUCCESS;
    
    channel = conn->channel;
    rinfo = &conn->rinfo;
    hinfo = &rinfo->hinfo;
    header_buf = rinfo->headerb;

    if ((*(int *)&header_buf[0]) != REQ_MARKER) {
        nioDbg("Cant parser the header");
        return -1;
    }

    memcpy(hinfo, &header_buf[4], sizeof(struct qnio_header));
    nioDbg("payload size received is %ld", rinfo->hinfo.payload_size);
    if (hinfo->payload_size == 0) {
        rinfo->state = NSRS_PROCESS_DATA;
        return err;
    }
    if (channel->flags & CHAN_CLIENT) {
        msg = (struct qnio_msg *)hinfo->cookie;
        if (msg->recv != NULL) {
            rinfo->buf_source = BUF_SRC_USER;
        } else {
            nioDbg("Client side message, assigning default buffer");
            aligned_size = ((hinfo->payload_size / BUF_ALIGN) + 1) * BUF_ALIGN;
            posix_memalign((void **)&rinfo->buf, BUF_ALIGN, aligned_size);
            rinfo->buf_source = BUF_SRC_MALLOC;
        }
    } else if (channel->flags & CHAN_SERVER) {
        if (hinfo->payload_size <= IO_POOL_BUF_SIZE) {
            nioDbg("Server side message, assigning pool buffer");
            rinfo->buf = (qnio_byte_t *)slab_get(&conn->io_buf_pool);
            rinfo->buf_source = BUF_SRC_POOL;
        } else {
            nioDbg("Server side message, assigning default buffer");
            aligned_size = ((hinfo->payload_size / BUF_ALIGN) + 1) * BUF_ALIGN;
            posix_memalign((void **)&rinfo->buf, BUF_ALIGN, aligned_size);
            rinfo->buf_source = BUF_SRC_MALLOC;
        }
    } else {
        nioDbg("Invalid cannnel");
        return -1;
    }

    /*
     * Setup the I/O vector to read the data.
     */
    io_iov_clear(&rinfo->iovec);
    if (rinfo->buf_source == BUF_SRC_USER) {
        for (i = 0; i < msg->recv->_count; i++) {
            io_iov_add(&rinfo->iovec, &(msg->recv->_iovec[i]));
        }
    } else {
        iov.iov_base = rinfo->buf;
        iov.iov_len = hinfo->payload_size;
        io_iov_add(&rinfo->iovec, &iov);
    }
    nioDbg("remaining io = %ld\n", io_iov_remaining_payload(&rinfo->iovec));
    rinfo->state = NSRS_READ_DATA;
    return err;
}

qnio_byte_t *
generate_header(struct qnio_msg *msg)
{
    qnio_byte_t     *header;
    int            mark = REQ_MARKER;

    header = msg->header;
    memcpy(header, &mark, sizeof (int));
    memcpy(&header[4], msg, (HEADER_LEN-4));
    return (header);
}

static inline void
write_to_network(struct conn *conn)
{
    struct NSWriteInfo *winfo;
    struct qnio_msg *msg = NULL;
    io_vector *iovec;
    struct iovec header;
    size_t len, n;
    int iovcount, i;

    winfo = &conn->winfo;
    if (winfo->state == NSWS_WRITE_START) {
        msg = (struct qnio_msg *)safe_fifo_first(&(conn->fifo_q));
        if (msg == NULL) {
            return;
        }
        io_iov_clear(&winfo->iovec);
        header.iov_base = generate_header(msg);
        header.iov_len = HEADER_LEN;
        io_iov_add(&winfo->iovec, &header);
        if (conn->channel->flags & CHAN_CLIENT) {
            iovec = msg->send;
        } else {
            iovec = msg->recv;
        }
        if (iovec != NULL) {
            for (i = 0; i < iovec->_count; i++) {
                io_iov_add(&winfo->iovec, &(iovec->_iovec[i]));
            }
        }
        winfo->state = NSWS_WRITE_DATA;
    }

    assert(winfo->state == NSWS_WRITE_DATA);
    len = io_iov_remaining_payload(&winfo->iovec);
    iovcount = io_iov_count(&winfo->iovec);
    n = conn->rem.io_class->writev(&conn->rem, winfo->iovec.cur_iovec, iovcount);
    nioDbg("wrote %ld bytes to remote [%d]", n, errno);

    /* entire payload has been written over the wire */
    if (n == len) {
#ifdef QNIO_HOUSEKEEPING
        conn->ctx->out += n;
#endif
        reset_write_state(winfo);
        /* dequeue msg from queue */
        msg = (struct qnio_msg *)safe_fifo_dequeue(&conn->fifo_q);
        nioDbg("Msg is written on wire msgid=%ld", msg->hinfo.cookie);
        if(conn->ctx->gc != NULL) {
            conn->ctx->gc(msg);
        }
        if(msg->msg_io_done != NULL) {
            msg->msg_io_done(msg);
        }
        if(!is_resp_required(msg)) {
            if(msg->hinfo.flags & QNIO_FLAG_REQ) {
                 conn->ctx->notify(msg);
            } else {
                 if(msg->send) {
                     io_vector_delete(msg->send);
                 }
                 if(msg->recv && msg->hinfo.data_type == DATA_TYPE_PS) {
                     io_vector_delete(msg->recv);
                 }
                 qnio_free_io_pool_buf(msg);
                 slab_put(&conn->msg_pool, msg);
            }
        } else {
            nioDbg("Msg is pending response msgid=%ld", msg->hinfo.cookie);
            LIST_ADD(&conn->msgs, &msg->lnode);
        }
    } else if (n > 0) {
        io_iov_forword(&winfo->iovec, n);
#ifdef QNIO_HOUSEKEEPING
        conn->ctx->out += n;
#endif
    }
}

static inline void
stop_endpoint(struct endpoint *endpoint)
{
    if (endpoint->io_class != NULL && endpoint->io_class->close != NULL) {
        endpoint->io_class->close(endpoint);
    }
    endpoint->io_class = NULL;
    endpoint->flags |= FLAG_CLOSED;
    endpoint->flags &= ~(FLAG_R | FLAG_W | FLAG_ALWAYS_READY);
}

static inline void
read_from_network(struct conn *conn)
{
    struct endpoint *remote;
    struct NSReadInfo *rinfo;
    size_t len;
    int n, iovcount;

    remote = &conn->rem;
    rinfo = &conn->rinfo;
    iovcount = io_iov_count(&rinfo->iovec);
    n = remote->io_class->readv(remote, rinfo->iovec.cur_iovec, iovcount);
    nioDbg("read %d bytes from remote endpoint [%d]", n, errno);
    if (n > 0) {
        io_iov_forword(&rinfo->iovec, n);
#ifdef QNIO_HOUSEKEEPING
        conn->ctx->in += n;
#endif
    } else if (!(remote->flags & FLAG_DONT_CLOSE)&&
               !(n == -1 && (ERRNO == EINTR || ERRNO == EWOULDBLOCK))) {
        nioDbg("Stopping endpoint");
        stop_endpoint(remote);
    }

    len = io_iov_remaining_payload(&rinfo->iovec);
    nioDbg("Remaining %ld bytes from remote endpoint [%d]", len, errno);
    if (len == 0) {
        rinfo->state = NSRS_PROCESS_DATA;
    }
    return;
}

/*
 * Handle outgoing messages.
 */
void
process_local_endpoint(struct endpoint *local)
{
    struct conn *conn;

    conn = local->conn;
    /* reset the ding */
    conn->ev.io_class->read(&conn->ev, NULL, 1);
    if (safe_fifo_size(&conn->fifo_q) > 0) {
        write_to_network(conn);
        conn->ev.io_class->write(&conn->ev, NULL, 0);
    }
}

/*
 * Handle incoming messages.
 */
void
process_remote_endpoint(struct endpoint *remote)
{
    struct conn *conn;
    struct NSReadInfo *rinfo;
    struct iovec header;

    conn = remote->conn;
    rinfo = &conn->rinfo;
    if (rinfo->state == NSRS_READ_START) {
        /*
         * Prepare for header read.
         */
        io_iov_clear(&rinfo->iovec);
        header.iov_base = rinfo->headerb;
        header.iov_len = HEADER_LEN;
        io_iov_add(&rinfo->iovec, &header);
        rinfo->state = NSRS_READ_HEADER;
    }

    if (rinfo->state == NSRS_READ_HEADER) {
        /*
         * Read header
         */
        read_from_network(conn);
        if (io_iov_remaining_payload(&rinfo->iovec) != 0) {
            return;
        }
        rinfo->state = NSRS_PROCESS_HEADER;
    }

    if (rinfo->state == NSRS_PROCESS_HEADER) { 
        /*
         * Parse header and prepare for  data read
         */
        process_header(conn);
    }

    if (rinfo->state == NSRS_READ_DATA) {
        /*
         * Read data
         */
        read_from_network(conn);
        if (io_iov_remaining_payload(&rinfo->iovec) != 0) {
            return;
        }
        rinfo->state = NSRS_PROCESS_DATA;
    }

    if (rinfo->state == NSRS_PROCESS_DATA) {
        if (conn->channel->flags & CHAN_CLIENT) {
            process_client_message(conn);
        } else if (conn->channel->flags & CHAN_SERVER) {
            process_server_message(conn);
        } else {
            nioDbg("Invalid cannnel");
        }
        reset_read_state(rinfo);
    }
    return;
}
