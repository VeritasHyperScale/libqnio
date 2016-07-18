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

static inline qnio_error_t
open_local_endpoint(struct conn *c)
{
    /* Check the opcode and setup local endpoint for appropriate driver */
    c->loc.io_class = &io_qnio;

    c->loc.flags |= FLAG_W | FLAG_ALWAYS_READY | FLAG_DONT_CLOSE;

    return (QNIOERROR_SUCCESS);
}

qnio_error_t
qnio_free_io_pool_buf(struct qnio_msg *msg)
{
    if(msg->buf_source == BUF_SRC_USER)
    {
        nioDbg("not freeing user io buffer");
        return QNIOERROR_SUCCESS;
    }
    if(msg->io_buf != NULL)
    {
        nioDbg("Msg buffer is being freed msgid=%ld %p",msg->hinfo.cookie, msg->io_buf);
        if (msg->buf_source == BUF_SRC_POOL)
        {
            slab_put(msg->io_pool, msg->io_buf);
        }
        else
        {
            free(msg->io_buf);
        }
    }

    return QNIOERROR_SUCCESS;
}

/*
 * Flushes all messages from
 * the channel corresponding to the given connection.
 * Calls notify (io_done) for each of the messages
 * and then empties pending message list.
 * Will be called only once the whole channel is marked as
 * disconnected.
 */
void
flush_pending_messages(struct conn *c)
{
    struct qnio_msg *msg = NULL;
    list_t *list, *tmplist;

    nioDbg("Flush all pending messages");
    LIST_FOREACH_SAFE(&c->msgs, list, tmplist)
    {
        msg = LIST_ENTRY(list, struct qnio_msg, lnode);
        LIST_DEL(&msg->lnode);
        msg->hinfo.err = QNIOERROR_HUP;
        if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ)
        {
            ck_pr_store_int(&msg->resp_ready, 1);
        }
        else if(c->ctx->notify)
        {
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

    while(safe_fifo_size(&c->loc.fifo_q) > 0)
    {
        msg = (struct qnio_msg *) safe_fifo_dequeue(&c->loc.fifo_q);
        if(msg == NULL)
            break;
        msg->hinfo.err = QNIOERROR_HUP;
        if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ)
        {
            ck_pr_store_int(&msg->resp_ready, 1);
        }
        else if(c->ctx->notify)
        {
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
    LIST_FOREACH_SAFE(&c->msgs, list, tmplist)
    {
        msg = LIST_ENTRY(list, struct qnio_msg, lnode);
        ck_pr_or_64(&msg->hinfo.flags, QNIO_FLAG_NOCONN);
    }
    pthread_mutex_unlock(&c->msg_lock);
}

void
disconnect(struct conn *c)
{
    if (c == NULL)
    {
        return;
    }

    nioDbg("Disconnecting loc = [%d] and rem = [%d]", c->loc.sock,
              c->rem.sock);

    if (c->loc.io_class != NULL)
    {
        c->loc.io_class->close(&c->loc);
        if (c->loc.io.buf != NULL)
        {
            free(c->loc.io.buf);
        }
    }
    if (c->rem.io_class != NULL)
    {
        c->rem.io_class->close(&c->rem);
    }
    if (c->ev.io_class != NULL)
    {
        c->ev.io_class->close(&c->ev);
    }
    nioDbg("Freeing memory resources associated with connection");
    slab_free(&c->msg_pool);
    slab_free(&c->io_buf_pool);
    safe_fifo_free(&c->loc.fifo_q);
    pthread_mutex_destroy(&c->msg_lock);
    free(c);
    c = NULL;
}

static inline int
parse_header(struct conn *c, qnio_byte_t *s, int buflen)
{
    qnio_error_t     err = QNIOERROR_SUCCESS;
    struct qnio_msg *msg = NULL;
    struct iovec    iov;
    uint64_t       aligned_size;

    if ((*(int *)&s[0]) == REQ_MARKER)
    {
        memcpy(&(c->rem.hinfo), &s[4], sizeof(struct qnio_header));

        nioDbg("payload size received is %ld", c->rem.hinfo.payload_size);

        c->rem.io_ptr = NULL;
        if ((c->channel->flags & CHAN_CLIENT) && c->rem.hinfo.payload_size > 0)
        {
            msg =
                (struct qnio_msg *)c->rem.hinfo.cookie;
            if (msg->recv != NULL)
            {
                nioDbg("Client side message, assigning user buffer");
                iov = io_vector_at(msg->recv, 0);
                io_assign(&c->rem.ubuf, &iov);
                io_clear(&c->rem.ubuf);
                c->rem.io_ptr = &c->rem.ubuf;
                msg->buf_source = BUF_SRC_USER;
            }
            else
            {
                nioDbg("Client side message, assigning default buffer");
                aligned_size = ((c->rem.hinfo.payload_size / BUF_ALIGN) + 1) * BUF_ALIGN;
                posix_memalign((void **)&c->rem.io.buf, BUF_ALIGN, aligned_size);
                c->rem.io.size = aligned_size;
                io_clear(&c->rem.io);
                c->rem.io_ptr = &c->rem.io;
            }
        }
        else if ((c->channel->flags & CHAN_SERVER) && c->rem.hinfo.payload_size > 0)
        {
            if (c->rem.hinfo.payload_size <= IO_POOL_BUF_SIZE)
            {
                nioDbg("Server side message, assigning pool buffer");
                c->rem.io.buf = (qnio_byte_t *)slab_get(&c->io_buf_pool);
                c->rem.io.size = c->rem.hinfo.payload_size;
                io_clear(&c->rem.io);
                c->rem.io_ptr = &c->rem.io;
            }
            else
            {

                nioDbg("Server side message, assigning default buffer");
                aligned_size = ((c->rem.hinfo.payload_size / BUF_ALIGN) + 1) * BUF_ALIGN;
                posix_memalign((void **)&c->rem.io.buf, BUF_ALIGN, aligned_size);
                c->rem.io.size = aligned_size;
                io_clear(&c->rem.io);
                c->rem.io_ptr = &c->rem.io;
            }
        }
        else
        {
            nioDbg("zero payload buffer not required");
            c->rem.io.buf = NULL;
            c->rem.io.size = 0;
            io_clear(&c->rem.io);
            c->rem.io_ptr = &c->rem.io;
        }
    }
    else
    {
        nioDbg("Cant parser the header");
        err = -1;
    }
    return (err);
}

static inline qnio_error_t
read_header(struct conn *c)
{
    qnio_error_t err = QNIOERROR_SUCCESS;

    if (io_data_len(&c->rem.hbuf) < HEADER_LEN)
    {
        nioDbg("not enough data in remote buffer to parse header");
        return (-1);
    }

    err = parse_header(c, c->rem.hbuf.buf, HEADER_LEN);
    if (err != QNIOERROR_SUCCESS)
    {
        nioDbg("Parsing of header failed, bail");
        return (-1);
    }
    c->rem.flags |= FLAG_HEADERS_PARSED;

    /* Remove the length of request from total, count only data */
    c->rem.hbuf.total -= HEADER_LEN;

    io_inc_tail(&c->rem.hbuf, HEADER_LEN);

    return (err);
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
write_to_remote(struct endpoint *local, struct endpoint *remote)
{
    struct qnio_msg          *msg = NULL;
    int                     len, n, iovcount=0;

    msg = (struct qnio_msg *) safe_fifo_first(&(local->fifo_q));
    len = io_iov_data_len(&msg->data_iov);
    iovcount = io_iov_count(&msg->data_iov);
    if(iovcount > 1024)
    {
        iovcount = 1024;
    }
    n = remote->io_class->writev(remote, msg->data_iov.start, iovcount);

    nioDbg("wrote %d bytes to remote [%d]",n,errno);

    if (n == len)   /* entire payload has been written over the wire */
    {
#ifdef QNIO_HOUSEKEEPING
        local->conn->ctx->out += n;
#endif
        /* dequeue msg from queue */
        safe_fifo_dequeue(&local->fifo_q);

        nioDbg("Msg is written on wire msgid=%ld",msg->hinfo.cookie);
        if(local->conn->ctx->gc != NULL)
        {
            local->conn->ctx->gc(msg);
        }
        if(msg->msg_io_done != NULL)
        {
            msg->msg_io_done(msg);
        }
        if(!is_resp_required(msg))
        {
            if(msg->hinfo.flags & QNIO_FLAG_REQ)
            {
                 local->conn->ctx->notify(msg);
            }
            else
            {
                 if(msg->send)
                 {
                     io_vector_delete(msg->send);
                 }
                 if(msg->recv && msg->hinfo.data_type == DATA_TYPE_PS)
                 {
                     io_vector_delete(msg->recv);
                 }
                 qnio_free_io_pool_buf(msg);
                 slab_put(&local->conn->msg_pool, msg);
            }
        }
        else
        {
            nioDbg("Msg is pending response msgid=%ld",msg->hinfo.cookie);
            LIST_ADD(&local->conn->msgs, &msg->lnode);
        }
    }
    else if (n > 0)
    {
        io_iov_wrote(&msg->data_iov, n);
#ifdef QNIO_HOUSEKEEPING
        local->conn->ctx->out += n;
#endif
    }
}

static inline void
read_local(struct endpoint *endpoint)
{
    /* Read from underlying endpoint i.e. reset eventfd flag */
    endpoint->io_class->read(endpoint, NULL, 1);
}

static inline void
stop_endpoint(struct endpoint *endpoint)
{
    if (endpoint->io_class != NULL && endpoint->io_class->close != NULL)
    {
        endpoint->io_class->close(endpoint);
    }
    endpoint->io_class = NULL;
    endpoint->flags |= FLAG_CLOSED;
    endpoint->flags &= ~(FLAG_R | FLAG_W | FLAG_ALWAYS_READY);
}

static inline void
send_server_error(struct conn *c, int status)
{
    stop_endpoint(&c->loc);
}

static inline void
read_from_remote(struct endpoint *endpoint, int len)
{
    int             n;

    if (len == 0)
    {
        endpoint->flags |= FLAG_DATA_READY;
        return;
    }

    len = len - io_data_len(endpoint->io_ptr);

    n = endpoint->nread_last = endpoint->io_class->read(endpoint,
                                                        io_space(
                                                            endpoint->io_ptr),
                                                        len);
    nioDbg("read %d bytes from remote endpoint [%d]",n,errno);
    if (n > 0)
    {
        io_inc_head(endpoint->io_ptr, n);
#ifdef QNIO_HOUSEKEEPING
        endpoint->conn->ctx->in += n;
#endif
    }
    else if (n == -1 && (ERRNO == EINTR || ERRNO == EWOULDBLOCK))
    {
        n = n;  /* Ignore EINTR and EAGAIN */
    }
    else if (!(endpoint->flags & FLAG_DONT_CLOSE))
    {
        stop_endpoint(endpoint);
    }

    if ((io_data_len(endpoint->io_ptr) == IO_BUF_SIZE)
        || (io_data_len(endpoint->io_ptr) == endpoint->hinfo.payload_size &&
            endpoint->hinfo.payload_size > 0))
    {
        endpoint->flags |= FLAG_DATA_READY;
    }
}

static inline void
write_to_local(struct endpoint *from, struct endpoint *to, int len)
{
    int n;

    /* TODO: should be assert on CAN_WRITE flag */
    n = to->io_class->write(to, io_data(from->io_ptr), len);
    if (n > 0)
    {
        io_inc_tail(from->io_ptr, n);
    }
    else if (n == -1 && (ERRNO == EINTR || ERRNO == EWOULDBLOCK))
    {
        n = n;  /* Ignore EINTR and EAGAIN */
    }
    else if (!(to->flags & FLAG_DONT_CLOSE))
    {
        stop_endpoint(to);
    }
}

static inline void
reset_endpoint(struct endpoint *endpoint)
{
    /* reset header parsed flag for next payload */
    endpoint->flags &= ~(FLAG_DATA_READY);
    endpoint->flags &= ~(FLAG_HEADERS_PARSED);

    endpoint->hinfo.payload_size = 0;
    endpoint->hinfo.cookie = -1;
    endpoint->hinfo.crc = 0;

    io_clear(&endpoint->hbuf);
    io_clear(endpoint->io_ptr);

    endpoint->io_ptr = NULL;
}

void
process_local_endpoint(struct endpoint *local)
{
    /* reset the ding */
    local->conn->ev.io_class->read(&local->conn->ev, NULL, 1);

    if (safe_fifo_size(&local->fifo_q) > 0)
    {
        write_to_remote(local, &local->conn->rem);
        local->conn->ev.io_class->write(&local->conn->ev, NULL, 0);
    }
}

void
process_remote_endpoint(struct endpoint *remote)
{
    /* If the request is not parsed yet, do so */
    if (!(remote->flags & FLAG_HEADERS_PARSED))
    {
        remote->io_ptr = &remote->hbuf;
        read_from_remote(remote, HEADER_LEN);
        read_header(remote->conn);
    }

    if (remote->flags & FLAG_HEADERS_PARSED)
    {
        read_from_remote(remote, remote->hinfo.payload_size);
    }

    if (remote->flags & FLAG_DATA_READY)
    {
        write_to_local(remote, &remote->conn->loc, remote->hinfo.payload_size);
        reset_endpoint(remote);
    }
}
