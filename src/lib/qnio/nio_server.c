/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qnio.h"
#include "defs.h"

static struct qnio_ctx *s_ctx;

static struct endpoint *
add_socket(int sock, struct qnio_epoll_unit *eu)
{
    struct conn       *c;
    struct usa         sa;
    struct epoll_event ep_event;
    int epoll_err;
    struct channel *channel = NULL;

    sa.len = sizeof (sa.u.sin);
    if (getpeername(sock, &sa.u.sa, &sa.len))
    {
        nioDbg("add_socket: %s", strerror(errno));
        return (NULL);
    }
    else
    {
        c = (struct conn *)malloc(sizeof (struct conn));
        memset(c, 0, sizeof (struct conn));

        s_ctx->nrequests++;
        c->rem.conn = c->loc.conn = c->ev.conn = c;
        c->ctx = s_ctx;
        c->sa = sa;

        (void)getsockname(sock, &sa.u.sa, &sa.len);
        c->loc_port = sa.u.sin.sin_port;

        set_close_on_exec(sock);

        c->loc.io_class = &io_qnio;
        c->loc.sock = DUMMY_FD;
        c->loc.flags |= FLAG_DONT_CLOSE;

        c->ev.io_class = &io_event;
        c->ev.sock = eventfd(0, EFD_NONBLOCK);
        c->loc.flags |= FLAG_DONT_CLOSE;

        /* Add local and remote sockets to epoll ctl */
        ep_event.events = EPOLLIN;
        ep_event.data.ptr = &c->loc;
        epoll_err = epoll_ctl(eu->send_epoll_fd, EPOLL_CTL_ADD,
                              c->ev.sock, &ep_event);
        if (epoll_err == -1)
        {
            nioDbg("epoll_ctl error %d for local eventfd",errno);
            free(c);
            return (NULL);
        }

        safe_fifo_init(&c->loc.fifo_q);

        c->rem.io_class = &io_socket;
        c->rem.sock = sock;
        c->rem.flags |= FLAG_DONT_CLOSE;

        c->rem.io.buf = NULL;
        c->rem.io.size = 0;

        c->loc.io.buf = NULL;
        c->loc.io.size = 0;

        c->ev.io.buf = NULL;
        c->ev.io.size = 0;

        c->rem.hbuf.buf = c->rem.headerb;
        c->rem.hbuf.size = HEADER_LEN;

        /* get channel */
        channel = qnio_map_find(s_ctx->channels, DUMMY_CHANNEL);
        if (!channel)
        {
            nioDbg("Default dummy channel for server not found");
            free(c);
            return (NULL);
        }
        c->channel = channel;

        slab_init(&c->msg_pool, MSG_POOL_SIZE/MAX_EPOLL_UNITS, sizeof(struct qnio_msg), 0, NULL);
        slab_init(&c->io_buf_pool, IO_POOL_SIZE/MAX_EPOLL_UNITS, IO_POOL_BUF_SIZE, BUF_ALIGN, NULL);
        LIST_INIT(&c->msgs);
        pthread_mutex_init(&c->msg_lock, NULL);
    }
    return (&c->rem);
}

qnio_error_t
qnio_set_server_gc_callback(qnio_notify callback)
{
    if(s_ctx)
        s_ctx->gc = callback;

    return QNIOERROR_SUCCESS;
}

qnio_error_t
qnio_set_server_msg_io_done_callback(qnio_notify callback)
{
    if(s_ctx)
        s_ctx->msg_io_done = callback;

    return QNIOERROR_SUCCESS;
}

qnio_error_t
qnio_server_init(qnio_notify server_notify)
{
    qnio_error_t err = QNIOERROR_SUCCESS;
    struct channel *channel = NULL;
    int i;

    nioDbg("Starting server init");

    s_ctx = (struct qnio_ctx *)malloc(sizeof (struct qnio_ctx));

    s_ctx->io_buf_size = IO_BUF_SIZE;

    s_ctx->channels = new_qnio_map(compare_key, NULL, NULL);

    /*
     * Dummy channel for server side.
     * Reason for adding a channel on server side
     * although it doesn't need one is that the msg map
     * can now be maintained per channel and can now be cleaned up
     * when a channel goes bad.
     * This helps keep the client/server code symetric.
     */
    channel = (struct channel *)malloc(sizeof (struct channel));

    channel->ctx = s_ctx;
    channel->flags = CHAN_SERVER;
    strncpy(channel->name, DUMMY_CHANNEL, strlen(DUMMY_CHANNEL) + 1);
    qnio_map_insert(s_ctx->channels, channel->name,
                  (struct channel *)channel);

    s_ctx->notify = server_notify;
    s_ctx->gc = NULL;
    s_ctx->msg_io_done = NULL;
    s_ctx->nmsgid = 1;
    s_ctx->in = s_ctx->out = 0;

    /* Buffer where events are returned */
    s_ctx->activefds = calloc(MAXFDS, sizeof (struct epoll_event));
    s_ctx->epoll_fd = epoll_create1(0);
    if (s_ctx->epoll_fd == -1)
    {
        nioDbg("epoll_create error");
        err = -1;
    }

    for(i=0;i<MAX_EPOLL_UNITS;i++)
    {
        s_ctx->eu[i].send_activefds = calloc(MAXFDS, sizeof (struct epoll_event));
        s_ctx->eu[i].recv_activefds = calloc(MAXFDS, sizeof (struct epoll_event));

        s_ctx->eu[i].send_epoll_fd = epoll_create1(0);
        if (s_ctx->eu[i].send_epoll_fd == -1)
        {
            nioDbg("epoll_create error");
            err = -1;
        }

        s_ctx->eu[i].recv_epoll_fd = epoll_create1(0);
        if (s_ctx->eu[i].recv_epoll_fd == -1)
        {
            nioDbg("epoll_create error");
            err = -1;
        }
        s_ctx->eu[i].ctx = s_ctx;
    }

    return (err);
}

void *
server_send_epoll(void *args)
{
    struct endpoint   *e;
    struct qnio_epoll_unit *eu = (struct qnio_epoll_unit *) args;
    int                n, i;
    struct epoll_event ep_event;

    nioDbg("Starting server send epoll loop");
    while (1)
    {
        n = epoll_wait(eu->send_epoll_fd, eu->send_activefds,
                       MAXFDS, EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < n; i++)
        {
            if (eu->send_activefds[i].events & EPOLLIN)
            {
                e = (struct endpoint *)eu->send_activefds[i].data.ptr;
                if ((ck_pr_load_int(&e->conn->flags) & CONN_FLAG_DISCONNECTED))
                {
                    nioDbg("Server side connection is not usable. Cleaning up conn resources.");
                    /* Remove eventfd from epoll to prevent further dings */
                    epoll_ctl(eu->send_epoll_fd, EPOLL_CTL_DEL,
                        e->conn->ev.sock, &ep_event);
                    /* Connection was marked as disconnected by recv epoll
                     * Do the cleanup associated with disconnect
                     */
                    disconnect(e->conn);
                    continue;
                }
                process_local_endpoint(e);
            }
            else if ((eu->send_activefds[i].events & EPOLLERR) ||
                (eu->send_activefds[i].events & EPOLLHUP) ||
                (!(eu->send_activefds[i].events & EPOLLIN)))
            {
                nioDbg("epoll error occured on %d\n",
                          eu->send_activefds[i].data.fd);
                close(eu->send_activefds[i].data.fd);
            }
        }
    }

    free(eu->send_activefds);
    return (NULL);
}

void *
server_recv_epoll(void *args)
{
    struct endpoint   *e;
    struct qnio_epoll_unit *eu = (struct qnio_epoll_unit *) args;
    int                n, i;
    struct epoll_event ep_event;

    nioDbg("Starting server recv epoll loop");

    while (1)
    {
        n = epoll_wait(eu->recv_epoll_fd, eu->recv_activefds,
                       MAXFDS, EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < n; i++)
        {
            if (eu->recv_activefds[i].events & EPOLLRDHUP)
            {
                nioDbg("Client socket disconnected arrived");

                /* This implies client socket disconnected */
                e = (struct endpoint *)eu->recv_activefds[i].data.ptr;
                if (e == NULL)
                {
                    nioDbg("Invalid endpoint. Skip processing");
                    continue;
                }

                epoll_ctl(eu->recv_epoll_fd, EPOLL_CTL_DEL,
                    e->conn->rem.sock, &ep_event);

                /* Mark pending messages on this connection as
                 * having no connection anymore
                 */
                nioDbg("Marking server side pending messages as having no connection anymore");
                mark_pending_noconn(e->conn);

                /* Mark the connection as disconnected */
                nioDbg("Marking server side connection as disconnected");
                ck_pr_or_int(&(e->conn->flags), CONN_FLAG_DISCONNECTED);

                /* Ding send epoll for cleanup */
                e->conn->ev.io_class->write(&e->conn->ev, NULL, 0);
            }
            else if (eu->recv_activefds[i].events & EPOLLIN)
            {
                e = (struct endpoint *)eu->recv_activefds[i].data.ptr;
                process_remote_endpoint(e);

                /* Check whether we should close this connection */
                if (e->conn->rem.flags & FLAG_CLOSED)
                {
                    disconnect(e->conn);
                }
            }
            else if ((eu->recv_activefds[i].events & EPOLLERR) ||
                (eu->recv_activefds[i].events & EPOLLHUP) ||
                (!(eu->recv_activefds[i].events & EPOLLIN)))
            {
                nioDbg("epoll error occured on %d\n",
                          eu->recv_activefds[i].data.fd);
                close(eu->recv_activefds[i].data.fd);
            }
        }
    }

    free(eu->recv_activefds);

    return (NULL);
}

int
spawn_server_epoll(struct qnio_epoll_unit *eu)
{
    int retval = 0;

    nioDbg("Spawning server epoll threads");

    retval = pthread_create(&eu->send_epoll, NULL, server_send_epoll,
                            (void *)eu);
    if (retval != 0)
    {
        nioDbg("epoll thread create failed");
    }
    retval = pthread_create(&eu->recv_epoll, NULL, server_recv_epoll,
                            (void *)eu);
    if (retval != 0)
    {
        nioDbg("epoll thread create failed");
    }
    return (retval);
}

qnio_error_t
qnio_server_start(char *node, char *port)
{
    qnio_error_t         err = QNIOERROR_SUCCESS;
    int                sfd, s, n, i;
    struct epoll_event event;
    struct qnio_epoll_unit *eu = NULL;
    int                eu_counter = 0;

    nioDbg("Entering qnio_epoll");

    s_ctx->node = node;
    if(port)
        s_ctx->port = port;
    else
        s_ctx->port = QNIO_DEFAULT_PORT;

    sfd = create_and_bind(s_ctx->node, s_ctx->port);
    if (sfd == -1)
    {
        return (-1);
    }
    s_ctx->listen_fd = sfd;

    s = make_socket_non_blocking(sfd);
    if (s == -1)
    {
        return (-1);
    }
    s = listen(sfd, SOMAXCONN);
    if (s == -1)
    {
        nioDbg("listen error");
        return (-1);
    }
    event.data.fd = sfd;
    event.events = EPOLLIN;
    s = epoll_ctl(s_ctx->epoll_fd, EPOLL_CTL_ADD, sfd, &event);
    if (s == -1)
    {
        nioDbg("epoll_ctl error");
        return (-1);
    }

    for(i=0;i<MAX_EPOLL_UNITS;i++)
    {
        nioDbg("Starting server epoll unit #%d",i);
        spawn_server_epoll(&s_ctx->eu[i]);
    }

    nioDbg("Starting listener epoll loop");
    /* The event loop */
    while (1)
    {
        n = epoll_wait(s_ctx->epoll_fd, s_ctx->activefds,
                       MAXFDS, EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < n; i++)
        {
            if ((s_ctx->activefds[i].events & EPOLLERR) ||
                (s_ctx->activefds[i].events & EPOLLHUP) ||
                (!(s_ctx->activefds[i].events & EPOLLIN)))
            {
                nioDbg("epoll error occured on %d\n",
                          s_ctx->activefds[i].data.fd);
                close(s_ctx->activefds[i].data.fd);
                continue;
            }
            else if (sfd == s_ctx->activefds[i].data.fd)
            {
                nioDbg("Got a new connection");
                /* We have a notification on the listening socket, which
                 *  means one or more incoming connections. */
                while (1)
                {
                    struct sockaddr in_addr;
                    socklen_t       in_len;
                    int             infd;
                    char            hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                    in_len = sizeof in_addr;
                    nioDbg("Accepting new connection");
                    infd = accept(sfd, &in_addr, &in_len);
                    if (infd == -1)
                    {
                        if ((errno == EAGAIN) ||
                            (errno == EWOULDBLOCK))
                        {
                            /* We have processed all incoming
                             *  connections. */
                            break;
                        }
                        else
                        {
                            nioDbg("accept error %d",errno);
                            break;
                        }
                    }
                    s = getnameinfo(&in_addr, in_len,
                                    hbuf, sizeof hbuf,
                                    sbuf, sizeof sbuf,
                                    NI_NUMERICHOST | NI_NUMERICSERV);
                    if (s == 0)
                    {
                        nioDbg("Accepted connection on descriptor %d "
                                  "(host=%s, port=%s)\n", infd, hbuf, sbuf);
                    }
                    /* Make the incoming socket non-blocking and add it to the
                     *  list of fds to monitor. */
                    s = make_socket_non_blocking(infd);
                    if (s == -1)
                    {
                        return (-1);
                    }
                    eu = &s_ctx->eu[eu_counter];
                    eu_counter++;
                    if(eu_counter == MAX_EPOLL_UNITS)
                        eu_counter = 0;
                    event.data.fd = infd;
                    nioDbg("Adding connection to epoll unit #%d",eu_counter);
                    event.events = EPOLLIN | EPOLLRDHUP;
                    event.data.ptr = add_socket(infd, eu);
                    if(event.data.ptr == NULL)
                    {
                        nioDbg("qnio_server_start: add_socket returned NULL");
                        break;
                    }

                    s = epoll_ctl(eu->recv_epoll_fd,
                                  EPOLL_CTL_ADD, infd, &event);
                    if (s == -1)
                    {
                        nioDbg("qnio_server_start: epoll_ctl error %d",errno);
                        return (-1);
                    }
                }
                continue;
            }
        }
    }

    free(s_ctx->activefds);

    close(sfd);

    return (err);
}

qnio_error_t
qnio_send_resp(struct qnio_msg *msg)
{
    struct iovec   header;
    int             i = 0;
    struct conn *c = (struct conn *) msg->ctx;

    nioDbg("Msg resp being sent for msgid=%ld",msg->hinfo.cookie);
    if (ck_pr_load_64(&msg->hinfo.flags) & QNIO_FLAG_NOCONN)
    {
        nioDbg("Server side connection is disconnected. Aborting qnio_send_resp.");
        return QNIOERROR_NOCONN;
    }
    pthread_mutex_lock(&c->msg_lock);
    LIST_DEL(&msg->lnode);
    pthread_mutex_unlock(&c->msg_lock);
    if (msg->hinfo.payload_size > IO_BUF_SIZE)
    {
        /* return payload too big */
        return (QNIOERROR_INVALIDARG);
    }
    io_iov_clear(&msg->data_iov);

    header.iov_base = generate_header(msg);
    header.iov_len = HEADER_LEN;

    io_iov_add(&msg->data_iov, &header);

    if (msg->recv != NULL)
    {
        for (i = 0; i < msg->recv->_count; i++)
        {
            io_iov_add(&msg->data_iov, &(msg->recv->_iovec[i]));
        }
    }
    if (c == NULL || (ck_pr_load_int(&c->flags) & CONN_FLAG_DISCONNECTED))
    {
        nioDbg("Server side connection is disconnected. Not enqueuing response.");
        /*
         * Possible if disconnect has been processed for this connection
         * in the epoll loop.
         */
        return QNIOERROR_NOCONN;
    }
    safe_fifo_enqueue(&(c->loc.fifo_q), msg);

    nioDbg("Msg resp is enqueued msgid=%ld",msg->hinfo.cookie);
    /* signal connection eventfd */
    c->ev.io_class->write(&c->ev, NULL, 0);

    return (QNIOERROR_SUCCESS);
}
