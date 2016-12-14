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
#include "qnio.h"
#include "qnio_server.h"
#include "utils.h"

static struct qnio_server_ctx *s_ctx;
static struct qnio_common_ctx *cmn_ctx;

static void
disconnect(struct conn *c)
{
    if (c == NULL) {
        return;
    }

    nioDbg("Disconnecting network conn = [%d]", c->ns.sock);
    if (c->ns.io_class != NULL) {
        c->ns.io_class->close(&c->ns);
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

static void
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
int
create_and_bind(char *node, char *port)
{
    struct addrinfo  hints;
    struct addrinfo *result, *rp;
    int s, sfd;
    int soreuse=1;

    memset(&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo(node, port, &hints, &result);
    if (s != 0)
    {
        nioDbg("getaddrinfo: %s", gai_strerror(s));
        return (-1);
    }
    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
        {
            continue;
        }
        setsockopt(sfd,SOL_SOCKET,SO_REUSEADDR, &soreuse, sizeof(soreuse));
        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
        {
            /* We managed to bind successfully! */
            break;
        }
        close(sfd);
    }
    if (rp == NULL)
    {
        nioDbg("Could not bind %d", errno);
        return (-1);
    }
    freeaddrinfo(result);

    return (sfd);
}

static struct endpoint *
add_socket(int sock, struct qnio_epoll_unit *eu)
{
    struct conn *c;
    struct usa sa;
    struct epoll_event ep_event;
    int epoll_err;

    sa.len = sizeof (sa.u.sin);
    if (getpeername(sock, &sa.u.sa, &sa.len)) {
        nioDbg("add_socket: %s", strerror(errno));
        return (NULL);
    } else {
        c = (struct conn *)malloc(sizeof (struct conn));
        memset(c, 0, sizeof (struct conn));

        s_ctx->nrequests++;
        c->ns.conn = c->ev.conn = c;
        c->ctx = cmn_ctx;
        c->sa = sa;

        (void)getsockname(sock, &sa.u.sa, &sa.len);
        c->loc_port = sa.u.sin.sin_port;

        set_close_on_exec(sock);

        c->ev.io_class = &io_event;
        c->ev.sock = eventfd(0, EFD_NONBLOCK);
        c->ev.flags |= FLAG_DONT_CLOSE;

        /* Add event and network sockets to epoll ctl */
        ep_event.events = EPOLLIN;
        ep_event.data.ptr = &c->ev;
        epoll_err = epoll_ctl(eu->send_epoll_fd, EPOLL_CTL_ADD,
                              c->ev.sock, &ep_event);
        if (epoll_err == -1) {
            nioDbg("epoll_ctl error %d for local eventfd",errno);
            free(c);
            return (NULL);
        }

        safe_fifo_init(&c->fifo_q);
        c->ns.io_class = &io_socket;
        c->ns.sock = sock;
        c->ns.flags |= FLAG_DONT_CLOSE;

        reset_read_state(&c->rinfo);
        reset_write_state(&c->winfo);

        slab_init(&c->msg_pool, MSG_POOL_SIZE/MAX_EPOLL_UNITS,
                  sizeof(struct qnio_msg), 0, NULL);
        slab_init(&c->io_buf_pool, IO_POOL_SIZE/MAX_EPOLL_UNITS,
                  IO_POOL_BUF_SIZE, BUF_ALIGN, NULL);
        LIST_INIT(&c->msgs);
        pthread_mutex_init(&c->msg_lock, NULL);
    }
    return (&c->ns);
}

qnio_error_t
qnio_server_init(qnio_notify server_notify)
{
    qnio_error_t err = QNIOERROR_SUCCESS;
    int i;

    nioDbg("Starting server init");
    cmn_ctx = (struct qnio_common_ctx *)malloc(sizeof (struct qnio_common_ctx));
    cmn_ctx->mode = QNIO_SERVER_MODE;
    cmn_ctx->notify = server_notify;
    cmn_ctx->in = cmn_ctx->out = 0;

    s_ctx = (struct qnio_server_ctx *)malloc(sizeof (struct qnio_server_ctx));
    /* Buffer where events are returned */
    s_ctx->activefds = calloc(MAXFDS, sizeof (struct epoll_event));
    s_ctx->epoll_fd = epoll_create1(0);
    if (s_ctx->epoll_fd == -1) {
        nioDbg("epoll_create error");
        err = -1;
    }

    for(i=0;i<MAX_EPOLL_UNITS;i++) {
        s_ctx->eu[i].send_activefds = calloc(MAXFDS, sizeof (struct epoll_event));
        s_ctx->eu[i].recv_activefds = calloc(MAXFDS, sizeof (struct epoll_event));

        s_ctx->eu[i].send_epoll_fd = epoll_create1(0);
        if (s_ctx->eu[i].send_epoll_fd == -1) {
            nioDbg("epoll_create error");
            err = -1;
        }

        s_ctx->eu[i].recv_epoll_fd = epoll_create1(0);
        if (s_ctx->eu[i].recv_epoll_fd == -1) {
            nioDbg("epoll_create error");
            err = -1;
        }
    }
    return (err);
}

void *
server_send_epoll(void *args)
{
    struct endpoint *e;
    struct qnio_epoll_unit *eu = (struct qnio_epoll_unit *) args;
    int n, i;
    struct epoll_event ep_event;

    nioDbg("Starting server send epoll loop");
    while (1) {
        n = epoll_wait(eu->send_epoll_fd, eu->send_activefds,
                       MAXFDS, EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < n; i++) {
            if (eu->send_activefds[i].events & EPOLLIN) {
                e = (struct endpoint *)eu->send_activefds[i].data.ptr;
                if ((ck_pr_load_int(&e->conn->flags) & CONN_FLAG_DISCONNECTED)) {
                    nioDbg("Server side connection is not usable."
                           " Cleaning up conn resources.");
                    /* Remove eventfd from epoll to prevent further dings */
                    epoll_ctl(eu->send_epoll_fd, EPOLL_CTL_DEL,
                              e->conn->ev.sock, &ep_event);
                    /* Connection was marked as disconnected by recv epoll
                     * Do the cleanup associated with disconnect
                     */
                    disconnect(e->conn);
                    continue;
                }
                process_outgoing_messages(e->conn);
            } else if ((eu->send_activefds[i].events & EPOLLERR) ||
                (eu->send_activefds[i].events & EPOLLHUP) ||
                (!(eu->send_activefds[i].events & EPOLLIN))) {
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
    struct endpoint *e;
    struct qnio_epoll_unit *eu = (struct qnio_epoll_unit *) args;
    struct epoll_event ep_event;
    int n, i;

    nioDbg("Starting server recv epoll loop");
    while (1) {
        n = epoll_wait(eu->recv_epoll_fd, eu->recv_activefds,
                       MAXFDS, EPOLL_WAIT_TIMEOUT);
        for (i = 0; i < n; i++) {
            if (eu->recv_activefds[i].events & EPOLLRDHUP) {
                nioDbg("Client socket disconnected arrived");

                /* This implies client socket disconnected */
                e = (struct endpoint *)eu->recv_activefds[i].data.ptr;
                if (e == NULL) {
                    nioDbg("Invalid endpoint. Skip processing");
                    continue;
                }

                epoll_ctl(eu->recv_epoll_fd, EPOLL_CTL_DEL,
                    e->conn->ns.sock, &ep_event);

                /* Mark pending messages on this connection as
                 * having no connection anymore
                 */
                nioDbg("Marking server side pending messages as having"
                       " no connection anymore");
                mark_pending_noconn(e->conn);

                /* Mark the connection as disconnected */
                nioDbg("Marking server side connection as disconnected");
                ck_pr_or_int(&(e->conn->flags), CONN_FLAG_DISCONNECTED);

                /* Ding send epoll for cleanup */
                e->conn->ev.io_class->write(&e->conn->ev, NULL, 0);
            } else if (eu->recv_activefds[i].events & EPOLLIN) {
                e = (struct endpoint *)eu->recv_activefds[i].data.ptr;
                process_incoming_messages(e->conn);

                /* Check whether we should close this connection */
                if (e->conn->ns.flags & FLAG_CLOSED) {
                    disconnect(e->conn);
                }
            } else if ((eu->recv_activefds[i].events & EPOLLERR) ||
                (eu->recv_activefds[i].events & EPOLLHUP) ||
                (!(eu->recv_activefds[i].events & EPOLLIN))) {
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
    if (retval != 0) {
        nioDbg("epoll thread create failed");
    }
    retval = pthread_create(&eu->recv_epoll, NULL, server_recv_epoll,
                            (void *)eu);
    if (retval != 0) {
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
    if(port) {
        s_ctx->port = port;
    } else {
        s_ctx->port = QNIO_DEFAULT_PORT;
    }

    sfd = create_and_bind(s_ctx->node, s_ctx->port);
    if (sfd == -1) {
        return (-1);
    }
    s_ctx->listen_fd = sfd;

    s = make_socket_non_blocking(sfd);
    if (s == -1) {
        return (-1);
    }
    s = listen(sfd, SOMAXCONN);
    if (s == -1) {
        nioDbg("listen error");
        return (-1);
    }
    event.data.fd = sfd;
    event.events = EPOLLIN;
    s = epoll_ctl(s_ctx->epoll_fd, EPOLL_CTL_ADD, sfd, &event);
    if (s == -1) {
        nioDbg("epoll_ctl error");
        return (-1);
    }

    for(i=0;i<MAX_EPOLL_UNITS;i++) {
        nioDbg("Starting server epoll unit #%d",i);
        spawn_server_epoll(&s_ctx->eu[i]);
    }

    nioDbg("Starting listener epoll loop");
    /* The event loop */
    while (1)
    {
        n = epoll_wait(s_ctx->epoll_fd, s_ctx->activefds,
                       MAXFDS, EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < n; i++) {
            if ((s_ctx->activefds[i].events & EPOLLERR) ||
                (s_ctx->activefds[i].events & EPOLLHUP) ||
                (!(s_ctx->activefds[i].events & EPOLLIN))) {
                nioDbg("epoll error occured on %d\n",
                          s_ctx->activefds[i].data.fd);
                close(s_ctx->activefds[i].data.fd);
                continue;
            } else if (sfd == s_ctx->activefds[i].data.fd) {
                nioDbg("Got a new connection");
                /* We have a notification on the listening socket, which
                 *  means one or more incoming connections. */
                while (1) {
                    struct sockaddr in_addr;
                    socklen_t       in_len;
                    int             infd;
                    char            hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

                    in_len = sizeof in_addr;
                    nioDbg("Accepting new connection");
                    infd = accept(sfd, &in_addr, &in_len);
                    if (infd == -1) {
                        if ((errno == EAGAIN) ||
                            (errno == EWOULDBLOCK)) {
                            /* We have processed all incoming
                             *  connections. */
                            break;
                        } else {
                            nioDbg("accept error %d",errno);
                            break;
                        }
                    }
                    s = getnameinfo(&in_addr, in_len,
                                    hbuf, sizeof hbuf,
                                    sbuf, sizeof sbuf,
                                    NI_NUMERICHOST | NI_NUMERICSERV);
                    if (s == 0) {
                        nioDbg("Accepted connection on descriptor %d "
                                  "(host=%s, port=%s)\n", infd, hbuf, sbuf);
                    }
                    /* Make the incoming socket non-blocking and add it to the
                     *  list of fds to monitor. */
                    s = make_socket_non_blocking(infd);
                    if (s == -1) {
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
                    if(event.data.ptr == NULL) {
                        nioDbg("qnio_server_start: add_socket returned NULL");
                        break;
                    }

                    s = epoll_ctl(eu->recv_epoll_fd,
                                  EPOLL_CTL_ADD, infd, &event);
                    if (s == -1) {
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
    struct conn *c = (struct conn *) msg->ctx;

    nioDbg("Msg resp being sent for msgid=%ld", msg->hinfo.cookie);
    if (ck_pr_load_64(&msg->hinfo.flags) & QNIO_FLAG_NOCONN) {
        nioDbg("Server side connection is disconnected. Aborting qnio_send_resp.");
        return QNIOERROR_NOCONN;
    }
    pthread_mutex_lock(&c->msg_lock);
    LIST_DEL(&msg->lnode);
    pthread_mutex_unlock(&c->msg_lock);
    if (c == NULL || (ck_pr_load_int(&c->flags) & CONN_FLAG_DISCONNECTED)) {
        nioDbg("Server side connection is disconnected. Not enqueuing response.");
        /*
         * Possible if disconnect has been processed for this connection
         * in the epoll loop.
         */
        return QNIOERROR_NOCONN;
    }
    safe_fifo_enqueue(&c->fifo_q, msg);

    nioDbg("Msg resp is enqueued msgid=%ld", msg->hinfo.cookie);
    /* signal connection eventfd */
    c->ev.io_class->write(&c->ev, NULL, 0);
    return (QNIOERROR_SUCCESS);
}
