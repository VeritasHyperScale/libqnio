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

#include "defs.h"
#include "qnio_api.h"
#include "qnio.h"
#include "qnio_client.h"
#include "utils.h"

struct qnio_client_ctx *qnc_ctx; /* Network client context */
static struct qnio_common_ctx *cmn_ctx;

static void *client_epoll(void *);

static void
close_connection(struct conn *conn)
{
    if (conn->ns.io_class != NULL) {
        conn->ns.io_class->close(&conn->ns);
    }
    if (conn->ev.io_class != NULL) {
        conn->ev.io_class->close(&conn->ev); 
    }
    safe_fifo_free(&conn->fifo_q);
    free(conn);
}

static struct conn *
open_connection(struct network_channel *netch, int flags, int euid)
{
    int sock = -1, epoll_err;
    struct sockaddr_in my_addr;
    struct epoll_event ep_event;
    struct conn *c = NULL;
    int err;
    struct addrinfo hints, *infos = NULL;
    SSL *ssl = NULL;

    /* creating the client socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        nioDbg("open_connection: Socket creation failed [%d]", errno);
        goto out;
    }
    memset((char *)&my_addr, 0, sizeof (my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(0);
    err = QNIO_SYSCALL(bind(sock, (struct sockaddr *)&my_addr, sizeof (my_addr)));
    if(err < 0) {
        nioDbg("Bind: failed [%d]", errno);
        goto out;
    }

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(netch->name, netch->port, &hints, &infos);
    if(err) {
        if(err == EAI_SYSTEM) {
            err = errno;
        } 
        nioDbg("getaddrinfo failed [%d], %s", err, gai_strerror(err));
        goto out;
    }

    if(infos == NULL) {
        nioDbg("getaddrinfo: failed no ipv4ip for channel %s", netch->name);
        goto out;
    }

    if (connect(sock, infos->ai_addr, infos->ai_addrlen) < 0) {
        nioDbg("Connect: failed [%d]", errno);
        goto out;
    }

    /*
     * Use channel SSL context to set up individual connections
     */
    if(netch->channel.ssl_ctx)
    {
        ssl = SSL_new(netch->channel.ssl_ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) == -1) {
            nioDbg("ssl connect failed");
            SSL_free(ssl);
            return (NULL);
        }
    }

    freeaddrinfo(infos);
    infos = NULL;

    c = (struct conn *)malloc(sizeof (struct conn));
    if(c == NULL) {
        nioDbg("open_connection:malloc failed ");
        goto out;
    }
        
    memset(c, 0, sizeof (struct conn));
    c->netch = netch;
    c->ctx = cmn_ctx;
    c->ns.conn = c->ev.conn = c;
    c->euid = euid;

    set_close_on_exec(sock);
    err = make_socket_non_blocking(sock);
    if(err == -1) {
        nioDbg("open_connection: make_socket_non_blocking failed [%d]", errno);
        goto out;
    }

    c->ev.io_class = &io_event;
    c->ev.sock = eventfd(0, EFD_NONBLOCK);
    c->ev.flags = FLAG_DONT_CLOSE;

    c->ns.io_class = &io_socket;
    c->ns.sock = sock;
    c->ns.flags = FLAG_DONT_CLOSE;

    if (netch->channel.ssl_ctx)
    {
        c->ns.ssl = ssl;
        c->ns.io_class = &io_ssl;
    }

    reset_read_state(&c->rinfo);
    reset_write_state(&c->winfo);
    safe_fifo_init(&c->fifo_q);
    LIST_INIT(&c->msgs);
    c->flags |= flags;

    /* Add event and network sockets to epoll ctl */
    ep_event.events = EPOLLIN;
    ep_event.data.ptr = &c->ev;
    epoll_err = epoll_ctl(qnc_ctx->ceu[euid].epoll_fd, EPOLL_CTL_ADD,
                    c->ev.sock, &ep_event);
    if (epoll_err == -1) {
        nioDbg("open_connection: epoll_ctl error %d", errno);
        goto out;
    }
    ep_event.events = EPOLLIN | EPOLLRDHUP;
    ep_event.data.ptr = &c->ns;
    epoll_err = epoll_ctl(qnc_ctx->ceu[euid].epoll_fd, EPOLL_CTL_ADD,
                    c->ns.sock, &ep_event);
    if (epoll_err == -1) {
        nioDbg("open_connection: epoll_ctl2 error %d", errno);
        goto out;
    }
    return (c);

out:
    if(sock != -1) {
        close(sock);
    }
    if(infos) {
        freeaddrinfo(infos);
    }
    if(c) {
        free(c);
    }
    if(ssl) {
        SSL_free(ssl);
    }
    return NULL;
}

/*
 * Reopens a single connection in the given channel.
 * Part of the workflow to reopen a channel that was
 * disconnected previously.
 * Opens the network socket associated with the connection
 * it will add the socket to the epoll with EPOLLIN and EPOLLRDHUP.
 * Returns 0 on Success, non-zero on failiure.
 */
static int
reopen_connection(struct network_channel *netch, struct conn *c, int euid)
{
    int sock = -1, epoll_err;
    struct sockaddr_in my_addr;
    struct epoll_event ep_event;
    int err = 0;
    struct addrinfo hints, *infos = NULL;

    nioDbg("Reopening connection");
    /* creating the client socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        err = errno;
        nioDbg("Socket creation failed [%d]", errno);
        goto out;
    }
    memset((char *)&my_addr, 0, sizeof (my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    my_addr.sin_port = htons(0);
    err = QNIO_SYSCALL(bind(sock, (struct sockaddr *)&my_addr, sizeof (my_addr)));
    if(err < 0) {
        err = errno;
        nioDbg("Bind: failed [%d]", errno);
        goto out;
    }

    set_close_on_exec(sock);
    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(netch->name, netch->port, &hints, &infos);
    if(err) {
        if(err == EAI_SYSTEM)
            err = errno;
        nioDbg("getaddrinfo2 failed [%d], %s", err, gai_strerror(err));
        goto out;
    }

    if(infos == NULL) {
        nioDbg("getaddrinfo2: failed no ipv4ip for channel %s", netch->name);
        err = -1;
        goto out;
    }

    err = QNIO_SYSCALL(connect(sock, infos->ai_addr, infos->ai_addrlen));
    if(err < 0) {
        nioDbg("Connect: failed [%d]", errno);
        err = errno;
        goto out;
    }

    freeaddrinfo(infos);
    infos = NULL;
    c->ns.sock = sock;

    err = make_socket_non_blocking(sock);
    if(err == -1) {
        err = errno;
        nioDbg("make_socket_non_blocking2: failed [%d]", errno);
        goto out;
    }

    ep_event.events = EPOLLIN | EPOLLRDHUP;
    ep_event.data.ptr = &c->ns;
    epoll_err = epoll_ctl(qnc_ctx->ceu[euid].epoll_fd, EPOLL_CTL_ADD,
                    c->ns.sock, &ep_event);
    if (epoll_err == -1) {
        err = errno;
        nioDbg("epoll_ctl error %d", err);
        goto out;
    }
    ck_pr_and_int(&c->flags, ~CONN_FLAG_DISCONNECTED);
    return (0);

out:
    if(sock != -1) {
        close(sock);
    }
    if(infos) {
        freeaddrinfo(infos);
    }
    return err;
}

/*
 * This function will try and re-establish a channel that was previously
 * disconnected.
 * The client disconnect handling code will preserve the channel in its
 * pristine state, minus the invalid network socket and flag it as such
 * This code will go over the connections and reopen them one at a time.
 * If all connections are established channel is marked as usable again.
 * Returns 0 for sucess and -1 for failure.
 */
static int
reconnect_channel(struct network_channel *netch)
{
    int i, ret = 0;
    struct conn *c;

    nioDbg("Reconnecting channel");
    for (i = 0; i < MAX_CONN; i++) {
        c = netch->conn[i];
        if(!c) {
            continue;
        }
        if (ck_pr_load_int(&c->flags) & CONN_FLAG_DISCONNECTED) {
            nioDbg("Trying reconnect for connection #%d", i);
            ret = reopen_connection(netch, c, c->euid);
            if(ret != 0) {
                nioDbg("Connection reopen failed %d", ret);
                return ret;
            }
        }
    }
    ck_pr_and_int(&netch->flags, ~CHAN_DISCONNECTED);
    return (0);
}

static int
create_connections(struct network_channel *netch, int count)
{
    int i, got_conn = 0;
    struct conn *c;
    int euid = 0;

    nioDbg("Opening connections");
    for (i = 0; i < count; i++, euid++) {
        c = open_connection(netch, 0, euid % MAX_CLIENT_EPOLL_UNITS);
        if (c != NULL) {
            got_conn = 1;
            netch->conn[i] = c;
        } else {
            break;
        }
    }
    if (got_conn == 0) {
        return (-1); /* Not a single connection got established */
    }
    return (0);
}

/*
 * Called when channel gets disconnected.
 * Set error state and call notify (io_done) for each
 * message with pending response.
 */
static void
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
        } else if (c->ctx->notify) {
            c->ctx->notify(msg);
        }
    }
}

/*
 * Flushes all messages from
 * the send queue corresponding to the given connection.
 * Calls notify (io_done) for each of the messages
 * and removes the message from the map.
 */
static void
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
        } else if (c->ctx->notify) {
            c->ctx->notify(msg);
        }
    }
}

static void *
client_epoll(void *args)
{
    struct qnio_client_epoll_unit *eu = (struct qnio_client_epoll_unit *) args;
    struct epoll_event      ep_event;
    struct endpoint         *e;
    int                     n, i;

    nioDbg("Starting client epoll loop");
    /* The event loop */
    while (1) {
        n = epoll_wait(eu->epoll_fd, eu->activefds, MAXFDS,
                       EPOLL_WAIT_TIMEOUT);

        if (ck_pr_load_int(&eu->exit_thread)) {
            break;
        }
        for (i = 0; i < n; i++) {
            if (eu->activefds[i].events & (EPOLLRDHUP | EPOLLHUP)) {
                /* This implies client socket disconnected */
                e = (struct endpoint *)eu->activefds[i].data.ptr;
                
                nioDbg("Client socket disconnected. Channel is not usable");
                /* Mark channel as disconnected */
                ck_pr_or_int(&(e->conn->netch->flags), CHAN_DISCONNECTED);

                /* Mark the connection as disconnected */
                ck_pr_or_int(&(e->conn->flags), CONN_FLAG_DISCONNECTED);

                /* Flush messages pending a response */
                flush_pending_messages(e->conn);

                /* Remove socket from epoll */
                epoll_ctl(eu->epoll_fd, EPOLL_CTL_DEL, e->sock, &ep_event);
                /* Flush pending messages from message queue for this connection */
                flush_message_queue(e->conn);
                continue;
            } else if ((eu->activefds[i].events & EPOLLERR) ||
                (eu->activefds[i].events & EPOLLHUP) ||
                (!(eu->activefds[i].events & EPOLLIN))) {
                nioDbg("Got EPOLLERR or EPOLLHUP");
                /* An error has occured on this fd, or the socket is not
                 *  ready for reading (why were we notified then?) */
                fprintf(stderr, "epoll error\n");
                close(eu->activefds[i].data.fd);
                continue;
            } else {
                e = (struct endpoint *)eu->activefds[i].data.ptr;
                if (e->io_class == &io_event) {
                    process_outgoing_messages(e->conn);
                } else {
                    process_incoming_messages(e->conn);
                }
            }
        }
    }
    nioDbg("client epoll thread exiting, epoll unit = %p", eu);
    return (NULL);
}

static int
spawn_epoll(struct qnio_client_epoll_unit *eu)
{
    int retval = 0;

    retval = pthread_create(&eu->client_epoll, NULL, client_epoll,
                            (void *)eu);
    if (retval != 0) {
        nioDbg("epoll thread create failed");
    }
    return (retval);
}

/*
 * client_lock should be held before calling.
 */
static void
qnc_client_start(void)
{
    struct epoll_event event;
    int i;

    nioDbg("Starting Network Client.");
    qnc_ctx->channels = new_qnio_map(compare_key, NULL, NULL);

    for(i = 0; i < MAX_CLIENT_EPOLL_UNITS; i++) {
        ck_pr_store_int(&(qnc_ctx->ceu[i].exit_thread), 0);
        qnc_ctx->ceu[i].activefds = calloc(MAXFDS, sizeof event);
        qnc_ctx->ceu[i].epoll_fd = epoll_create1(0);
        if(qnc_ctx->ceu[i].epoll_fd == -1) {
            nioDbg("epoll_create error");
            goto out;
        }
        spawn_epoll(&qnc_ctx->ceu[i]);
    }

out:
    nioDbg("Client init done");
    return;
}

/*
 * client_lock should be held before calling.
 */
static void
qnc_client_stop(void)
{
    int i;
    struct epoll_event ep_event;
    int fd[MAX_CLIENT_EPOLL_UNITS];

    /*
     * Stop epoll threads
     */
    nioDbg("Stopping Network Client.");
    for(i = 0; i < MAX_CLIENT_EPOLL_UNITS; i++) {
        ck_pr_store_int(&(qnc_ctx->ceu[i].exit_thread), 1);
        fd[i] = eventfd(0, EFD_NONBLOCK);
        ep_event.events = EPOLLIN;
        ep_event.data.ptr = NULL;
        epoll_ctl(qnc_ctx->ceu[i].epoll_fd, EPOLL_CTL_ADD, fd[i], &ep_event);
        eventfd_write(fd[i], 1);
    }

    for(i = 0; i < MAX_CLIENT_EPOLL_UNITS; i++) {
        pthread_join(qnc_ctx->ceu[i].client_epoll, NULL);
    }

    for(i = 0; i<MAX_CLIENT_EPOLL_UNITS; i++) {
        if (qnc_ctx->ceu[i].epoll_fd >= 0) {
            close(qnc_ctx->ceu[i].epoll_fd);
        }
        if (fd[i] >= 0) {
            close(fd[i]);
        }
        free(qnc_ctx->ceu[i].activefds);
    }

    free(qnc_ctx->channels);
    return;
}

/*
 * This function returns one of the default connection.
 */
static inline struct conn *
get_free_connection(struct network_channel *netch)
{
    struct conn *c = NULL;
    
    if (ck_pr_load_int(&netch->flags) & CHAN_DISCONNECTED) {
        return NULL;
    }
    c = netch->conn[netch->free_conn_idx % MAX_CONN];
    ck_pr_inc_64(&(netch->free_conn_idx));
    return c;
}

static inline int
send_on_connection(struct qnio_msg *msg, struct conn *c)
{
    msg->ctx = c;
    msg->hinfo.cookie = (uint64_t) msg;
    msg->hinfo.crc = (unsigned char)((uint64_t) msg % CRC_MODULO);
    nioDbg("Msg is born on client side msgid=%ld %p",msg->hinfo.cookie, msg);
    if (ck_pr_load_int(&c->flags) & CONN_FLAG_DISCONNECTED) {
        nioDbg("Connection is not usable");
        msg->hinfo.err = QNIOERROR_HUP;
        errno = ENXIO;
        return -1;
    }

    safe_fifo_enqueue(&c->fifo_q, msg);

    /* signal connection eventfd */
    c->ev.io_class->write(&c->ev, NULL, 0);
    nioDbg("Msg is enqueued msgid=%ld", msg->hinfo.cookie);
    return (0);
}

struct channel *
qnc_channel_open(void *channel_arg, const char *cacert, const char *client_key,
                 const char *client_cert)

{
    struct network_channel_arg *nc_arg;
    struct network_channel *netch;
    struct channel *channel;
    SSL_CTX *ssl_ctx = NULL;
    int ret;

    nc_arg = (struct network_channel_arg *)channel_arg;
    if (!qnc_ctx) {
        nioDbg("Network client not initialized");
        return NULL;
    }

    pthread_mutex_lock(&qnc_ctx->chnl_lock);
    if (qnc_ctx->nchannel == 0) {
        qnc_client_start();
    }
    netch = qnio_map_find(qnc_ctx->channels, nc_arg->host);
    if (netch) {
        nioDbg("Channel already exists");

        /* Now check if the SSL creds passed for the new open match
         * the existing channel. Return error if they don't match.
         */
        channel = &netch->channel;
        if (channel->ssl_ctx && (cacert || client_key || client_cert)) {
            if (strcmp(channel->cacert, cacert) != 0 ||
                strcmp(channel->client_key, client_key) ||
                strcmp(channel->client_cert, client_cert))
            {
                nioDbg("Error - Attempt to open channel to same host with "
                       "different SSL credentials");
                pthread_mutex_unlock(&qnc_ctx->chnl_lock);
                return NULL;
            }
        }

        netch->refcount ++;
        pthread_mutex_unlock(&qnc_ctx->chnl_lock);
        if (ck_pr_load_int(&netch->flags) & CHAN_DISCONNECTED) {
            pthread_mutex_lock(&netch->conn_lock);
            ret = reconnect_channel(netch);
            pthread_mutex_unlock(&netch->conn_lock);
            if(ret != 0) {
                pthread_mutex_lock(&qnc_ctx->chnl_lock);
                netch->refcount --;
                pthread_mutex_unlock(&qnc_ctx->chnl_lock);
                return NULL;
            }
        }
        return &netch->channel;
    }

    /*
     * Secure SSL communication is enabled by passing these three values.
     * All, or none, should be passed.
     */
    if ( cacert || client_key || client_cert) {
        if ( !cacert || !client_key || !client_cert)
        {
            nioDbg("Secure mode can only be enabled when cacert, client_key,"
                   " and client_cert are all specified");
            pthread_mutex_unlock(&qnc_ctx->chnl_lock);
            return NULL;
        }
    }

    netch = (struct network_channel *)malloc(sizeof (struct network_channel));
    memset(netch, 0, sizeof (struct network_channel));
    channel = &netch->channel;

    /*
     * Initialize SSL context for the new channel based on the certs and keys
     * passed by the user.
     */
    if (cacert == NULL) {
        nioDbg("Client is running in unsecure mode");
        channel->cacert = NULL;
        channel->client_key = NULL;
        channel->client_cert = NULL;
        channel->ssl_ctx = NULL;
    } else {
        nioDbg("Client is running in secure mode");
        ssl_ctx = init_client_ssl_ctx(cacert, client_key, client_cert);
        if (!ssl_ctx) {
            nioDbg("Failed to setup SSL context for the new channel!!!");
            errno = ENXIO;
            goto err;
        }
        nioDbg("Successfully setup SSL context for the new channel");

        /*
         * Copy SSL related stuff for the new channel
         */
        channel->cacert = strdup(cacert);
        channel->client_key = strdup(client_key);
        channel->client_cert = strdup(client_cert);
        channel->ssl_ctx = ssl_ctx;
    }

    netch->channel.cd = &qnc_ctx->drv;
    netch->refcount = 1;
    safe_strncpy(netch->name, nc_arg->host, NAME_SZ64);
    safe_strncpy(netch->port, nc_arg->port, PORT_SZ);
    netch->free_conn_idx = 0;
    if (create_connections(netch, MAX_CONN) != 0) {
        nioDbg("Failed to open connection");
        goto err;
    }

    qnio_map_insert(qnc_ctx->channels, netch->name, (struct network_channel *)netch);
    qnc_ctx->nchannel++;
    pthread_mutex_unlock(&qnc_ctx->chnl_lock);
    return &netch->channel;
    
err:
    if (netch) {
        free(netch);
    }
    if (qnc_ctx->nchannel == 0) {
        qnc_client_stop();
    }
    pthread_mutex_unlock(&qnc_ctx->chnl_lock);
    return NULL;
}

void
qnc_channel_close(struct channel *channel)
{
    struct network_channel *netch = (struct network_channel *)channel;
    struct conn *conn;
    int i;

    pthread_mutex_lock(&qnc_ctx->chnl_lock);
    netch->refcount --;
    if (netch->refcount) {
        pthread_mutex_unlock(&qnc_ctx->chnl_lock);
        return;
    }
   
    for (i = 0; i < MAX_CONN; i++) {
        conn = netch->conn[i];
        if (conn) {
            close_connection(conn);
            netch->conn[i] = NULL;
        }
    }

    /*
     * Free the SSL related network_channel members
     */
    free(channel->cacert);
    free(channel->client_key);
    free(channel->client_cert);
    free(channel->ssl_ctx);

    qnio_map_delete(qnc_ctx->channels, netch->name);
    free(netch);
    qnc_ctx->nchannel --;
    if (qnc_ctx->nchannel == 0) {
        qnc_client_stop();
    }
    pthread_mutex_unlock(&qnc_ctx->chnl_lock);
}

static void
qnc_message_resend_cleanup(struct qnio_msg *msg)
{
    ck_pr_store_int(&msg->resp_ready, 0);
    msg->hinfo.err = 0;
    if (msg->io_buf != NULL) {
        switch (msg->buf_source) {
        case BUF_SRC_USER:
            break;

        case BUF_SRC_MALLOC:
            free(msg->io_buf);
            if (msg->recv) {
                io_vector_delete(msg->recv);
                msg->recv = NULL;
            }
            break;

        case BUF_SRC_POOL:
            slab_put(msg->io_pool, msg->io_buf);
            msg->io_buf = NULL;
            if (msg->recv) {
                io_vector_delete(msg->recv);
                msg->recv = NULL;
            }
            break;

        default:
            nioDbg("Unknown buffer source");
            break;
        }
    }
    return;
}
    
static qnio_error_t
qnc_message_send(struct channel *channel, struct qnio_msg *msg)
{
    struct conn *c = NULL;
    struct network_channel *netch;

    /* find appropriate connection in channel */
    netch = (struct network_channel *)channel;
    c = get_free_connection(netch);
    if (!c) {
        msg->hinfo.err = QNIOERROR_HUP;
        return -1;
    }

    return (send_on_connection(msg, c));
}

struct channel_driver *
qnc_driver_init(qnio_notify client_notify)
{
    if (qnc_ctx) {
        nioDbg("Driver already initialized");
        return NULL;
    }

    qnc_ctx = (struct qnio_client_ctx *)malloc(sizeof (struct qnio_client_ctx));
    cmn_ctx = (struct qnio_common_ctx *)malloc(sizeof (struct qnio_common_ctx));
    qnc_ctx->drv.chdrv_type = IIO_NETWORK_CHANNEL;
    qnc_ctx->channels = NULL;
    qnc_ctx->nchannel = 0;
    pthread_mutex_init(&qnc_ctx->chnl_lock, NULL);
    qnc_ctx->drv.chdrv_open = qnc_channel_open;
    qnc_ctx->drv.chdrv_close = qnc_channel_close;
    qnc_ctx->drv.chdrv_msg_resend_cleanup = qnc_message_resend_cleanup;
    qnc_ctx->drv.chdrv_msg_send = qnc_message_send;

    cmn_ctx->mode = QNIO_CLIENT_MODE;
    cmn_ctx->in = cmn_ctx->out = 0;
    cmn_ctx->notify = client_notify;
    return &qnc_ctx->drv;
}

struct channel_driver *
qnc_secure_driver_init(qnio_notify client_notify, const char *instance)
{
    struct channel_driver *drv = NULL;

    drv = qnc_driver_init(client_notify);
    qnc_ctx->instance = (const char *) instance;

    return drv;
}
