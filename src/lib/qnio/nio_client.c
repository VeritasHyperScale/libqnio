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

pthread_mutex_t        conn_lock;
pthread_mutex_t        chnl_lock;

static void *client_epoll(void *);

/*
 * Function to determine if a channel is usable or not
 * Iterates over the channel to find if there is a single
 * connection which is not disconnected. Returns true if
 * it finds one. Otherwise returns false.
 */
bool
is_channel_usable(struct channel *chan)
{
    struct conn *tmp_c = NULL;
    bool retval = false;
    int i = 0;

    pthread_mutex_lock(&conn_lock);
    for (i = 0; i < MAX_CONN; i++) {
        tmp_c = chan->conn[i];
        if (tmp_c && !(ck_pr_load_int(&tmp_c->flags) & CONN_FLAG_DISCONNECTED)) {
            retval = true;
            break;
        }
    }
    pthread_mutex_unlock(&conn_lock);
    return retval;
}

inline int
close_connection(struct conn *c)
{
    int          i = 0;

    if (c->rem.io_class != NULL) {
        c->rem.io_class->close(&c->rem);
    }

    if (c->ev.io_class != NULL) {
        c->ev.io_class->close(&c->ev);
    }
    /* reset the streaming and in-use flags */
    pthread_mutex_lock(&conn_lock);
    for (i = 0; i < MAX_CONN; i++) {
        if (c == c->channel->conn[i]) {
            c->channel->conn[i] = NULL;
            break;
        }
    }
    free(c);
    pthread_mutex_unlock(&conn_lock);
    return (0);
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

static struct conn *
open_connection(struct channel *channel, int flags, int euid)
{
    int sock = -1, epoll_err;
    struct sockaddr_in my_addr;
    struct epoll_event ep_event;
    struct conn *c = NULL;
    int err;
    struct addrinfo hints, *infos = NULL;

    /* creating the client socket */
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        nioDbg("open_connection: Socket creation failed [%d]",errno);
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

    err = getaddrinfo(channel->name,channel->port,&hints,&infos);
    if(err) {
        if(err == EAI_SYSTEM) {
            err = errno;
        } 
        nioDbg("getaddrinfo failed [%d], %s",err,gai_strerror(err));
        goto out;
    }

    if(infos == NULL) {
        nioDbg("getaddrinfo: failed no ipv4ip for channel %s",channel->name);
        goto out;
    }

    if (connect(sock, infos->ai_addr, infos->ai_addrlen) < 0) {
        nioDbg("Connect: failed [%d]", errno);
        goto out;
    }

    freeaddrinfo(infos);
    infos = NULL;

    c = (struct conn *)malloc(sizeof (struct conn));
    if(c == NULL) {
        nioDbg("open_connection:malloc failed ");
        goto out;
    }
        
    memset(c, 0, sizeof (struct conn));
    c->channel = channel;
    c->ctx = channel->ctx;
    c->rem.conn = c->loc.conn = c->ev.conn = c;
    c->euid = euid;

    set_close_on_exec(sock);

    err = make_socket_non_blocking(sock);
    if(err == -1) {
        nioDbg("open_connection: make_socket_non_blocking failed [%d]",errno);
        goto out;
    }

    c->loc.io_class = &io_qnio;
    c->loc.sock = DUMMY_FD; /* There is no sock/fd associated with io qnio*/
    c->loc.flags = FLAG_DONT_CLOSE;

    c->ev.io_class = &io_event;
    c->ev.sock = eventfd(0, EFD_NONBLOCK);
    c->ev.flags = FLAG_DONT_CLOSE;

    c->rem.io_class = &io_socket;
    c->rem.sock = sock;
    c->rem.flags = FLAG_DONT_CLOSE;

    reset_read_state(&c->rinfo);
    reset_write_state(&c->winfo);
    safe_fifo_init(&c->fifo_q);
    LIST_INIT(&c->msgs);
    c->flags |= flags;

    /* Add local and remote sockets to epoll ctl */
    ep_event.events = EPOLLIN;
    ep_event.data.ptr = &c->loc;
    epoll_err = epoll_ctl(channel->ctx->ceu[euid].epoll_fd, EPOLL_CTL_ADD,
                    c->ev.sock, &ep_event);
    if (epoll_err == -1) {
        nioDbg("open_connection: epoll_ctl error %d",errno);
        goto out;
    }
    ep_event.events = EPOLLIN | EPOLLRDHUP;
    ep_event.data.ptr = &c->rem;
    epoll_err = epoll_ctl(channel->ctx->ceu[euid].epoll_fd, EPOLL_CTL_ADD,
                    c->rem.sock, &ep_event);
    if (epoll_err == -1) {
        nioDbg("open_connection: epoll_ctl2 error %d",errno);
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
    return NULL;
}

/*
 * Reopens a single connection asynchronously in a channel.
 * Part of the workflow to reopen a channel that was
 * disconnected previously.
 * Opens the remote socket associated with the connection
 * in non-blocking mode (if specified as such).
 * If flag says async, connection is made blocking and added to epoll
 * list upon success.
 * If connect returns EINPROGRESS
 * it will add the socket to the epoll loop and wait
 * till the connetion is complete by checking for EPOLLOUT
 * Once connection is complete socket will be added to epoll
 * with EPOLLIN and EPOLLRDHUP.
 * Returns 0 only if all connections succeed in the first attempt
 * which is unlikely given that the sockets are non-blocking.
 * Otherwise returns -1
 */
static int
reopen_connection(struct channel *channel, struct conn *c, int async, int euid)
{
    int sock = -1, epoll_err;
    struct sockaddr_in my_addr;
    struct epoll_event ep_event;
    int err = 0;
    struct addrinfo hints,*infos = NULL;

    assert(async == CONN_TRY_SYNC);
    /*
     * Currently CONN_TRY_ASYNC implementation should not work as we're closing
     * socket after associating it with epoll_fd. As there are no callers
     * of reopen_connection with async flag I'm asserting this until the 
     * implementation is corrected.
     */

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

    set_close_on_exec(sock);//todo handle failure

    if (async) { 
	    err = make_socket_non_blocking(sock);
	    if(err == -1) {
	        err = errno;
	        nioDbg("make_socket_non_blocking: failed [%d]",errno);
	        goto out;
	    } 
    }

    memset(&hints,0,sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    err = getaddrinfo(channel->name,channel->port,&hints,&infos);
    if(err) {
        if(err == EAI_SYSTEM)
            err = errno;
        nioDbg("getaddrinfo2 failed [%d], %s",err,gai_strerror(err));
        goto out;
    }

    if(infos == NULL) {
        nioDbg("getaddrinfo2: failed no ipv4ip for channel %s",channel->name);
        err = -1;
        goto out;
    }

    err = QNIO_SYSCALL(connect(sock, infos->ai_addr,infos->ai_addrlen));
    if(err < 0) {
        err = errno;
        nioDbg("Connect: failed [%d]", errno);

        if(async && errno == EINPROGRESS) {
            nioDbg("Connect in progress");
            ck_pr_or_int(&c->flags, CONN_FLAG_INPROGRESS);
            c->rem.sock = sock;
            ep_event.events = EPOLLOUT | EPOLLERR;
            ep_event.data.ptr = &c->rem;
            epoll_err = epoll_ctl(channel->ctx->ceu[euid].epoll_fd,
                                  EPOLL_CTL_ADD, c->rem.sock, &ep_event);
            if (epoll_err == -1) {
                err = errno;
                nioDbg("epoll_ctl error %d",err);
            }
        }
        goto out;
    }

    freeaddrinfo(infos);
    infos = NULL;
    c->rem.sock = sock;

    if(!async) {
        err = make_socket_non_blocking(sock);
        if(err == -1) {
            err = errno;
            nioDbg("make_socket_non_blocking2: failed [%d]",errno);
            goto out;
        }
    }

    ep_event.events = EPOLLIN | EPOLLRDHUP;
    ep_event.data.ptr = &c->rem;
    epoll_err = epoll_ctl(channel->ctx->ceu[euid].epoll_fd, EPOLL_CTL_ADD,
                    c->rem.sock, &ep_event);
    if (epoll_err == -1) {
        err = errno;
        nioDbg("epoll_ctl error %d",err);
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
 * pristine state, minus the invalid remote socket and flag it as such
 * This code will go over the connections and reopen them one at a time.
 * If all connections are established channel is marked as usable again.
 * Returns 0 for sucess and -1 for failure.
 */
static int
reconnect_channel(struct channel *channel)
{
    int i, ret = 0;
    struct conn *c;

    nioDbg("Reconnecting channel");
    for (i = 0; i < CHNL_DEFAULT_CONNECTIONS; i++) {
        c = channel->conn[i];
        if(!c) {
            continue;
        }
        if (ck_pr_load_int(&c->flags) & CONN_FLAG_INPROGRESS) {
            nioDbg("Connection in progress #%d",i);
            return -1;
        }
        if (ck_pr_load_int(&c->flags) & CONN_FLAG_DISCONNECTED) {
            nioDbg("Trying reconnect for connection #%d",i);
            ret = reopen_connection(channel, c, CONN_TRY_SYNC, c->euid);
            if(ret != 0) {
                nioDbg("Connection reopen failed %d", ret);
                return ret;
            }
        }
    }
    ck_pr_and_int(&channel->flags, ~CHAN_DISCONNECTED);
    return (0);
}

static int
create_connections(struct channel *channel, int count)
{
    int          i, got_conn = 0;
    struct conn *c;
    int euid = 0;

    nioDbg("Opening connections");
    for (i = 0; i < count; i++,euid++) {
        c = open_connection(channel, CONN_FLAG_REGULAR, euid % MAX_CLIENT_EPOLL_UNITS);
        if (c != NULL) {
            got_conn = 1;
            channel->conn[i] = c;
        } else {
            /*TODO: Need to see if this condition needs handling */
        }
    }
    if (got_conn == 0) {
        return (-1); /* Not a single connection got established */
    }
    return (0);
}

qnio_error_t
qnio_set_client_gc_callback(struct qnio_ctx *ctx, qnio_notify callback)
{
    if(ctx) {
        ctx->gc = callback;
    }
    return QNIOERROR_SUCCESS;
}

qnio_error_t
qnio_set_client_msg_io_done_callback(struct qnio_ctx *ctx, qnio_notify callback)
{
    if(ctx) {
        ctx->msg_io_done = callback;
    }

    return QNIOERROR_SUCCESS;
}

struct qnio_ctx *
qnio_client_init(qnio_notify client_notify)
{
    struct epoll_event event;
    struct qnio_ctx *ctx = NULL;
    int i;

    nioDbg("Starting client init");

    pthread_mutex_lock(&chnl_lock);
    ctx = (struct qnio_ctx *)malloc(sizeof (struct qnio_ctx));
    ctx->channels = new_qnio_map(compare_key, NULL, NULL);
    ctx->notify = client_notify;
    ctx->gc = NULL;
    ctx->msg_io_done = NULL;
    ctx->nmsgid = 1;
    ctx->in = ctx->out = 0;


    /* Initialize slab pools */
    slab_init(&ctx->msg_pool, MSG_POOL_SIZE, sizeof(struct qnio_msg), 0, NULL);
    for(i=0;i<MAX_CLIENT_EPOLL_UNITS+1;i++) {
        ctx->ceu[i].activefds = calloc(MAXFDS, sizeof event);
        ctx->ceu[i].epoll_fd = epoll_create1(0);
        if(ctx->ceu[i].epoll_fd == -1) {
            nioDbg("epoll_create error");
            goto out;
        }
        ctx->ceu[i].ctx = ctx;
        spawn_epoll(&ctx->ceu[i]);
    }

out:
    pthread_mutex_unlock(&chnl_lock);
    nioDbg("Client init done");
    return (ctx);
}

qnio_error_t
qnio_create_channel(struct qnio_ctx *ctx, char *hostname, char *port)
{
    qnio_error_t      err = QNIO_ERR_SUCCESS;
    struct channel *channel = NULL;

    if (hostname == NULL) {
        nioDbg("Channel name is null");
        return (-1);
    }

    if(port == NULL) {
        port = QNIO_DEFAULT_PORT;
    }

    pthread_mutex_lock(&chnl_lock);
    /* If channel already defined, perform no-op */
    if (qnio_map_find(ctx->channels, hostname) != NULL) {
        nioDbg("Channel already exists");
        pthread_mutex_unlock(&chnl_lock);
        return (QNIO_ERR_CHAN_EXISTS);
    }

    channel = (struct channel *)malloc(sizeof (struct channel));
    memset(channel, 0, sizeof(struct channel));

    channel->ctx = ctx;
    channel->flags = CHAN_CLIENT;
    strncpy(channel->name, hostname, strlen(hostname) + 1);
    strncpy(channel->port, port, strlen(port) + 1);

    channel->free_conn_idx = 0;
    channel->next_stream_idx = CHNL_DEFAULT_CONNECTIONS;
    if (create_connections(channel, CHNL_DEFAULT_CONNECTIONS) != 0) {
        nioDbg("Failed to open single connection");
        nioDbg("hostname=%s, port=%s", channel->name, channel->port);
        err = QNIO_ERR_CHAN_CREATE_FAILED;
        goto err;
    }
    qnio_map_insert(ctx->channels, channel->name,
                  (struct channel *)channel);
err:
    pthread_mutex_unlock(&chnl_lock);
    return (err);
}

qnio_error_t
qnio_destroy_channel(struct qnio_ctx *ctx, char *chnl_name)
{
    qnio_error_t err = QNIOERROR_SUCCESS;
    return (err);
}

static void *
client_epoll(void *args)
{
    struct endpoint   *e;
    struct qnio_client_epoll_unit *eu = (struct qnio_client_epoll_unit *) args;
    int                n, i;
    struct epoll_event ep_event;
    struct qnio_msg *msg;

    nioDbg("Starting client epoll loop");
    /* The event loop */
    while (1) {
        n = epoll_wait(eu->epoll_fd, eu->activefds, MAXFDS,
                       EPOLL_WAIT_TIMEOUT);

        for (i = 0; i < n; i++) {
            if (eu->activefds[i].events & EPOLLRDHUP) {
                /* This implies client socket disconnected */
                e = (struct endpoint *)eu->activefds[i].data.ptr;
                
                if (!(ck_pr_load_int(&(e->conn->channel->flags)) &
                    CHAN_DISCONNECTED) && e->conn->euid == 0) {
                    nioDbg("Notifying for channel hangup");
                    msg = (struct qnio_msg *) malloc(sizeof(struct qnio_msg));
                    memset(msg, 0, sizeof(struct qnio_msg));
                    msg->hinfo.err = QNIOERROR_CHANNEL_HUP;
                    msg->reserved = e->conn->ctx->apictx;
                    e->conn->ctx->notify(msg);
                }

                nioDbg("Client socket disconnected. Channel is not usable");
                /* Mark channel as disconnected */
                ck_pr_or_int(&(e->conn->channel->flags), CHAN_DISCONNECTED);

                /* Mark the connection as disconnected */
                ck_pr_or_int(&(e->conn->flags), CONN_FLAG_DISCONNECTED);

                /* Flush messages pending a response */
                flush_pending_messages(e->conn);

                /* Remove socket from epoll */
                epoll_ctl(eu->epoll_fd, EPOLL_CTL_DEL, e->sock, &ep_event);
                /* Flush pending messages from local message queue for this connection */
                flush_message_queue(e->conn);
                continue;
            }
            else if ((eu->activefds[i].events & EPOLLERR) ||
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
                if (e->sock == DUMMY_FD) {
                    process_local_endpoint(e);
                } else {
                    process_remote_endpoint(e);
                }
            }
        }
    }
    free(eu->activefds);
    return (NULL);
}

static inline struct conn *
get_free_connection(struct channel *ch, int flags)
{
    struct conn *c = NULL;
    int ret = 0;
    int i = 0;

    if (ck_pr_load_int(&ch->flags) & CHAN_DISCONNECTED) {
        nioDbg("Trying to reconnect channel");
        /* Need a lock here since this will be in the IO codepath */
        pthread_mutex_lock(&conn_lock);
        ret = reconnect_channel(ch);
        if(ret != 0) {
            nioDbg("Channel reconnect failed");
            pthread_mutex_unlock(&conn_lock);
            return NULL;
        }
        nioDbg("Channel reconnected");
        pthread_mutex_unlock(&conn_lock);
    }

    if (flags == CONN_FLAG_REGULAR) {
        c = ch->conn[ch->free_conn_idx % CHNL_DEFAULT_CONNECTIONS];
        ck_pr_inc_64(&(ch->free_conn_idx));
    } else {
        c = open_connection(ch, CONN_FLAG_STREAM, MAX_CLIENT_EPOLL_UNITS);
        if (c == NULL) {
            return (NULL);
        }
        pthread_mutex_lock(&conn_lock);
        for(i=0;i<MAX_STREAMS;i++) {
            if(ch->conn[ch->next_stream_idx]) {
                if(ch->next_stream_idx < (MAX_CONN-1)) {
                    ch->next_stream_idx++;
                } else {
                    ch->next_stream_idx = CHNL_DEFAULT_CONNECTIONS;
                }
                continue;
            } else {
                break;
            }
        }
        if(i == MAX_STREAMS) {
            errno = EMFILE;
            pthread_mutex_unlock(&conn_lock);
            return NULL;
        }
        ch->conn[ch->next_stream_idx] = c;

        /* Use the index as the stream id */
        c->stream_id = ch->next_stream_idx;
        pthread_mutex_unlock(&conn_lock);
        nioDbg("stream ID = %d", c->stream_id);
    }
    if (c != NULL) {
        c->flags |= flags;
    }

    return (c);
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
        return -1;
    }

    safe_fifo_enqueue(&c->fifo_q, msg);

    /* signal connection eventfd */
    c->ev.io_class->write(&c->ev, NULL, 0);
    nioDbg("Msg is enqueued msgid=%ld",msg->hinfo.cookie);
    return (0);
}

qnio_error_t
qnio_send_recv(struct qnio_ctx *ctx, struct qnio_msg *msg)
{
    struct channel *channel = NULL;
    struct conn    *c = NULL;

    if (!msg) {
        return (-1);
    }

    msg->hinfo.flags = QNIO_FLAG_SYNC_REQ | QNIO_FLAG_REQ_NEED_RESP;

    /* get channel */
    channel = qnio_map_find(ctx->channels, msg->channel);
    if (!channel) {
        return (-1);
    }
    /* find appropriate connection in channel */
    c = get_free_connection(channel, CONN_FLAG_REGULAR);
    if (!c) {
        errno = EAGAIN;
        return (-1);
    }

    msg->resp_ready = 0;
    nioDbg("Enqueuing sync send message");
    send_on_connection(msg, c);
    nioDbg("Waiting for sync send response");
    while (ck_pr_load_int(&msg->resp_ready) == 0) {
        usleep(SEND_RECV_SLEEP);
    }

    nioDbg("Got sync send response");
    return (msg->hinfo.err);
}

qnio_error_t
qnio_send(struct qnio_ctx *ctx, struct qnio_msg *msg)
{
    struct channel *channel = NULL;
    struct conn    *c = NULL;

    if (!msg) {
        return (-1);
    }

    /* get channel */
    channel = qnio_map_find(ctx->channels, msg->channel);
    if (!channel) {
        return (-1);
    }
    /* find appropriate connection in channel */
    c = get_free_connection(channel, CONN_FLAG_REGULAR);
    if (!c) {
        errno = EAGAIN;
        return (-1);
    }
    return (send_on_connection(msg, c));
}

struct qnio_msg *
qnio_alloc_msg(struct qnio_ctx *ctx)
{
    struct qnio_msg *msg;

    msg = (struct qnio_msg *) slab_get(&ctx->msg_pool);
    clear_msg(msg);
    msg->msg_pool = &ctx->msg_pool;
    return msg;
}

qnio_error_t
qnio_free_msg(struct qnio_msg *msg)
{
    slab_t *msg_pool;

    if(msg == NULL || msg->msg_pool == NULL) {
        return -1;
    }
    msg_pool = msg->msg_pool;
    nioDbg("Msg is returned back to pool msgid=%ld %p",msg->hinfo.cookie,msg);
    slab_put(msg_pool, msg);
    return QNIOERROR_SUCCESS;
}
