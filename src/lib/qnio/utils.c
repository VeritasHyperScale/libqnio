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

void
set_close_on_exec(int fd)
{
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int
make_socket_non_blocking(int sfd)
{
    int flags, s;
    int nodelay = 1;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1)
    {
        nioDbg("fcntl error");
        return (-1);
    }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1)
    {
        nioDbg("fcntl error");
        return (-1);
    }
    setsockopt(sfd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    return (0);
}

int
compare_key(const void *x, const void *y)
{
    return (strcmp((const char *)x, (const char *)y));
}

int
compare_int(const void *x, const void *y)
{
    return ((*(int *)x) - (*(int *)y));
}

int
is_resp_required(struct qnio_msg *msg)
{
    return ((msg->hinfo.flags & QNIO_FLAG_REQ_NEED_ACK) ||
            (msg->hinfo.flags & QNIO_FLAG_REQ_NEED_RESP));
}

void
clear_msg(struct qnio_msg *msg)
{
    msg->hinfo = (const struct qnio_header){ 0 };
    msg->buf_source = 0;
    msg->resp_ready = 0;
    msg->channel = NULL;
    msg->ctx = NULL;
    memset(msg->header, 0, HEADER_LEN);
    msg->msg_pool = NULL;
    msg->io_pool = NULL;
    msg->rfd = 0;
    msg->user_ctx = 0;
    msg->lnode = (const struct list_head) { 0 };
    io_iov_clear(&msg->data_iov);
    msg->send = NULL;
    msg->recv = NULL;
    msg->io_buf = NULL;
    msg->msg_io_done = NULL;
    msg->io_blob = NULL;
    msg->reserved = NULL;
}

void *
vec_alloc(void *v)
{
    io_vector *vec = new_io_vector(1, NULL);

    io_vector_clear(vec, NULL);
    vec->_count = 0;
    vec->_total_size = 0;

    return vec;
}
