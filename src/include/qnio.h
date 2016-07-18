/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef QNIO_HEADER_DEFINED
#define QNIO_HEADER_DEFINED    1

#include <sys/uio.h>
#include "types.h"
#include "datastruct.h"
#include "io_iov.h"
#include "list.h"

#define QNIO_FLAG_REQ                  1
#define QNIO_FLAG_RESP                 2
#define QNIO_FLAG_ACK                  4
#define QNIO_FLAG_REQ_NEED_ACK         8
#define QNIO_FLAG_REQ_NEED_RESP        16
#define QNIO_FLAG_SYNC_REQ             32
#define QNIO_FLAG_SYNC_RESP            64
#define QNIO_FLAG_NOCONN               128

#define QNIO_DEFAULT_PORT              "9999"
#define IO_BUF_SIZE                   4603904 /* 4.4MB */
#define IIO_IO_BUF_SIZE               4194304 /* 4.0MB */

#define QNIO_ERR_SUCCESS               0
#define QNIO_ERR_CHAN_EXISTS           1
#define QNIO_ERR_CHAN_CREATE_FAILED    2

#define HEADER_LEN                    256 

#define DATA_TYPE_RAW                 1
#define DATA_TYPE_PS                  2
#define DATA_TYPE_RAW_SS              3

#define MAX_EPOLL_UNITS               16 
#define MAX_CLIENT_EPOLL_UNITS        8 

#ifdef DEBUG
#define QNIO_HOUSEKEEPING
#endif

struct qnio_msg;
struct qnio_ctx;

typedef void (*qnio_notify) (struct qnio_msg *msg);

/*
 * An epoll unit to allow for scaling on either the client or server.
 * Threads on server/client can service an epoll unit. 
 * Connections will be assigned to epoll units.
 * Max number of epoll units will determine the number of threads used.
 */
struct qnio_epoll_unit
{
    struct epoll_event *send_activefds; /* Send Epoll active fd set     */
    struct epoll_event *recv_activefds; /* Recv Epoll active fd set     */
    int                 send_epoll_fd;  /* Send Epoll fd                */
    int                 recv_epoll_fd;  /* Recv Epoll fd                */
    pthread_t          send_epoll;
    pthread_t          recv_epoll;
    struct qnio_ctx     *ctx;
};

struct qnio_client_epoll_unit
{
    struct epoll_event *activefds;      
    int                 epoll_fd;       
    pthread_t          client_epoll;
    struct qnio_ctx     *ctx;
};

struct qnio_ctx
{
    char         *node;
    char         *port;
    clock_t       start_time;           /* Start time                   */
    int           nactive;              /* # of connections now         */
    unsigned long nrequests;            /* Requests made                */
    uint64_t      in, out;              /* IN/OUT traffic counters      */

    int                 io_buf_size;    /* IO Buffer size               */
    struct epoll_event *activefds;      /* Epoll active fd set          */
    int                 listen_fd;      /* Source fd                    */
    int                 epoll_fd;       /* Epoll fd                     */
    uint64_t            nmsgid;
    qnio_map             *channels;
    qnio_notify          notify;
    qnio_notify          gc;
    qnio_notify          msg_io_done;
    void               *payload_pool;
    slab_t             msg_pool;
    struct qnio_epoll_unit eu[MAX_EPOLL_UNITS];
    struct qnio_client_epoll_unit ceu[MAX_EPOLL_UNITS+1];
    void               *apictx;
};

struct qnio_header
{
    uint64_t         payload_size;
    int              data_type;
    qnio_error_t       err;
    uint64_t         cookie;
    unsigned char    crc;
    uint16_t         opcode;
    uint64_t         io_offset;
    uint64_t         io_size;
    uint64_t         io_nbytes;
    uint64_t         io_seqno;
    uint64_t         io_flags;
    uint64_t         flags;
    uint64_t         io_remote_hdl;
    uint32_t         io_remote_flags;
    char             target[NAME_SZ64];
};


struct qnio_msg
{
    struct qnio_header hinfo;
    /* New members to this structure go after this */
    int           buf_source;
    int           resp_ready;
    char         *channel;
    void         *ctx;      /* pointer to struct conn */
    qnio_byte_t     header[HEADER_LEN];
    void         *msg_pool; /* pointer to msg pool */
    void         *io_pool;  /* pointer to io pool */
    int           rfd;      /* remote file descriptor for this message */
    void         *user_ctx; /* pointer to client context */
    list_t        lnode;    /* list node */
    struct io_iov data_iov;
    io_vector    *send;
    io_vector    *recv;
    qnio_byte_t    *io_buf;
    qnio_notify    msg_io_done;
    void         *io_blob;
    void         *reserved;
};


struct qnio_ctx * qnio_client_init(qnio_notify client_notify);
qnio_error_t qnio_create_channel(struct qnio_ctx *ctx, char *channel, char *port);
qnio_error_t qnio_send(struct qnio_ctx *ctx, struct qnio_msg *msg);
qnio_error_t qnio_send_recv(struct qnio_ctx *ctx, struct qnio_msg *msg);
int qnio_stream_open(struct qnio_ctx *ctx, char *channel);
qnio_error_t qnio_stream_send(struct qnio_ctx *ctx, int stream, struct qnio_msg *msg);
qnio_error_t qnio_stream_close(struct qnio_ctx *ctx, char *channel, int stream);
qnio_error_t qnio_destroy_channel(struct qnio_ctx *ctx, char *chnl_name);
qnio_error_t qnio_set_client_gc_callback(struct qnio_ctx *ctx, qnio_notify callback);
qnio_error_t qnio_set_client_msg_io_done_callback(struct qnio_ctx *ctx, qnio_notify callback);

/* Server side interfaces */
qnio_error_t qnio_server_init(qnio_notify server_notify);
qnio_error_t qnio_set_server_gc_callback(qnio_notify callback);
qnio_error_t qnio_set_server_msg_io_done_callback(qnio_notify callback);
qnio_error_t qnio_server_start(char *node, char *port);
qnio_error_t qnio_send_resp(struct qnio_msg *msg);

struct qnio_msg *qnio_alloc_msg(struct qnio_ctx *ctx);
qnio_error_t qnio_free_msg(struct qnio_msg *msg);
qnio_error_t qnio_free_io_pool_buf(struct qnio_msg *msg);

#endif
