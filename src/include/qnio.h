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

#include "defs.h"
#include "qnio_api.h"
#include "iio.h"

#ifdef DEBUG
#define QNIO_HOUSEKEEPING
#endif

#define MAXFDS                      256
#define EPOLL_WAIT_TIMEOUT          -1
#define MAX_DRV_NAME_LEN            NAME_SZ64
#define REQ_MARKER                  0x5CA1AB1E
#define REQ_ERROR                   0xB000B000
#define IO_POOL_SIZE                4096
#define IO_POOL_BUF_SIZE            65536 
#define BUF_ALIGN                   4096
#define CRC_MODULO                  256

#define QNIO_SYSCALL(expression)                   \
    ({ long int __result;                         \
       do { __result = (long int)(expression); }  \
       while (__result == -1L && (errno == EAGAIN || errno == EINTR)); \
       __result; })

enum qnio_mode {
    QNIO_SERVER_MODE,
    QNIO_CLIENT_MODE
};

struct qnio_common_ctx {
    enum qnio_mode mode;
    uint64_t in, out; /* IN/OUT traffic counters */
    qnio_notify notify;
};

enum NSReadState { /* Network stream read state */
    NSRS_READ_START,
    NSRS_READ_HEADER,
    NSRS_PROCESS_HEADER,
    NSRS_READ_DATA,
    NSRS_PROCESS_DATA
};

enum NSWriteState { /* Network stream write state */
    NSWS_WRITE_START,
    NSWS_WRITE_DATA
};

struct NSReadInfo { /* Network stream read info */
    enum NSReadState state;
    qnio_byte_t headerb[HEADER_LEN];
    struct qnio_header hinfo;
    struct io_iov iovec;
    qnio_byte_t *buf;
    int buf_source;
};

struct NSWriteInfo { /* Network stream write info */
    enum NSWriteState state;
    struct io_iov iovec;
};

struct endpoint;

/*
 *  IO class descriptor (file, socket, etc)
 *  These classes are defined in io_*.c files.
 */
struct io_class
{
    const char *name;
    int         (*read)(struct endpoint *, void *buf, size_t len);
    int         (*write)(struct endpoint *, const void *buf, size_t len);
    void        (*close)(struct endpoint *);
    int         (*readv)(struct endpoint *, struct iovec *vec, int count);
    int         (*writev)(struct endpoint *, struct iovec *vec, int count); 
    void        (*read_done)(void *);
    void        (*write_done)(void *);
};

extern const struct io_class io_socket;
extern const struct io_class io_event;

/*
 * Data exchange endpoint. Represents one end of a connection
 */
struct endpoint
{
    int sock; /* File Descriptor */
    unsigned int flags;
    struct conn *conn;
    const struct io_class *io_class; /* IO class */
};

/*
 * Endpoint flags
 */
#define FLAG_R                 0x0001       /* Can read in general  */
#define FLAG_W                 0x0002       /* Can write in general */
#define FLAG_CLOSED            0x0004             
#define FLAG_DONT_CLOSE        0x0008
#define FLAG_ALWAYS_READY      0x0010       /* Some stream types like
                                                 * user_func */
/*
 * Unified socket address
 */
struct usa
{
    socklen_t len;
    union
    {
        struct sockaddr    sa;
        struct sockaddr_in sin;
    } u;
};

struct conn
{
    struct qnio_common_ctx *ctx;
    struct network_channel *netch;
    struct usa sa; /* Remote socket address */
    time_t birth_time; /* Creation time */
    int flags;
    int conn_status;
    int euid;
    int stream_id; /* Stream ID (generated) in case of long msg */
    int loc_port; /* Local port */
    int status; /* Reply status code */
    time_t expire_time; /* Expiration time */
    struct endpoint ns; /* Network stream */
    struct endpoint ev; /* Event Stream, for wake-up calls */
    struct NSReadInfo rinfo; /* State of network read */
    struct NSWriteInfo winfo; /* State of network write */
    safe_fifo_t fifo_q; /* List of pending messages */
    list_t msgs; /* List of messages with pending ack or response */
    slab_t msg_pool;
    slab_t io_buf_pool;
    pthread_mutex_t msg_lock;
};

/*
 * "struct conn" flags.
 */
#define CONN_FLAG_REGULAR           0x0001
#define CONN_FLAG_STREAM            0x0002
#define CONN_FLAG_STREAM_CLOSE      0x0004
#define CONN_FLAG_DISCONNECTED      0x0008
#define CONN_FLAG_INPROGRESS        0x0010

void process_outgoing_messages(struct conn *conn);
void process_incoming_messages(struct conn *conn);
void reset_read_state(struct NSReadInfo *rinfo);
void reset_write_state(struct NSWriteInfo *winfo);

#endif /* QNIO_HEADER_DEFINED */
