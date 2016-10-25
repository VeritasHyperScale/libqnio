/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef QNIODEFS_HEADER_DEFINED
#define QNIODEFS_HEADER_DEFINED    1

#include <stdio.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/eventfd.h>

#include "qnio.h"
#include "io_qnio.h"
#include "datastruct.h"
#include "list.h"
#include "io.h"

#define MAXFDS                      256
#define EPOLL_WAIT_TIMEOUT          -1
#define MAX_DRV_NAME_LEN            NAME_SZ64
#define REQ_MARKER                  0x5CA1AB1E
#define REQ_ERROR                   0xB000B000
#define IO_QUEUE_DEPTH              16
#define CHNL_DEFAULT_CONNECTIONS    8 
#define MSG_POOL_SIZE               4096
#define IO_POOL_SIZE                4096
#define IO_POOL_BUF_SIZE            65536 
#define BILLION                     1E9
#define BUF_ALIGN                   4096
#define DUMMY_FD                    -999
#define DUMMY_CHANNEL               "dummychannel" 
#define MAX_STREAMS                 1024
#define MAX_CONN                    MAX_STREAMS + CHNL_DEFAULT_CONNECTIONS

#define CONN_FLAG_REGULAR           1
#define CONN_FLAG_STREAM            2
#define CONN_FLAG_STREAM_CLOSE      4
#define CONN_FLAG_DISCONNECTED      8
#define CONN_FLAG_INPROGRESS        16 

#define CHAN_DISCONNECTED           1
#define CHAN_SERVER                 2
#define CHAN_CLIENT                 4

#define CONN_TRY_SYNC               0
#define CONN_TRY_ASYNC              1

/* connection status */
#define CONN_FREE                   0
#define CONN_INUSE                  1

#define MSG_TYPE_REQUEST            1
#define MSG_TYPE_RESPONSE           2

#define BUF_SRC_NONE                0
#define BUF_SRC_POOL                1
#define BUF_SRC_USER                2
#define BUF_SRC_MALLOC              3

#define CRC_MODULO                  256

#define TMPDIR                      "/var/tmp"
#define ERRNO                       errno
#define SEND_RECV_SLEEP             200

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

/*
 * Endpoint status
 */
#define FLAG_R                 0x0001       /* Can read in general  */
#define FLAG_W                 0x0002       /* Can write in general */
#define FLAG_CLOSED            0x0004             
#define FLAG_DONT_CLOSE        0x0008
#define FLAG_ALWAYS_READY      0x0010       /* Some stream types like
                                                 * user_func */
#define QNIO_SYSCALL(expression)                   \
    ({ long int __result;                         \
       do { __result = (long int)(expression); }  \
       while (__result == -1L && (errno == EAGAIN || errno == EINTR)); \
       __result; })

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

struct conn
{
    struct qnio_ctx *ctx;
    struct channel *channel;
    struct usa sa; /* Remote socket address */
    time_t birth_time; /* Creation time */
    int flags;
    int conn_status;
    int euid;
    int stream_id; /* Stream ID (generated) in case of long msg */
    int loc_port; /* Local port */
    int status; /* Reply status code */
    time_t expire_time; /* Expiration time */
    struct endpoint loc; /* Local stream */
    struct endpoint rem; /* Remote stream */
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
 * Client side channel. Basically a group of connections
 */
struct channel
{
    char           name[NAME_SZ64];
    char           port[8];
    struct conn    *conn[MAX_CONN];    /* Array of connection pointers */
    uint64_t       free_conn_idx;
    int            next_stream_idx;
    struct qnio_ctx *ctx;
    int            flags;
};

extern const struct io_class io_file;
extern const struct io_class io_socket;
extern const struct io_class io_event;
extern const struct io_class io_qnio;

void set_close_on_exec(int);
int make_socket_non_blocking(int);
void print_ps(kvset_t *);
void print_map(void *i, void *);
int compare_key(const void *x, const void *y);
int compare_int(const void *x, const void *y);
int is_resp_required(struct qnio_msg *msg);

qnio_byte_t * generate_header(struct qnio_msg *msg);
void process_connection(struct conn *c);
void process_local_endpoint(struct endpoint *local);
void process_remote_endpoint(struct endpoint *remote);
void disconnect(struct conn *c);
int close_connection(struct conn *c);
void flush_message_queue(struct conn *c);
void flush_pending_messages(struct conn *c);
void mark_pending_noconn(struct conn *c);
void reset_read_state(struct NSReadInfo *rinfo);
void reset_write_state(struct NSWriteInfo *winfo);

int create_and_bind(char *node, char *port);
void clear_msg(struct qnio_msg *msg);

#define nioErr(fmt, ...) {\
        time_t t = time(0); \
        char buf[9] = {0}; \
        strftime(buf, 9, "%H:%M:%S", localtime(&t)); \
        fprintf(stderr, "[%s: %lu] %d: %s():\t" fmt "\n",\
		buf, pthread_self(), __LINE__, __FUNCTION__, ##__VA_ARGS__);\
}

#define nioDbg nioErr

#endif /* QNIOEFS_HEADER_DEFINED */
