#ifndef QNIO_CLIENT_HEADER_DEFINED
#define QNIO_CLIENT_HEADER_DEFINED

#include <openssl/ssl.h>

#define MAX_CLIENT_EPOLL_UNITS      8
#define MAX_CONN                    8

struct network_channel_arg {
    char host[NAME_SZ64];
    char port[PORT_SZ];
};

struct qnio_client_epoll_unit
{
    struct epoll_event *activefds;      
    pthread_t client_epoll;
    int epoll_fd;
    int exit_thread;
};

struct qnio_client_ctx {
    struct channel_driver drv;
    int nchannel;
    pthread_mutex_t chnl_lock;
    qnio_map *channels;
    struct qnio_client_epoll_unit ceu[MAX_CLIENT_EPOLL_UNITS];
    const char *instance;
};

/*
 * Network Channel flags.
 */
#define CHAN_DISCONNECTED           1

/*
 * Network Channel is group of connections
 */
struct network_channel
{
    struct channel channel;
    char name[NAME_SZ64];
    char port[PORT_SZ];
    struct conn *conn[MAX_CONN];
    uint64_t free_conn_idx;
    int refcount;
    int flags;
    pthread_mutex_t conn_lock;
};

struct channel_driver* qnc_driver_init(qnio_notify client_notify);
struct channel_driver* qnc_secure_driver_init(qnio_notify client_notify, const char *instance);
extern struct qnio_client_ctx *qnc_ctx;

#endif /* QNIO_CLIENT_HEADER_DEFINED */
