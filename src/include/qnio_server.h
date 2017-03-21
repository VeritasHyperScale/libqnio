#ifndef QNIO_SERVER_HEADER_DEFINED
#define QNIO_SERVER_HEADER_DEFINED

#include <openssl/ssl.h>

#define MAX_EPOLL_UNITS             16 
#define QNIO_DEFAULT_PORT           "9999"
#define SECURE_IMPL                 "/var/lib/libvxhs/secure"

/*
 * An epoll unit to allow for scaling on server.
 * Threads can service an epoll unit. 
 * Connections will be assigned to epoll units.
 * Max number of epoll units will determine the number of threads used.
 */
struct qnio_epoll_unit
{
    struct epoll_event *send_activefds; /* Send Epoll active fd set     */
    struct epoll_event *recv_activefds; /* Recv Epoll active fd set     */
    int send_epoll_fd;  /* Send Epoll fd                */
    int recv_epoll_fd;  /* Recv Epoll fd                */
    pthread_t send_epoll;
    pthread_t recv_epoll;
};

struct qnio_server_ctx {
    char *node;
    char *port;
    unsigned long nrequests;
    int listen_fd; /* Source fd */
    int epoll_fd; /* Epoll fd */
    struct epoll_event *activefds; /* Epoll active fd set */
    qnio_map *channels;
    struct qnio_epoll_unit eu[MAX_EPOLL_UNITS];
};

qnio_error_t qns_server_init(qnio_notify server_notify);
qnio_error_t qns_server_start(char *node, char *port);
qnio_error_t qns_send_resp(struct qnio_msg *msg);
int is_secure();

#endif /* QNIO_SERVER_HEADER_DEFINED */
