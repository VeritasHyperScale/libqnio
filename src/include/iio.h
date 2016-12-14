/*
 * Common abstartion for Network and Memory channels.
 */

#ifndef IIO_HEADER_DEFINED
#define IIO_HEADER_DEFINED

/*
 *  Opcode for driver well defined interfaces. Well defined
 *  interface use 0x1FFF to 0xFFFF, only last four bit can change.
 *  We will use OPCODE_SHIFT to fetch last four bit and use that
 *  as index.
 */
#define IOR_READ_REQUEST            0x1FFF
#define IOR_WRITE_REQUEST           0x2FFF

#define IOR_SOURCE_TAG_APPIO     0x00000100 /* Tag specific to APP-I/O (QEMU) */

#define QNIO_FLAG_REQ                  1
#define QNIO_FLAG_RESP                 2
#define QNIO_FLAG_ACK                  4
#define QNIO_FLAG_REQ_NEED_ACK         8
#define QNIO_FLAG_REQ_NEED_RESP        16
#define QNIO_FLAG_SYNC_REQ             32
#define QNIO_FLAG_SYNC_RESP            64
#define QNIO_FLAG_NOCONN               128

#define QNIO_DEFAULT_PORT              "9999"

#define QNIO_ERR_SUCCESS               0
#define QNIO_ERR_CHAN_EXISTS           1
#define QNIO_ERR_CHAN_CREATE_FAILED    2

#define HEADER_LEN                    256 

#define DATA_TYPE_RAW                 1
#define DATA_TYPE_PS                  2
#define DATA_TYPE_RAW_SS              3

#define BUF_SRC_NONE                0
#define BUF_SRC_POOL                1
#define BUF_SRC_USER                2
#define BUF_SRC_MALLOC              3

#define MSG_POOL_SIZE               4096

struct qnio_header
{
    uint64_t payload_size;
    int data_type;
    qnio_error_t err;
    uint64_t cookie;
    unsigned char crc;
    uint16_t opcode;
    uint64_t io_offset;
    uint64_t io_size;
    uint64_t io_nbytes;
    uint64_t io_seqno;
    uint64_t io_flags;
    uint64_t flags;
    uint64_t io_remote_hdl;
    uint32_t io_remote_flags;
    char target[NAME_SZ64];
};

#define HEADER_LEN      256
struct qnio_msg
{
    struct qnio_header hinfo; /* header should be the first field */
    int buf_source;
    int resp_ready;
    void *ctx; /* pointer to struct conn */
    qnio_byte_t header[HEADER_LEN];
    void *msg_pool; /* pointer to msg pool */
    void *io_pool; /* pointer to io pool */
    qnio_byte_t *io_buf;
    void *user_ctx; /* pointer to client context */
    list_t lnode; /* list of messages with pending ACK */
    io_vector *send;
    io_vector *recv;
    void *io_blob;
    void *reserved;
};

/*
 * This is abstract structure. This is not used directly.
 * The derived structure like "struct network_channel" will be used.
 */
struct channel {
    struct channel_driver *cd;
};

enum channel_type {
    IIO_NETWORK_CHANNEL,
    IIO_MEMORY_CHANNEL
};

typedef void (*qnio_notify) (struct qnio_msg *msg);
struct channel_driver {
    enum channel_type type;
    struct channel *(*chdrv_open)(void *channel_arg);
    void (*chdrv_close)(struct channel *channel);
    void (*chdrv_msg_resend_cleanup)(struct qnio_msg *);
    int (*chdrv_msg_send)(struct channel *channel, struct qnio_msg *msg);
    qnio_notify chdrv_msg_cb;
};

struct qnio_msg * iio_message_alloc(slab_t *msg_pool);
void iio_message_free(struct qnio_msg *msg);
void iio_free_io_pool_buf(struct qnio_msg *msg);
#endif /* IIO_HEADER_DEFINED */
