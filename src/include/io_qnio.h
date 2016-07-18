/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef IO_QNIO_HEADER_DEFINED
#define IO_QNIO_HEADER_DEFINED
#include "qnio.h"

#define IIO_REASON_SENT       0x0001   /* The buffer can be reused, data has been put on the wire */
#define IIO_REASON_RMTRX      0x0002   /* The data was successfully received on the target machine */
#define IIO_REASON_DONE       0x0004   /* The data was processed on the target, the value is returned */
#define IIO_REASON_EVENT      0x0008   /* Generic events such as disconnected etc if applicable */
#define IIO_REASON_HUP        0x0010   /* Hangup event */
 
 
  
#define IO_QNIO_EVENT_HANGUP               0x0001   /* The channel no longer has an endpoint */
 
/* Operation Flags */
 
#define IIO_FLAG_ASYNC        0x0001   /* Do an async send */
#define IIO_FLAG_NOPARTIAL    0x0002   /* No partial read/write */
#define IIO_FLAG_SENT         0x0004   /* Issue a callback when the data has been sent */
#define IIO_FLAG_RMTRX        0x0008   /* Issue a callback when the remote computer process has the data */
#define IIO_FLAG_DONE         0x0010   /* Issue a callback when the remote computer process "processed" the */
                                        /* data and has a response if there is any response */
typedef struct iio_msg_t
{
   enum 
   { 
       IIOM_DTYPE_NONE,   /* No data is present */
       IIOM_DTYPE_PS,     /* The type of the data is a propertyset */
       IIOM_DTYPE_JSON,   /* The type of the data is JSON string */
       IIOM_DTYPE_BYTES   /* The type of the data is a counted_byte */
   } type;
   uint32_t iio_error;          /* Error code */
   uint32_t iio_opcode;         /* Opcode of the request */
   union
   {
       struct 
       {
           unsigned char  *iio_recv_buf;  /* The data pointer, this is allocated by the caller */
           uint64_t iio_len; /* The size of buffer as provided in the request */
           uint64_t iio_nbytes; /* The number of bytes written or read */
       } iio_buf;
       kvset_t *iio_ps;    /* out Propertyset */
       char          *iio_json;  /* out JSON */
       uint32_t iio_etype; /* A number indicating the event */
   } iio_data;
}iio_msg;

/*
 * INPUT:
 *     rfd - The descriptor on which this operation (for which the callback is called) was performed
 *     reason - one of the reasons for the callback, please see the reasons above
 *     ctx - opaque context
 *     reply - the message pointer
 * RETURNS:
 *     void
 * DESCRIPTION:
 *     This callback is called, whenever there is something important to inform the upper layers about
 *     It can be called multiple times for the same IO request. If a request to write was done async, you can
 *     choose to get a callback when the data was written on the wire and/or when the message was processed.
 *     there are three levels of ACK that can be done and all three can be requested.
 *     One has to look at the "type" and then access the data.
 *     The callback can also be called when there is a remote hangup. In which case, there will be no data
 *     It is perfectly possible to write/read partial data. The number of bytes written is part of the iio_buf.
 *     Partial read/write can be avoided (unless error) if IIO_FLAG_NOPARTIAL is specified for the request
 * MEMORY_MANAGEMENT:
 *     The callee is responsible for all internal buffers
 *     If the callback is as a result of a read request, the data buffer is exactly the same buffer used
 *     during the call to iio_read(), the same is the case with iio_write
 *     Propertysets are returned as a result of a callback due to a completion of an iio_ioctl()
 *     this again is the propertyset passed in as part of the argument (out argument).
 * CONTEXT:
 *     The callback is called in the interrupt context which implies, the callback should be returned right away
 *     no memory allocation can be done either from system or from pool. The callback should be wait-free.
 */
typedef void (*iio_cb_t) (int32_t rfd, uint32_t reason, void *ctx, iio_msg *reply);
 
struct ioapi_ctx
{
    safe_map_t     channels;
    safe_map_t     devices;
    safe_map_t     dev_refcount; 
    int32_t        next_fd;
    iio_cb_t       io_cb;
    struct qnio_ctx *qnioctx;
    int32_t        need_json;
};

OF_EXT_API_ (struct ioapi_ctx *) iio_init(iio_cb_t cb);

/*
 * INPUT:
 *    uri - const string of the format of://<hostname|ip>:port
 *    flags - currently unused, this must be set to 0
 * DESCRIPTION:
 *    This call returns the channel descriptor > 0 and -1 on error with errno set
 */
OF_EXT_API_ (int32_t) iio_open(struct ioapi_ctx *apictx, const char *uri, uint32_t flags);

/*
 * INPUT:
 *    cfd - got from a previous open call to iio_open();
 *    devpath - remote device path eg. /dev/of/vdisk/vdisk1
 *    flags - must be set to 0
 * RETURNS:
 *     rfd - a descriptor for the device
 *    -1 on error, errno is set to what the error indicates
 *    errno can be one of:
 *        ENODEV - remote device not found
 *        EBADF  - the channel id is bad
 *        EBUSY  - The call cannot be completed right now
 *        EPIPE  - the channel got disconnected, call back would be called in addition to this.
 * DESCRIPTION:
 *     The call "indicates" an intent to use the device. No guarantees on the implementations can be assumed.
 *     The caller should call iio_devclose with the descriptor returned once the intent is done.
 *     The fd returned is invalid after iio_devclose
 *    
 */
OF_EXT_API_(int32_t) iio_devopen(struct ioapi_ctx *apictx, int32_t cfd, const char *devpath, uint32_t flags);

/*
 * INPUT:
 *    cfd - got from a previous open call to iio_open();
 *    rfd - a descriptor previously opened by iio_devopen()
 * OUTPUT: None
 * DESCRIPTION:
 *    the call invalidates an rfd previously opened using iio_devopen()
 *    Calling iio_devclose() multiple times results in an undefined behavior.
 *    For every matching iio_devopen() there should be a matching iio_devclose()
 *    The call frees all data structures associated with the remote device
 */
OF_EXT_API_(int32_t) iio_devclose(struct ioapi_ctx *apictx, int32_t cfd, int32_t rfd);
 
/*
 * INPUT:
 *    cfd - got from a previous open call to iio_open();
 *    rfd - the remove device descriptor on which write needs to be performed
 *    ctx - an opaque context that is not interpreted This is set for async calls only
 *          It can be NULL.
 *    offset - an offset to perform the write
 *    count  - the number of iovecs
 *    iov - an array of iovecs (This is a scatter gather operation)
 *    flags - can be one of
 *        IIO_FLAG_ASYNC - indicating this is a aio call.
 *        IIO_FLAG_SENT  - callback when all data hits the wire and buffers are free to be be reused
 *        IIO_FLAG_RMTRX - callback when the remote host process receives the data
 *        IIO_FLAG_DONE  - callback when the remote host process is done with the data and sent to stable storage
 * RETURNS:
 *        -1 on error, sets errno
 *        EBADF  - the remote fd is bad
 *        EBUSY  - The call cannot be completed right now
 *        EPIPE  - the channel got disconnected, call back would be called in addition to this.
 */
OF_EXT_API_(int32_t) iio_writev(struct ioapi_ctx *apictx, int32_t rfd, struct iovec *iov, int iovcnt, uint64_t offset, void *ctx, uint32_t flags);

/*
 * INPUT:
 *    apictx - API context for the request 
 *    rfd - the remove device descriptor on which write needs to be performed
 *    ctx - an opaque context that is not interpreted. This is set for async calls only
 *          It can be NULL.
 *    opcode - an opcode for the ioctl
 *    injson  - the input json 
 *    outjson - the output json (this is optional)
 *    flags - can be one of
 *        IIO_FLAG_ASYNC - indicating this is a aio call.
 *        IIO_FLAG_SENT  - callback when the request hits the wire and inps is freed to be be reused
 *        IIO_FLAG_RMTRX - callback when the remote host process receives the request
 *        IIO_FLAG_DONE  - callback when the remote host process is done with the request and response
 *                         will be set in the callback
 * If the call is sync, then the call blocks until a response is received and the outps is populated.
 * No callbacks are called.
 * RETURNS:
 *        -1 on error, sets errno
 *        EBADF  - the remote fd is bad
 *        EBUSY  - The call cannot be completed right now
 *        EPIPE  - the channel got disconnected, call back would be called in addition to this.
 */
OF_EXT_API_(int32_t) iio_ioctl_json(struct ioapi_ctx *apictx, int32_t rfd, uint32_t opcode, char *injson, char **outjson, void *ctx, uint32_t flags);


/*
 * INPUT:
 *    cfd - got from a previous open call to iio_open();
 *    rfd - the remove device descriptor on which write needs to be performed
 *    ctx - an opaque context that is not interpreted. This is set for async calls only
 *          It can be NULL.
 *    offset - an offset to read from
 *    size  - the size of the read request
 *    buf - the output buffer of size "size"
 *    flags - can be one of
 *        IIO_FLAG_ASYNC - indicating this is a aio call.
 *        IIO_FLAG_SENT  - callback when the request hits the wire and inps is freed to be be reused
 *        IIO_FLAG_RMTRX - callback when the remote host process receives the request
 *        IIO_FLAG_DONE  - callback when the remote host process is done with the request and response
 *                         will be set in the callback as IIO_REASON_DONE with the data type as IIOM_DTYPE_BYTES 
 * If the call is sync, then the call blocks until a response is received and the buffer is read.
 * No callbacks are called.
 * It should be noted, that the buf needs to be stable until the callback with request IIO_REASON_DONE is completed
 * in the case of async io
 * RETURNS:
 *        -1 on error, sets errno
 *        EBADF  - the remote fd is bad
 *        EBUSY  - The call cannot be completed right now
 *        EPIPE  - the channel got disconnected, call back would be called in addition to this.
 */
OF_EXT_API_(int32_t) iio_read(struct ioapi_ctx *apictx, int32_t rfd, unsigned char *buf, uint64_t size, uint64_t offset, void *ctx, uint32_t flags); 

/*
 * Delete a previously created channel
 */
OF_EXT_API_(int32_t) iio_close(struct ioapi_ctx *apictx, uint32_t cfd);

#endif
