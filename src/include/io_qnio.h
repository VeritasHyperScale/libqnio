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

#include "types.h"
#include "qnio_api.h"
#include "datastruct.h"

#define IO_QNIO_EVENT_HANGUP  0x0001   /* The channel no longer has an endpoint */
 

#define IO_BUF_SIZE           4603904  /* 4.4MB */

#ifdef DEBUG_QNIO
#define qnioDbg(...) {\
        time_t t = time(0); \
        char buf[9] = {0}; \
        strftime(buf, 9, "%H:%M:%S", localtime(&t)); \
        fprintf(stderr, "[%s: %lu] %d: %s():\t", buf, pthread_self(), __LINE__, __FUNCTION__);\
        fprintf(stderr, __VA_ARGS__);\
}
#else
#define qnioDbg(...) ((void)0)
#endif /* DEBUG_QNIO */

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
           unsigned char *iio_recv_buf;  /* The data pointer, this is allocated by the caller */
           uint64_t iio_len; /* The size of buffer as provided in the request */
           uint64_t iio_nbytes; /* The number of bytes written or read */
       } iio_buf;
       kvset_t *iio_ps;    /* out Propertyset */
       char *iio_json;  /* out JSON */
       uint32_t iio_etype; /* A number indicating the event */
   } iio_data;
}iio_msg;

struct ioapi_ctx
{
    safe_map_t     channels;
    safe_map_t     devices;
    int32_t        next_fd;
    iio_cb_t       io_cb;
    struct qnio_ctx *qnioctx;
};

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
int32_t iio_ioctl_json(void *apictx, int32_t rfd, uint32_t opcode, char *injson, char **outjson, void *ctx, uint32_t flags);

#endif
