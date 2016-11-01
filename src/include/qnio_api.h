/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef QNIO_API_H
#define QNIO_API_H

#include <sys/uio.h>

/*
 * Bump up the version everytime this file is modified
 */
#define QNIO_VERSION    33

/*
 * These are the opcodes referenced by qemu callback.
 * At present vxhs_iio_callback().
 */
#define IRP_READ_REQUEST                    0x1FFF
#define IRP_WRITE_REQUEST                   0x2FFF
#define IRP_VDISK_CHECK_IO_FAILOVER_READY   2020

#define IOR_VDISK_STAT                      1005
#define IOR_VDISK_GET_GEOMETRY              2017
#define IOR_VDISK_FLUSH                     2019
#define IOR_VDISK_CHECK_IO_FAILOVER_READY   IRP_VDISK_CHECK_IO_FAILOVER_READY

#define QNIOERROR_RETRY_ON_SOURCE           44
#define QNIOERROR_HUP                       901
#define QNIOERROR_NOCONN                    902
#define QNIOERROR_CHANNEL_HUP               903


/* Operation Flags */
#define IIO_FLAG_ASYNC        0x0001   /* Do an async send */
#define IIO_FLAG_NOPARTIAL    0x0002   /* No partial read/write */
#define IIO_FLAG_SENT         0x0004   /* Issue a callback when the 
                                          data has been sent */
#define IIO_FLAG_RMTRX        0x0008   /* Issue a callback when the remote
                                          computer process has the data */
#define IIO_FLAG_DONE         0x0010   /* Issue a callback when the remote 
                                          computer process "processed" the
                                          data and has a response if there
                                          is any response */


/* Buffer can be reused, data has been put on the wire */
#define IIO_REASON_SENT                     0x00000001

/* Data was successfully received on the target machine */
#define IIO_REASON_RMTRX                    0x00000002

/* Data was processed on the target, the value is returned */
#define IIO_REASON_DONE                     0x00000004

/* Generic events such as disconnected etc if applicable */
#define IIO_REASON_EVENT                    0x00000008

/* Hangup event */
#define IIO_REASON_HUP                      0x00000010

#define IIO_IO_BUF_SIZE                     4194304 /* 4.0MB */

/*
 * INPUT:
 *     rfd - The descriptor on which this operation was performed
 *     reason - one of the reasons for the callback, please see the reasons above
 *     ctx - opaque context
 *     error - 0 for sucess, non-zero for failure.
 *     opcode - Operation
 * RETURNS:
 *     void
 * DESCRIPTION:
 *     This callback is called, whenever there is something important
 *     to inform the upper layers about. It can be called multiple times
 *     for the same IO request. If a request to write was done async, you
 *     can choose to get a callback when the data was written on the wire 
 *     and/or when the message was processed. There are three levels of ACK
 *     that can be done and all three can be requested. One has to look at
 *     the "type" and then access the data.
 *     The callback can also be called when there is a remote hangup. In which
 *     case, there will be no data. It is perfectly possible to write/read
 *     partial data. The number of bytes written is part of the iio_buf.
 *     Partial read/write can be avoided (unless error) if IIO_FLAG_NOPARTIAL
 *     is specified for the request.
 *
 * MEMORY_MANAGEMENT:
 *     The callee is responsible for all internal buffers
 *     If the callback is as a result of a read request, the data buffer is
 *     exactly the same buffer used during the call to iio_read(), the same
 *     is the case with iio_write. Property sets are returned as a result of
 *     a callback due to a completion of an iio_ioctl(). This again is the 
 *     property set passed in as part of the argument (out argument).
 *
 * CONTEXT:
 *     The callback is called in the interrupt context which implies,
 *     the callback should be returned right away no memory allocation
 *     can be done either from system or from pool. The callback should
 *     be wait-free.
 */
typedef void (*iio_cb_t) (int32_t rfd, uint32_t reason, void *ctx,
                          uint32_t error, uint32_t opcode);
 
void *iio_init(int32_t version, iio_cb_t cb);

void iio_fini(void *);

int32_t iio_min_version(void);
int32_t iio_max_version(void);

/*
 * INPUT:
 *    uri - const string of the format of://<hostname|ip>:port
 *    flags - currently unused, this must be set to 0
 * DESCRIPTION:
 *    This call returns the channel descriptor > 0 and -1 on error
 *    with errno set
 */
int32_t iio_open(void *apictx, const char *uri, uint32_t flags);

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
 *        EPIPE  - the channel got disconnected, callback would be called
 *                 in addition to this.
 * DESCRIPTION:
 *     The call "indicates" an intent to use the device. No guarantees
 *     on the implementations can be assumed.
 *     The caller should call iio_devclose with the descriptor returned
 *     once the intent is done. The fd returned is invalid after iio_devclose
 */
int32_t iio_devopen(void *apictx, int32_t cfd, const char *devpath,
                    uint32_t flags);

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
int32_t iio_devclose(void *apictx, int32_t cfd, int32_t rfd);
 
/*
 * INPUT:
 *    rfd - the remove device descriptor on which write needs to be performed
 *    ctx - an opaque context that is not interpreted This is set for
 *          async calls only. It can be NULL.
 *    offset - an offset to perform the write
 *    size   - I/O size
 *    iov    - an array of iovecs (This is a scatter gather operation)
 *    count  - the number of iovecs
 *    flags  - can be one of
 *        IIO_FLAG_ASYNC - indicating this is a aio call.
 *        IIO_FLAG_SENT  - callback when all data hits the wire and buffers
 *                         are free to be be reused
 *        IIO_FLAG_RMTRX - callback when the remote host process receives
 *                         the data
 *        IIO_FLAG_DONE  - callback when the remote host process is done with
 *                         the data and sent to stable storage
 * RETURNS:
 *        -1 on error, sets errno
 *        EBADF  - the remote fd is bad
 *        EBUSY  - The call cannot be completed right now
 *        EPIPE  - the channel got disconnected, call back would be called in
 *                 addition to this.
 */

int32_t iio_writev(void *apictx, int32_t rfd, struct iovec *iov, int iovcnt,
                   uint64_t offset, uint64_t size, void *ctx, uint32_t flags);

int32_t iio_readv(void *apictx, int32_t rfd, struct iovec *iov, int iovcnt,
                   uint64_t offset, uint64_t size, void *ctx, uint32_t flags);

int32_t iio_read(void *apictx, int32_t rfd, unsigned char *buf,
                 uint64_t size, uint64_t offset, void *ctx, uint32_t flags); 

int32_t iio_ioctl(void *apictx, int32_t rfd, uint32_t opcode,
                  int64_t *vdisk_size, void *ctx, uint32_t flags);
/*
 * Delete a previously created channel
 */
int32_t iio_close(void *apictx, uint32_t cfd);

#endif
