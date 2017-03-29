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
#define QNIO_VERSION    34

/*
 * These are the opcodes referenced by callback routine.
 */
#define IRP_READ_REQUEST                    0x1FFF
#define IRP_WRITE_REQUEST                   0x2FFF
#define IRP_VDISK_CHECK_IO_FAILOVER_READY   2020

/*
 * opcodes for iio_ioctl.
 */
#define IOR_VDISK_STAT                      1005

/*
 * Error values for iio_cb_t callback function.
 */
#define QNIOERROR_HUP                       901 /* Retriable error */
#define QNIOERROR_NOCONN                    902 /* Non-retriable error */


/* Operation Flags */
#define IIO_FLAG_ASYNC        0x0001   /* Do an async send */

/*
 * INPUT:
 *     ctx - opaque context
 *     opcode - Operation
 *     error - 0 for sucess, non-zero for failure.
 * RETURNS:
 *     void
 * DESCRIPTION:
 *     This callback is called, after Async request completes.
 *
 * CONTEXT:
 *     The callback should be wait-free.
 */
typedef void (*iio_cb_t) (void *ctx, uint32_t opcode, uint32_t error);
 
/*
 * RETURNS:
 *     0 for sucess, non-zero for failure.
 * DESCRIPTION:
 *     Intilize the library state. This should be called at the
 *     begining before issuing any library call.
 */
int iio_init(int32_t version, iio_cb_t cb);

/*
 * RETURNS:
 *     void
 * DESCRIPTION:
 *     Relinquish library resources. This should be called on the
 *     close of last open device.
 */
void iio_fini(void);

/*
 * DESCRIPTION:
 *     Returns minimum QNIO API version supported by library.
 */
int32_t iio_min_version(void);

/*
 * DESCRIPTION:
 *     Returns maximum QNIO API version supported by library.
 */
int32_t iio_max_version(void);

/*
 * INPUT:
 *    uri - const string of the format of://<hostname|ip>:port
 *    devid - Device ID.
 *    flags - currently unused, this must be set to 0
 *    cacert - CA certificates file in PEM format
 *    client_key - Client private key file in PEM format
 *    client_cert - Client certificate file in PEM format
 * RETURNS:
 *    opeque device handle on success, NULL on failure.
 * DESCRIPTION:
 *    This call returns device handle on success. Returns NULL on
 *    failure with errno set
 *    errno can be one of:
 *        ENODEV - remote device not found
 *        EBADF  - Unable to open communication channel.
 *        EBUSY  - The call cannot be completed right now
 */
void *iio_open(const char *uri, const char *devid, uint32_t flags,
               const char *cacert, const char *client_key,
               const char *client_cert);

/*
 * Close the device.
 *    For every matching iio_open() there should be a matching iio_close()
 *    The last close free all data structures associated with the device.
 */
int32_t iio_close(void *dev_handle);

/*
 * INPUT:
 *    dev_handle - device descriptor on which read/write needs to be performed
 *    ctx - an opaque context that is not interpreted This is set for
 *          async calls only. It can be NULL.
 *    iov    - an array of iovecs (This is a scatter gather operation)
 *    iovcnt  - the number of iovecs
 *    offset - an offset to perform the write
 *    size   - I/O size
 *    flags  - can be one of
 *        IIO_FLAG_ASYNC - indicating this is a aio call.
 * RETURNS:
 *        -1 on error, sets errno
 *        EBADF  - the remote fd is bad
 *        EBUSY  - The call cannot be completed right now
 *        EPIPE  - the channel got disconnected, call back would be called in
 *                 addition to this.
 */

int32_t iio_writev(void *dev_handle, void *ctx, struct iovec *iov, int iovcnt,
                   uint64_t offset, uint64_t size, uint32_t flags);

int32_t iio_readv(void *dev_handle, void *ctx, struct iovec *iov, int iovcnt,
                  uint64_t offset, uint64_t size, uint32_t flags);

int32_t iio_ioctl(void *dev_handle, uint32_t opcode, void *opaque, uint32_t flags);

#endif
