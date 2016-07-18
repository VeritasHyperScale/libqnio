/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef QEMU_QNIO_HEADER_DEFINED
#define QEMU_QNIO_HEADER_DEFINED 1

#include <errno.h>
#include <inttypes.h>
#include <time.h>

#include "qnio.h"
#include "io_qnio.h"
#include "datastruct.h"

#define IOR_VDISK_STAT                  1005
#define IOR_VDISK_GET_GEOMETRY          2017
#define IOR_VDISK_FLUSH                 2019
#define IOR_VDISK_CHECK_IO_FAILOVER_READY    2020

#define qnioErr(...) {\
        time_t t = time(0); \
        char buf[9] = {0}; \
        strftime(buf, 9, "%H:%M:%S", localtime(&t)); \
        fprintf(stderr, "[%s: %lu] %d: %s():\t", buf, pthread_self(), __LINE__, __FUNCTION__);\
        fprintf(stderr, __VA_ARGS__);\
}

#define qnioDbg qnioErr

typedef enum {
    VDISK_AIO_READ,
    VDISK_AIO_WRITE,
    VDISK_STAT,
    VDISK_TRUNC,
    VDISK_AIO_FLUSH,
    VDISK_AIO_RECLAIM,
    VDISK_GET_GEOMETRY,
    VDISK_CHECK_IO_FAILOVER_READY,
    VDISK_AIO_LAST_CMD
} VDISKAIOCmd;

typedef void *qemu_aio_ctx_t;
typedef void (*qnio_callback_t)(ssize_t retval, void *arg);

#define QNIO_VDISK_NONE          0x00
#define QNIO_VDISK_CREATE        0x01

#define QEMU_VECTOR_ALIGNED		0
#define QEMU_VECTOR_NOT_ALIGNED		-1

#define QEMU_DONOT_COPY			0
#define QEMU_DO_COPY			1
#define QEMU_SECTOR_SIZE		VDBLK_SIZE
#define QEMU_SECTOR_SIZE_POWER		9

typedef struct qemu2qnio_ctx {
    uint32_t            qnio_flag;
    uint64_t            qnio_size;
    char                *qnio_channel;
    char                *target;
    qnio_callback_t      qnio_cb;
} qemu2qnio_ctx_t;

typedef qemu2qnio_ctx_t qnio2qemu_ctx_t;

extern void notify_to_qemu(struct qnio_msg *msg);
extern int qemu_qnio_open(qemu2qnio_ctx_t *qnio2qemu_ctx);
extern int qemu_qnio_submit_io(struct iovec *iov, int64_t niov, int64_t offset,
				qemu2qnio_ctx_t *qemu2qnio_msg, int cmd, qemu_aio_ctx_t ctx); 
extern int qemu_qnio_close(qemu2qnio_ctx_t *qnio2qemu_ctx);
extern void vxhs_dec_acb_segment_count(void *acb, int count);
extern void vxhs_inc_acb_segment_count(void *acb, int count);
extern void vxhs_set_acb_buffer(void *ptr, void *buffer);

#endif
