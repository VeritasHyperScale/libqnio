/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef IIOAPI_HEADER_DEFINED
#define IIOAPI_HEADER_DEFINED

#include "types.h"
#include "datastruct.h"
#include "list.h"
#include "iio.h"

struct ioapi_ctx
{
    iio_cb_t io_cb;
    slab_t msg_pool;
    qnio_map *devices;
    pthread_mutex_t dev_lock;
    int ndevices;
    struct channel_driver *network_driver;
};
 
enum iio_device_state
{
    IIO_DEVICE_ACTIVE,
    IIO_DEVICE_QUIESCE,
    IIO_DEVICE_FAILOVER,
    IIO_DEVICE_FAILED
};

struct iio_vdisk_hostinfo
{
    char hosts[MAX_HOSTS][NAME_SZ];
    int nhosts;
    int failover_idx;
};

struct iio_device
{
    int refcount;
    enum iio_device_state state;
    char devid[NAME_SZ64];
    struct iio_vdisk_hostinfo *hostinfo;
    struct channel *channel;
    ck_spinlock_fas_t slock;
    list_t retryq;
    int active_msg_count;
    int retry_msg_count;
};

#endif /* IIOAPI_HEADER_DEFINED */
