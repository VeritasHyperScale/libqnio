/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "types.h"
#include "qnio_api.h"
#include "iioapi.h"
#include "defs.h"
#include "qnio_client.h"
#include "utils.h"
#include "cJSON.h"
#include <inttypes.h>

#define VDISK_TARGET_DIR            "/var/libqnio/vdisk"
#define QNIO_QEMU_VDISK_SIZE_STR    "vdisk_size_bytes"
#define IP_ADDR_LEN                 20
#define SEND_RECV_SLEEP             200 /* micro seconds */
#define FAILOVER_RETRY_WAIT         500000 /* micro seconds */
#define FAILOVER_TIMEOUT            60 /* seconds */

static void client_callback(struct qnio_msg *msg);
static int iio_check_failover_ready(struct iio_device *);

/*
 * Supported versions
 */
int32_t qnio_min_version = 34; 
int32_t qnio_max_version = 34;
struct ioapi_ctx *apictx;

struct iio_vdisk_hostinfo *
iio_read_hostinfo(const char *devid)
{
    FILE *fp;
    char filename[1024];
    char str[256];
    char hostname[NAME_SZ64];
    char port[PORT_SZ];
    struct iio_vdisk_hostinfo *hostinfo;
    int match;

    hostinfo = (struct iio_vdisk_hostinfo *)malloc(sizeof (struct iio_vdisk_hostinfo));
    sprintf(filename, "%s/%s.targets", VDISK_TARGET_DIR, devid);
    fp = fopen(filename, "r");
    if (!fp) {
        goto err;
    }

    hostinfo->nhosts = 0;
    hostinfo->failover_idx = 0;
    while (fscanf(fp, "%255s", str) != EOF) {
        if (hostinfo->nhosts >= MAX_HOSTS) {
            break;
        }
        match = sscanf(str, "of://%64[^:]:%8s", hostname, port);
        if (match != 2) {
            nioDbg("Invalid entry for device %s(%s)", devid, str);
            continue;
        }
        nioDbg("iio_read_hostinfo: %s\n", str);
        strncpy(hostinfo->hosts[hostinfo->nhosts], str, NAME_SZ);
        hostinfo->nhosts ++;
    }
    fclose(fp);
    if (hostinfo->nhosts == 0) {
        goto err;
    }
    return hostinfo;

err:
    if (hostinfo) {
        free(hostinfo);
    }
    return NULL;
}

static struct channel *
iio_channel_open(const char *uri)
{
    struct network_channel_arg nc_arg;
    struct channel *channel;
    int match = 0;
 
    match = sscanf(uri, "of://%64[^:]:%8s", nc_arg.host, nc_arg.port);
    if(match != 2) {
        nioDbg("parse uri failed [%s] match=%d", uri, match);
        return NULL;
    }
    nioDbg("iio_open: uri=%s, host=%s, port=%s\n", uri, nc_arg.host, nc_arg.port);
    channel = apictx->network_driver->chdrv_open(&nc_arg);
    if (!channel) {
        errno = EBADF;
        return NULL;
    }
    return channel;
}

/*
 * Resubmit message due to service failover.
 */
static void
iio_msg_resubmit(struct iio_device *device, struct qnio_msg *msg)
{
    int32_t err;
    struct channel *channel;

    channel = device->channel;
    err = channel->cd->chdrv_msg_send(channel, msg);
    if (err) {
        msg->hinfo.err = err;
        if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ) {
            ck_pr_store_int(&msg->resp_ready, 1);
        } else {
            channel->cd->chdrv_msg_cb(msg);
        }
    }
    return;
}

static void *
iio_device_failover_thread(void *args)
{
    struct iio_device *device = (struct iio_device *)args;
    struct iio_vdisk_hostinfo *hostinfo = device->hostinfo;
    struct channel *new_channel;
    struct qnio_msg *msg;
    time_t start_t, end_t;
    double diff_t;

    time(&start_t);
    nioDbg("Starting failover on device %s", device->devid);
    hostinfo->failover_idx = -1;

retry:
    /*
     * Find next host
     */
    hostinfo->failover_idx ++;
    if (hostinfo->failover_idx == hostinfo->nhosts) {
        hostinfo->failover_idx = 0;
    }

    /*
     * Open channel to the new host
     */
    new_channel = iio_channel_open(hostinfo->hosts[hostinfo->failover_idx]);
    if (new_channel == NULL) {
        time(&end_t);
        diff_t = difftime(end_t, start_t);
        if (diff_t > FAILOVER_TIMEOUT) {
            nioDbg("Failover timedout");
            goto err;
        }
        usleep(FAILOVER_RETRY_WAIT);
        goto retry;
    }

    /*
     * Close the old channel.
     */
    device->channel->cd->chdrv_close(device->channel);
    device->channel = new_channel;

    if (!iio_check_failover_ready(device)) {
        goto retry;
    }

    /*
     * Restart messages
     */
    ck_spinlock_lock(&device->slock);
    device->state = IIO_DEVICE_ACTIVE; 
    while (!LIST_EMPTY(&device->retryq)) {
        msg = LIST_ENTRY(device->retryq.next, struct qnio_msg, lnode);
        LIST_DEL(&msg->lnode);
        device->retry_msg_count --;
        ck_spinlock_unlock(&device->slock);
        nioDbg("Restarting message, msgid=%ld %p",msg->hinfo.cookie, msg);
        iio_msg_resubmit(device, msg);
        ck_spinlock_lock(&device->slock);
    }
    ck_spinlock_unlock(&device->slock);
    pthread_exit(0);
    return NULL;

err:
    /*
     * Fail all messages.
     */
    ck_spinlock_lock(&device->slock);
    device->state = IIO_DEVICE_FAILED;
    while (!LIST_EMPTY(&device->retryq)) {
        msg = LIST_ENTRY(device->retryq.next, struct qnio_msg, lnode);
        LIST_DEL(&msg->lnode);
        nioDbg("No host found failing message, msgid=%ld %p", msg->hinfo.cookie, msg);
        device->retry_msg_count --;
        ck_spinlock_unlock(&device->slock);
        msg->hinfo.err = QNIOERROR_NOCONN;
        if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ) {
            ck_pr_store_int(&msg->resp_ready, 1);
        } else {
            client_callback(msg);
        }
    }
    ck_spinlock_unlock(&device->slock);
    pthread_exit(0);
    return NULL;    
}

static void
iio_device_failover(struct iio_device *device)
{
    pthread_t th;
    int ret;

    ret = pthread_create(&th, NULL, iio_device_failover_thread, (void *)device);
    if (ret != 0) {
        /*
         * Thread creation failed. Do failover
         * in same thread.
         */
        iio_device_failover_thread(device);
    } else {
        pthread_detach(th);
    }
    return;
}

/*
 * Returns:
 *  1 - If message is added to the retry queue.
 *  0 - If message is not added to the retry queue
 */
static int
iio_msg_done(struct qnio_msg *msg)
{
    struct iio_device *device = (struct iio_device*)msg->reserved;
    struct channel *channel = device->channel;
    int retry = 0;
    int do_failover = 0;
    int error;

    ck_spinlock_lock(&device->slock);
    device->active_msg_count --;
    error = msg->hinfo.err;
    if (error == QNIOERROR_HUP) {
        nioDbg("QNIOERROR_HUP received on msgid=%ld %p",msg->hinfo.cookie, msg);
        switch (device->state) {
        case IIO_DEVICE_ACTIVE:
            device->state = IIO_DEVICE_QUIESCE;
            /* Continue */

        case IIO_DEVICE_QUIESCE:
        case IIO_DEVICE_FAILOVER:
            device->retry_msg_count ++;
            device->active_msg_count ++;
            channel->cd->chdrv_msg_resend_cleanup(msg);
            LIST_ADD(&device->retryq, &msg->lnode);
            retry = 1;
            break;

        case IIO_DEVICE_FAILED:
            break;

        default:
            nioDbg("Unknown device state");
            break;
        }
    } else if (error) {
        nioDbg("message failed with error %d", error);
    }

    if (device->state == IIO_DEVICE_QUIESCE &&
        device->active_msg_count == device->retry_msg_count) {
        device->state = IIO_DEVICE_FAILOVER;
        do_failover = 1;
    }
    ck_spinlock_unlock(&device->slock);

    if (do_failover) {
        iio_device_failover(device);
    }

    return retry;
}

static int32_t
iio_msg_wait(struct qnio_msg *msg)
{
    int retry;

retry:

    while (ck_pr_load_int(&msg->resp_ready) == 0) {
        usleep(SEND_RECV_SLEEP);
    }

    retry = iio_msg_done(msg);
    if (retry) {
        /*
         * If request got resubmitted due to failover
         * wait again.
         */
        goto retry;
    }
    return msg->hinfo.err;
}

static int32_t
iio_msg_submit(struct iio_device *device, struct qnio_msg *msg, uint32_t flags)
{
    int32_t err;
    int retry;
    struct channel *channel;

    nioDbg("iio_msg_submit: msg=%p, usr_ctx=%p, opcode=%d",
           msg, msg->user_ctx, (int)msg->hinfo.opcode);
    ck_spinlock_lock(&device->slock);
    if (device->state == IIO_DEVICE_FAILED) {
        ck_spinlock_unlock(&device->slock);
        msg->hinfo.err = QNIOERROR_NOCONN;
        errno = ENXIO;
        return -1;
    }
    device->active_msg_count ++;
    if (device->state == IIO_DEVICE_FAILOVER ||
        device->state == IIO_DEVICE_QUIESCE) {
        device->retry_msg_count ++;
        LIST_ADD(&device->retryq, &msg->lnode);
        ck_spinlock_unlock(&device->slock);
        return 0;
    }
    ck_spinlock_unlock(&device->slock); 
    if(flags & IIO_FLAG_ASYNC) {
        msg->hinfo.flags |= QNIO_FLAG_REQ;
    } else {
        msg->hinfo.flags |= QNIO_FLAG_SYNC_REQ;
    }
    msg->reserved = device;
    channel = device->channel;
    err = channel->cd->chdrv_msg_send(channel, msg);
    if(err != 0) {
        retry = iio_msg_done(msg);
        if (retry) {
            err = 0;
        }
    }
    return err;
}

int32_t
iio_min_version(void)
{
    return qnio_min_version;
}

int32_t
iio_max_version(void)
{
    return qnio_max_version;
}

static void
client_callback(struct qnio_msg *msg)
{
    uint32_t error;
    int retry;

    nioDbg("Got a response");
    retry = iio_msg_done(msg);
    if (retry) {
        return;
    }

    error = msg->hinfo.err;
    nioDbg("client_callback: msg=%p, usr_ctx=%p, opcode=%d",
           msg, msg->user_ctx, (int)msg->hinfo.opcode);
    apictx->io_cb(msg->user_ctx, msg->hinfo.opcode, error);
    iio_message_free(msg);
    return;
}

int
iio_init(int32_t version, iio_cb_t cb)
{
    if (version <  qnio_min_version || version > qnio_max_version) {
        nioDbg("Version [%d] not supported. Supported versions[%d - %d]",
               version, qnio_min_version, qnio_max_version);
        return -1;
    }
    if(cb == NULL) {
        nioDbg("Callback function is null\n");
        return -1;
    }
    if (apictx) {
        nioDbg("Library already initialized");
        return -1;
    }

    apictx = (struct ioapi_ctx *)malloc(sizeof (struct ioapi_ctx));
    memset(apictx, 0, sizeof (struct ioapi_ctx));
    pthread_mutex_init(&apictx->dev_lock, NULL);
    apictx->io_cb = cb;
    apictx->network_driver = qnc_driver_init(client_callback);
    nioDbg("Created API context.\n");
    return 0;
}

void
iio_fini(void)
{
    nioDbg("free API context \n");
    if (!apictx) {
        nioDbg("API context not initialized\n");
        return;
    }
    pthread_mutex_destroy(&apictx->dev_lock);
    apictx->network_driver = NULL;
    apictx->io_cb = NULL;
    free(apictx);
    apictx = NULL;
    return;
}

static void
iio_start()
{
    nioDbg("Starting IIO ...");
    slab_init(&apictx->msg_pool, MSG_POOL_SIZE, sizeof(struct qnio_msg), 0, NULL);
    apictx->devices = new_qnio_map(compare_key, NULL, NULL);
    return;
}

static void
iio_stop()
{
    nioDbg("Stopping IIO ...");
    free(apictx->devices);
    slab_free(&apictx->msg_pool);
    return;
}

void *
iio_open(const char *uri, const char *devid, uint32_t flags)
{
    struct channel *channel;
    struct iio_device *device;
    struct iio_vdisk_hostinfo *hostinfo;
    
    if(!uri || !devid) {
        errno = EINVAL;
        return NULL;
    }

    pthread_mutex_lock(&apictx->dev_lock);
    if (apictx->ndevices) {
        device = qnio_map_find(apictx->devices, devid);
        if (device !=  NULL) {
            device->refcount ++;
            pthread_mutex_unlock(&apictx->dev_lock);
            return device;
        }
    }

    hostinfo = iio_read_hostinfo(devid);
    if (hostinfo == NULL) {
        pthread_mutex_unlock(&apictx->dev_lock);
        errno = ENXIO;
        nioDbg("Unable to read the host information for device %s\n", devid);
        return NULL;
    }

    channel = iio_channel_open(uri);
    if (channel == NULL) {
        pthread_mutex_unlock(&apictx->dev_lock);
        free(hostinfo);
        errno = ENXIO;
        return NULL;
    }

    device = malloc(sizeof (struct iio_device));
    memset(device, 0, sizeof (struct iio_device));
    ck_spinlock_init(&device->slock);
    LIST_INIT(&device->retryq);
    device->refcount = 1;
    device->active_msg_count = 0;
    device->retry_msg_count = 0;
    device->channel = channel;
    device->hostinfo = hostinfo;
    safe_strncpy(device->devid, devid, NAME_SZ64);
    nioDbg("ndevices = %d\n", apictx->ndevices);
    if (apictx->ndevices == 0) {
        iio_start();
    }
    qnio_map_insert(apictx->devices, device->devid, device);
    apictx->ndevices ++;
    pthread_mutex_unlock(&apictx->dev_lock);
    return device;
}

int32_t
iio_close(void *dev_handle)
{
    struct iio_device *device = (struct iio_device *)dev_handle;
    struct channel *channel;

    pthread_mutex_lock(&apictx->dev_lock);
    device->refcount --;
    if (device->refcount) {
        pthread_mutex_unlock(&apictx->dev_lock);
        return 0;
    }

    channel = device->channel;
    channel->cd->chdrv_close(channel);
    device->channel = NULL;
    qnio_map_delete(apictx->devices, device->devid);
    apictx->ndevices --;
    if (apictx->ndevices == 0) {
        iio_stop();
    }
    free(device->hostinfo);
    free(device);
    pthread_mutex_unlock(&apictx->dev_lock);
    return 0;
}

int32_t
iio_readv(void *dev_handle, void *ctx_out, struct iovec *iov, int iovcnt,
          uint64_t offset, uint64_t size, uint32_t flags)
{
    struct iio_device *device = (struct iio_device *)dev_handle;
    struct qnio_msg *msg = NULL;
    int i, err;

    msg = iio_message_alloc(&apictx->msg_pool);
    msg->hinfo.opcode = IOR_READ_REQUEST;
    msg->hinfo.data_type = DATA_TYPE_RAW;
    msg->hinfo.io_offset = offset;
    msg->hinfo.io_size = size;
    msg->hinfo.payload_size = 0;
    msg->hinfo.io_flags |= IOR_SOURCE_TAG_APPIO;
    msg->hinfo.flags = QNIO_FLAG_REQ_NEED_RESP;
    safe_strncpy(msg->hinfo.target, device->devid, NAME_SZ64);
    msg->user_ctx = ctx_out;
    msg->send = NULL;
    msg->recv = new_io_vector(1, NULL);
    for(i = 0; i < iovcnt; i++) {
        io_vector_pushback(msg->recv, iov[i]);
    }
    if (io_vector_size(msg->recv) != size) {
        nioDbg("Mismatch of vector size and I/O size");
        iio_message_free(msg);
        errno = EIO;
        return -1;    
    }

    err = iio_msg_submit(device, msg, flags);
    if (err) {
        iio_message_free(msg);
    } else if (!(flags & IIO_FLAG_ASYNC)) {
        err = iio_msg_wait(msg);
        iio_message_free(msg);
    }
    return err;
}

int32_t
iio_writev(void *dev_handle, void *ctx_out, struct iovec *iov, int iovcnt,
           uint64_t offset, uint64_t size, uint32_t flags)
{
    struct iio_device *device = (struct iio_device *)dev_handle;
    struct qnio_msg *msg = NULL;
    int i, err;

    msg = iio_message_alloc(&apictx->msg_pool);
    msg->hinfo.opcode = IOR_WRITE_REQUEST;
    msg->hinfo.data_type = DATA_TYPE_RAW;
    msg->hinfo.io_offset = offset;
    msg->hinfo.io_size = size;
    msg->hinfo.payload_size = size;
    msg->hinfo.io_flags |= IOR_SOURCE_TAG_APPIO;
    msg->hinfo.flags = QNIO_FLAG_REQ_NEED_ACK;
    safe_strncpy(msg->hinfo.target, device->devid, NAME_SZ64);
    msg->user_ctx = ctx_out;
    msg->recv = NULL;
    msg->send = new_io_vector(1, NULL);
    for(i = 0; i < iovcnt; i++) {
        io_vector_pushback(msg->send, iov[i]);
    }
    if (io_vector_size(msg->send) != size) {
        nioDbg("Mismatch of vector size and I/O size");
        iio_message_free(msg);
        errno = EIO;
        return -1;    
    }

    err = iio_msg_submit(device, msg, flags);
    if (err) {
        iio_message_free(msg);
    } else if (!(flags & IIO_FLAG_ASYNC)) {
        err = iio_msg_wait(msg);
        iio_message_free(msg);
    }
    return err;
}

static int32_t
qnio_extract_size_from_json(char *json_str, int64_t *vdisk_size)
{
    cJSON *json_obj;
    int32_t ret = -EIO;

    nioDbg("iio_ioctl_json: %s\n", json_str);

    json_obj = cJSON_Parse(json_str);
    if (json_obj != NULL) {
        if (json_obj->type == cJSON_Object && json_obj->child != NULL) {
            if (json_obj->type != cJSON_Object) {
                nioDbg("iio_ioctl_json invalid return type for VDISK_STAT "
                          "IOCTL. json_obj->type = %d\n", json_obj->type);
            } else {
                if (strncmp(json_obj->child->string, QNIO_QEMU_VDISK_SIZE_STR,
                            sizeof (QNIO_QEMU_VDISK_SIZE_STR)) == 0) {
                    *vdisk_size = (int64_t)(json_obj->child->valueuint64);
                    ret = 0;
                } else {
                    nioDbg("iio_ioctl_json invalid response string for"
                              " VDISK_STAT IOCTL.i json_obj->type->string"
                              " = %s\n", json_obj->child->string);
                }
            }
        }
        cJSON_Delete(json_obj);
    } else {
        nioDbg("iio_ioctl_json: json_obj is NULL");
    }

    return (ret);
}

int32_t 
iio_ioctl_json(void *dev_handle, uint32_t opcode, char *injson,
               char **outjson, void *ctx_out, uint32_t flags)
{
    struct iio_device *device = (struct iio_device *)dev_handle;
    struct qnio_msg *msg = NULL;
    struct iovec data, out;
    kvset_t *inps = NULL;
    kvset_t *outps = NULL;
    qnio_stream *stream = NULL;
    int err;

    if (injson != NULL) {
        inps = parse_json(injson);
        if(inps == NULL) {
            nioDbg("Parse json failed");
            return -1;
        }
    }

    msg = iio_message_alloc(&apictx->msg_pool);
    msg->hinfo.opcode = opcode;
    msg->hinfo.data_type = DATA_TYPE_PS;
    msg->hinfo.payload_size = 0;
    data.iov_len = 0;
    if (inps != NULL) {
        msg->send = new_io_vector(1, NULL);
        data.iov_base = kvset_marshal(inps, (int *)&(data.iov_len));
        io_vector_pushback(msg->send, data);
        kvset_free(inps);
    }
    msg->recv = NULL;
    msg->hinfo.payload_size = data.iov_len;
    safe_strncpy(msg->hinfo.target, device->devid, NAME_SZ64);
    msg->user_ctx = ctx_out;
    msg->hinfo.flags = QNIO_FLAG_REQ_NEED_RESP;
    err = iio_msg_submit(device, msg, flags);
    if (err) {
        iio_message_free(msg);
    } else if(!(flags & IIO_FLAG_ASYNC)) {
        err = iio_msg_wait(msg);
        if(err == 0) {
            if (msg->recv) {
                out = io_vector_at(msg->recv, 0);
                stream = new_qnio_stream(0);
                kvset_unmarshal(out.iov_base, &outps);
                kvset_print(stream, 0, outps); 
                *outjson = (char *) malloc(stream->size + 1);
                memcpy(*outjson, stream->buffer, stream->size);
		        ((char *)*outjson)[stream->size] = '\0';
                qnio_delete_stream(stream);
                kvset_free(outps);
            }
        }
        iio_message_free(msg);
    }
    return err;
}

int32_t
iio_ioctl(void *dev_handle, uint32_t opcode, void *opaque, uint32_t flags)
{
    int64_t *vdisk_size = (int64_t *)opaque;
    int ret = 0;
    char *out = NULL;

    switch (opcode) {
    case IOR_VDISK_STAT:
        *vdisk_size = 0;
	    ret = iio_ioctl_json(dev_handle, IOR_VDISK_STAT, NULL, &out, NULL, flags);
	    if (ret == QNIOERROR_SUCCESS) {
		    ret = qnio_extract_size_from_json(out, vdisk_size);
            nioDbg("iio_ioctl returning disk size = %" PRId64 "\n", *vdisk_size);
	    }
        break;
    }

    if (ret != QNIOERROR_SUCCESS) {
	    nioDbg("Error while executing the IOCTL. Opcode = %u\n", opcode);
	    ret = -EIO;
    }

    if (out) {
    	/*
    	 * iio_ioctl_json() allocates the out for us. Done using it. Free it
    	 */
        free(out);
    }

    nioDbg("iio_ioctl opcode %u ret %d\n", opcode, ret);
    return ret;
}

/*
 * This request is sent while failover is in progress. We need to 
 * bypass the failover handling for this request. So, do not
 * use iio_msg_submit(), iio_msg_wait() calls.
 * 
 * Returns 
 *  1 -> Success
 *  0 -> Failure
 */
int
iio_check_failover_ready(struct iio_device *device)
{
    struct qnio_msg *msg = NULL;
    struct channel *channel;
    int err;

    msg = iio_message_alloc(&apictx->msg_pool);
    msg->hinfo.opcode = IRP_VDISK_CHECK_IO_FAILOVER_READY;
    msg->hinfo.data_type = DATA_TYPE_RAW;
    msg->hinfo.payload_size = 0;
    msg->recv = NULL;
    safe_strncpy(msg->hinfo.target, device->devid, NAME_SZ64);
    msg->user_ctx = NULL;
    msg->hinfo.flags = QNIO_FLAG_REQ_NEED_RESP | QNIO_FLAG_SYNC_REQ;
    msg->reserved = device;
    channel = device->channel;
    err = channel->cd->chdrv_msg_send(channel, msg);
    if (!err) {
        while (ck_pr_load_int(&msg->resp_ready) == 0) {
            usleep(SEND_RECV_SLEEP);
        }
        err = msg->hinfo.err;
    }
    iio_message_free(msg);
    if (err) {
        return 0;
    }
    return 1;
}
