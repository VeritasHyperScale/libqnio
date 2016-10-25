/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "io_qnio.h"
#include "defs.h"
#include "cJSON.h"
#include <inttypes.h>

/*
 * Size of logfile, 64MB
 */
#define QNIO_LOGFILE_SZ              67108864

/*
 * Bump up the version everytime this file is modified
 */
int qnio_version = 32;

#define QNIO_QEMU_VDISK_SIZE_STR              "vdisk_size_bytes"
#define QNIO_QEMU_VDISK_GEOM_HEADS_U32        "vdisk_geom_heads"
#define QNIO_QEMU_VDISK_GEOM_SECTORS_U32      "vdisk_geom_sectors"
#define QNIO_QEMU_VDISK_GEOM_CYLINDERS_U32    "vdisk_geom_cylinders"
#define QNIO_QEMU_VDISK_IP_ADDR_STR           "vdisk_ip"
#define QNIO_QEMU_VDISK_SRC_IP_STR            "vdisk_src_ip"

#define IP_ADDR_LEN                         20

void
client_callback(struct qnio_msg *msg)
{
    struct ioapi_ctx *apictx = (struct ioapi_ctx *) msg->reserved;
    uint32_t error;
    uint32_t reason = IIO_REASON_DONE;

    nioDbg("Got a response");
    error = msg->hinfo.err;

    if (error == QNIOERROR_CHANNEL_HUP) {
        reason = IIO_REASON_HUP;
    } else if (error != QNIOERROR_SUCCESS) {
        reason = IIO_REASON_EVENT;
    }

    apictx->io_cb(msg->rfd, reason, msg->user_ctx, error, msg->hinfo.opcode);
    if(msg->send) {
        io_vector_delete(msg->send);
    }
    if(msg->recv) {
        io_vector_delete(msg->recv);
    }

    qnio_free_io_pool_buf(msg);
    qnio_free_msg(msg);
    return;
}

void *
iio_init(iio_cb_t cb)
{
    struct ioapi_ctx *apictx = NULL;

    if(cb == NULL) {
        nioDbg("callback is null");
        return NULL;
    }

    apictx = (struct ioapi_ctx *)malloc(sizeof (struct ioapi_ctx));
    if (NULL == apictx) {
        nioDbg ("Failed to allocate ioapi_ctx");
        return NULL;
    }

    safe_map_init(&apictx->channels);
    safe_map_init(&apictx->devices);
    apictx->next_fd = 1;
    apictx->io_cb = cb;
    apictx->qnioctx = qnio_client_init(client_callback);
    apictx->qnioctx->apictx = apictx;
    return apictx;
}

int32_t 
iio_open(void *ctx, const char *uri, uint32_t flags)
{
    struct ioapi_ctx *apictx = ctx;
    char host[NAME_SZ] = {0};
    char port[NAME_SZ] = {0};
    int32_t cfd = -1;
    int match = 0;
    int err;
    
    if(!uri) {
        return -1;
    }

    match = sscanf(uri, "of://%99[^:]:%99s", host, port);
    if(match != 2) {
        nioDbg("parse uri failed %d [%s] [%s]", match, host, port);
        return -1;
    }

    nioDbg("iio_open: uri=%s, host=%s, port=%s\n", uri, host, port);
    err = qnio_create_channel(apictx->qnioctx, host, port);
    if (err == QNIO_ERR_SUCCESS) { 
        cfd = ck_pr_faa_int(&(apictx->next_fd), 1);
        safe_map_insert(&apictx->channels, cfd, strdup(host));
        nioDbg("New channel is ready %d", cfd);
    } else if (err == QNIO_ERR_CHAN_EXISTS) {
        cfd = ck_pr_faa_int(&(apictx->next_fd), 1);
        safe_map_insert(&apictx->channels, cfd, strdup(host));
        nioDbg("Existing channel is ready %d", cfd);
    }
    return cfd;
}

int32_t 
iio_devopen(void *ctx, int32_t cfd, const char *devpath, uint32_t flags)
{
    struct ioapi_ctx *apictx = ctx;
    char *channel;
    char chandev[NAME_SZ] = {0};
    int devfd;
    
    if(cfd < 0) {
        errno = EBADF;
        return -1;
    }
    if(!devpath) {
        return -1;
    }
    
    channel = (char *) safe_map_find(&apictx->channels, cfd);
    if(!channel) {
        errno = ENODEV;
        return -1;
    }

    devfd = ck_pr_faa_int(&(apictx->next_fd), 1);
    sprintf(chandev, "%s %s", channel, devpath);
    safe_map_insert(&apictx->devices, devfd, strdup(chandev));
    return devfd;
}

int32_t
iio_devclose(void *ctx, int32_t cfd, int32_t rfd)
{
    struct ioapi_ctx *apictx = ctx;
    char *chandev = NULL;

    chandev = (char *) safe_map_find(&apictx->devices, rfd);
    if(!chandev) {
        nioDbg("Could not find device for fd");
        errno = ENODEV;
        return -1;
    }
    safe_map_delete(&apictx->devices, rfd);
    return 0;
}

int32_t
iio_close(void *ctx, uint32_t cfd)
{
    struct ioapi_ctx *apictx = ctx;
    char *host = NULL;

    host = (char *) safe_map_find(&apictx->channels, cfd);
    if(!host) {
        nioDbg("Could not find channel for fd");
        errno = EBADF;
        return -1;
    }
    safe_map_delete(&apictx->channels, cfd);
    return 0;
}

int32_t
iio_readv(void *ctx, int32_t rfd, struct iovec *iov, int iovcnt,
          uint64_t offset, uint64_t size, void *ctx_out, uint32_t flags)
{
    struct ioapi_ctx *apictx = ctx;
    char *chandev = NULL;
    struct qnio_msg *msg = NULL;
    char channel[NAME_SZ] = {0};
    char device[NAME_SZ] = {0};
    int i, err;

    chandev = (char *) safe_map_find(&apictx->devices, rfd);
    if(!chandev) {
        nioDbg("Could not find device for fd");
        errno = ENODEV;
        return -1;
    }

    sscanf(chandev,"%s %s", channel, device);
    msg = qnio_alloc_msg(apictx->qnioctx); 
    msg->reserved = apictx;
    msg->rfd = rfd;
    msg->hinfo.opcode = IOR_READ_REQUEST;
    msg->hinfo.data_type = DATA_TYPE_RAW;
    msg->hinfo.io_offset = offset;
    msg->hinfo.io_size = size;
    msg->hinfo.payload_size = 0;
    msg->hinfo.io_flags |= IOR_SOURCE_TAG_APPIO;
    strncpy(msg->hinfo.target, device, strlen(device));
    msg->channel = channel;
    msg->user_ctx = ctx_out;
    msg->send = NULL;
    msg->recv = new_io_vector(1, NULL);
    for(i = 0; i < iovcnt; i++) {
        io_vector_pushback(msg->recv, iov[i]);
    }
    if (io_vector_size(msg->recv) != size) {
        nioDbg("Mismatch of vector size and I/O size");
        qnio_free_msg(msg);
        errno = EIO;
        return -1;    
    }
   
    if(flags & IIO_FLAG_ASYNC) {
        msg->hinfo.flags = QNIO_FLAG_REQ | QNIO_FLAG_REQ_NEED_RESP;
        err = qnio_send(apictx->qnioctx, msg);
        if(err != 0) {
            qnio_free_msg(msg);
        }
    } else {
        err = qnio_send_recv(apictx->qnioctx, msg);
        qnio_free_msg(msg);
    }
    return err;
}

int32_t
iio_writev(void *ctx, int32_t rfd, struct iovec *iov, int iovcnt,
           uint64_t offset, uint64_t size, void *ctx_out, uint32_t flags)
{
    struct ioapi_ctx *apictx = ctx;
    char *chandev = NULL;
    struct qnio_msg *msg = NULL;
    char channel[NAME_SZ] = {0};
    char device[NAME_SZ] = {0};
    int i, err;

    chandev = (char *) safe_map_find(&apictx->devices, rfd);
    if(!chandev) {
        nioDbg("Could not find device for fd");
        errno = ENODEV;
        return -1;
    }

    sscanf(chandev,"%s %s", channel, device);
    msg = qnio_alloc_msg(apictx->qnioctx); 
    msg->reserved = apictx;

    msg->rfd = rfd;
    msg->hinfo.opcode = IOR_WRITE_REQUEST;
    msg->hinfo.data_type = DATA_TYPE_RAW;
    msg->hinfo.io_offset = offset;
    msg->hinfo.io_size = size;
    msg->hinfo.payload_size = size;
    msg->hinfo.io_flags |= IOR_SOURCE_TAG_APPIO;
    strncpy(msg->hinfo.target, device, strlen(device));
    msg->channel = channel;
    msg->user_ctx = ctx_out;
    msg->recv = NULL;
    msg->send = new_io_vector(1, NULL);
    for(i = 0; i < iovcnt; i++) {
        io_vector_pushback(msg->send, iov[i]);
    }
    if (io_vector_size(msg->send) != size) {
        nioDbg("Mismatch of vector size and I/O size");
        qnio_free_msg(msg);
        errno = EIO;
        return -1;    
    }
    
    if(flags & IIO_FLAG_ASYNC) {
        msg->hinfo.flags = QNIO_FLAG_REQ;
        if(flags & IIO_FLAG_DONE) {
            msg->hinfo.flags |= QNIO_FLAG_REQ_NEED_ACK;
        }
        err = qnio_send(apictx->qnioctx, msg);
        if(err != 0) {
            qnio_free_msg(msg);
        }
    } else {
        err = qnio_send_recv(apictx->qnioctx, msg);
        qnio_free_msg(msg);
    }
    return err;
}

int32_t
qnio_extract_size_from_json(char *json_str, int64_t *vdisk_size)
{
    cJSON *json_obj;
    int32_t ret = -EIO;

    qnioDbg("iio_ioctl_json: %s\n", json_str);

    json_obj = cJSON_Parse(json_str);
    if (json_obj != NULL) {
        if (json_obj->type == cJSON_Object && json_obj->child != NULL) {
            if (json_obj->type != cJSON_Object) {
                qnioDbg("iio_ioctl_json invalid return type for VDISK_STAT "
                          "IOCTL. json_obj->type = %d\n", json_obj->type);
            } else {
                if (strncmp(json_obj->child->string, QNIO_QEMU_VDISK_SIZE_STR,
                            sizeof (QNIO_QEMU_VDISK_SIZE_STR)) == 0) {
                    *vdisk_size = (int64_t)(json_obj->child->valueuint64);
                    ret = 0;
                } else {
                    qnioDbg("iio_ioctl_json invalid response string for"
                              " VDISK_STAT IOCTL.i json_obj->type->string"
                              " = %s\n", json_obj->child->string);
                }
            }
        }
        cJSON_Delete(json_obj);
    } else {
        qnioDbg("iio_ioctl_json: json_obj is NULL");
    }

    return (ret);
}

int32_t
iio_ioctl(void *ctx, int32_t rfd, uint32_t opcode, int64_t *vdisk_size,
          void *ctx_out, uint32_t flags)
{
    struct ioapi_ctx *apictx = ctx;
    int ret = 0;
    char *out = NULL;

    switch (opcode) {
    case IOR_VDISK_STAT:
        *vdisk_size = 0;
	    ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_STAT, NULL, &out, NULL, flags);
	    if (ret == QNIOERROR_SUCCESS) {
		    ret = qnio_extract_size_from_json(out, vdisk_size);
            qnioDbg("iio_ioctl returning disk size = %" PRId64 "\n", *vdisk_size);
	    }
        break;

    case IOR_VDISK_FLUSH:
        *vdisk_size = 0;
        ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_FLUSH, NULL, &out, NULL, flags);
        break;

    case IOR_VDISK_CHECK_IO_FAILOVER_READY:
        ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_CHECK_IO_FAILOVER_READY,
                             NULL, &out, ctx_out, flags);
        break;
    }

    if (ret != QNIOERROR_SUCCESS) {
	    qnioDbg("Error while executing the IOCTL. Opcode = %u\n", opcode);
	    ret = -EIO;
    }

    if (out) {
    	/*
    	 * iio_ioctl_json() allocates the out for us. Done using it. Free it
    	 */
        free(out);
    }

    qnioDbg("iio_ioctl opcode %u ret %d\n", opcode, ret);
    return ret;
}

int32_t 
iio_ioctl_json(void *ctx, int32_t rfd, uint32_t opcode, char *injson,
               char **outjson, void *ctx_out, uint32_t flags)
{
    struct ioapi_ctx *apictx = ctx;
    char *chandev = NULL;
    struct qnio_msg *msg = NULL;
    char channel[NAME_SZ] = {0};
    char device[NAME_SZ] = {0};
    struct iovec data, out;
    int err;
    kvset_t *inps = NULL;
    kvset_t *outps = NULL;
    qnio_stream *stream = NULL;

    chandev = (char *) safe_map_find(&apictx->devices, rfd);
    if(!chandev) {
        nioDbg("Could not find device for fd");
        errno = ENODEV;
        return -1;
    }

    sscanf(chandev,"%s %s", channel, device);
    if (injson != NULL) {
        inps = parse_json(injson);
        if(inps == NULL) {
            nioDbg("Parse json failed");
            return -1;
        }
    }

    msg = qnio_alloc_msg(apictx->qnioctx); 
    msg->reserved = apictx;
    msg->rfd = rfd;
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
    strncpy(msg->hinfo.target,device,strlen(device));
    msg->channel = channel;
    msg->user_ctx = ctx_out;
 
    if(flags & IIO_FLAG_ASYNC) {
        msg->hinfo.flags = QNIO_FLAG_REQ;
        if(flags & IIO_FLAG_DONE) {
            msg->hinfo.flags |= QNIO_FLAG_REQ_NEED_RESP;
        }
        err = qnio_send(apictx->qnioctx, msg);
        if(err != 0) {
            qnio_free_io_pool_buf(msg);
            qnio_free_msg(msg);
        }
        return err;
    } else {
        err = qnio_send_recv(apictx->qnioctx, msg);
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
                io_vector_delete(msg->recv);
            }
        }
        qnio_free_io_pool_buf(msg);
        if (msg->send) {
            io_vector_delete(msg->send);
        }
        qnio_free_msg(msg);
        return err;
    }
}
