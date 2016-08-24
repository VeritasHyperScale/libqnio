/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemuqnio.h"
#include "io_qnio.h"
#include "cJSON.h"
#include "qnio_api.h"

#define QI_DEFAULT_LANES                    8

/*
 * Size of logfile, 64MB
 */
#define QNIO_LOGFILE_SZ              67108864

/*
 * Bump up the version everytime this file is modified
 */
int qemu_qnio_version = 31;

#define QNIO_QEMU_VDISK_SIZE_STR              "vdisk_size_bytes"
#define QNIO_QEMU_VDISK_GEOM_HEADS_U32        "vdisk_geom_heads"
#define QNIO_QEMU_VDISK_GEOM_SECTORS_U32      "vdisk_geom_sectors"
#define QNIO_QEMU_VDISK_GEOM_CYLINDERS_U32    "vdisk_geom_cylinders"
#define QNIO_QEMU_VDISK_IP_ADDR_STR           "vdisk_ip"
#define QNIO_QEMU_VDISK_SRC_IP_STR            "vdisk_src_ip"

#define IP_ADDR_LEN                         20

void (qeumu_iio_cb_t) (uint32_t rfd, uint32_t reason, void *ctx,
                       iio_msg *reply);

void *
qemu_iio_init(void *cb)
{
    iio_cb_t cbz = cb;
    qnioDbg("QEMU NIO Library version %d initialized\n", qemu_qnio_version);
    return (iio_init(cbz));
}

int32_t
qemu_open_iio_conn(void *qnio_ctx, const char *uri, uint32_t flags)
{
    int ret;

    ret = iio_open(qnio_ctx, uri, flags);
    return (ret);
}

int32_t
qemu_iio_devopen(void *qnio_ctx, int32_t cfd, const char *devpath,
                 uint32_t flags)
{
    int fd = iio_devopen(qnio_ctx, cfd, devpath, flags);

    return (fd);
}

int32_t
qemu_iio_devclose(void *qnio_ctx, int32_t cfd, uint32_t rfd)
{
    return (iio_devclose(qnio_ctx, cfd, rfd));
}

uint32_t
qemu_iio_extract_msg_error(void * ptr)
{
    assert (ptr != NULL);
    struct iio_msg_t *msg = (struct iio_msg_t *)ptr;
    return(msg->iio_error);
}

size_t
qemu_iio_extract_msg_size(void * ptr)
{
    assert (ptr != NULL);
    struct iio_msg_t *msg = (struct iio_msg_t *)ptr;
    return(msg->iio_data.iio_buf.iio_nbytes);
}

void
qemu_iio_release_msg(void *ptr)
{
    struct iio_msg_t *msg = (struct iio_msg_t *)ptr;

    if(msg->type == IIOM_DTYPE_PS)
        kvset_free(msg->iio_data.iio_ps);
    else if(msg->type == IIOM_DTYPE_JSON)
        free(msg->iio_data.iio_json);
    
    free(ptr);
}

uint32_t
qemu_iio_extract_msg_opcode(void * ptr)
{
    assert (ptr != NULL);
    struct iio_msg_t *msg = (struct iio_msg_t *)ptr;
    return(msg->iio_opcode);
}

size_t qemu_calculate_iovec_size(struct iovec *iov, int niov)
{
    int i;
    size_t size = 0;

    if (!iov || niov == 0)
    {
	return size;
    }
    for (i = 0; i < niov; i++)
    {
	size += iov[i].iov_len;
    }
    return size;
}

/*
 * This helper function copies the contents of memory pointed by
 * an array of iovector into the memory buffer given.
 * NOTE: This does not check if the buffer is large enough or not
 *	Caller needs to ensure enough memory is allocated.
 */
void qemu_copy_iov_to_buffer(struct iovec *iov, int niov, void *buf)
{
    int i;
    size_t offset = 0;

    if (iov != NULL || niov == 0 || !buf)
    {
        return;
    }

    for (i = 0; i < niov; i++)
    {
        /* coverity[var_deref_op] */
        memcpy(buf+offset, iov[i].iov_base, iov[0].iov_len);
        offset += iov[i].iov_len;
    }
}

/*
 * This helper function would convert an array of iovectors into a flat
 * buffer. If copy flag is set to QEMU_DO_COPY then it will copy the contents
 * of memory pointed to by the vector into memory buffer before returning
 * NOTE: The caller is supposed to free the memory
 */
void *qemu_convert_iovector_to_buffer(struct iovec *iov, int niov,
                                            int copy, size_t sector)
{
    void *buf = NULL;
    size_t size = 0;

    if (!iov || niov == 0)
    {
	return buf;
    }

    size = qemu_calculate_iovec_size(iov, niov);
    (void)posix_memalign(&buf, sector, size);
    if (!buf)
    {
        qnioDbg("Could not allocate the buffer for size %lu. returning"
                  " error\n", size);
    	errno = -ENOMEM;
    	return NULL;
    }
    if (copy == QEMU_DO_COPY)
    {
    	qemu_copy_iov_to_buffer(iov, niov, buf);
    }

    return buf;
}

/*
 * This helper function would iterate over the iovector. For every element
 * in the iovector it will perform the following checks:
 *	1. Is the length an integral multiple of sector size
 * Return Value:
 *	On Success : return QEMU_VECTOR_ALIGNED
 *	On Failure : return QEMU_VECTOR_NOT_ALIGNED. If anyone of the condition
 *	             above fails return
 *	-1. Does not continue checking for further IO vectors
 */
int qemu_is_iovector_read_aligned(struct iovec *iov, int niov, size_t sector)
{
    int i;

    if (!iov || niov == 0)
    {
	return QEMU_VECTOR_ALIGNED;
    }
    for (i = 0; i < niov; i++)
    {
	if (iov[i].iov_len % sector != 0)
	{
	    qnioDbg("Doing iov[i].iov_base = %p, iov[i].iov_len = %lu \n",
                      iov[i].iov_base, iov[i].iov_len);
	    return QEMU_VECTOR_NOT_ALIGNED;
	}
    }
    return QEMU_VECTOR_ALIGNED;
}

int32_t
qemu_iio_writev(void *qnio_ctx, uint32_t rfd, struct iovec *iov, int iovcnt,
                uint64_t offset, void *ctx, uint32_t flags)
{
    struct iovec    cur;
    uint64_t        cur_offset = 0;
    uint64_t        cur_write_len = 0;
    int             segcount = 0;
    int             ret = 0;
    int             i, nsio = 0;

    errno = 0;
    cur.iov_base = 0;
    cur.iov_len = 0;

    /*
     * qnioDbg("qemu_iio_writev: acb= %p offset = %lu, iovcnt = %d\n",
     *           ctx, offset, iovcnt);
     */
    ret = iio_writev(qnio_ctx, rfd, iov, iovcnt, offset, ctx, flags);
    /*
     * qnioDbg("qemu_iio_writev: iio_writev returned %d\n", ret);
     */
    if (ret == -1 && errno == EFBIG)
    {
        /*
         * IO size is larger than IIO_IO_BUF_SIZE hence need to
         * split the I/O at IIO_IO_BUF_SIZE boundary
         * There are two cases here:
         *  1. iovcnt is 1 and IO size is greater than IIO_IO_BUF_SIZE
         *  2. iovcnt is greater than 1 and IO size is greater than
         *     IIO_IO_BUF_SIZE.
         *
         * Need to adjust the segment count, for that we need to compute
         * the segment count and increase the segment count in one shot
         * instead of setting iteratively in for loop. It is required to
         * prevent any race between the splitted IO submission and IO
         * completion.
         */
        cur_offset = offset;
        for (i = 0; i < iovcnt; i++)
        {
            if (iov[i].iov_len <= IIO_IO_BUF_SIZE && iov[i].iov_len > 0)
            {
                cur_offset += iov[i].iov_len;
                nsio++;
            }
            else if (iov[i].iov_len > 0)
            {
                cur.iov_base = iov[i].iov_base;
                cur.iov_len = IIO_IO_BUF_SIZE;
                cur_write_len = 0;
                while (1)
                {
                    nsio++;
                    cur_write_len += cur.iov_len;
                    if (cur_write_len == iov[i].iov_len)
                    {
                        break;
                    }
                    cur_offset += cur.iov_len;
                    cur.iov_base += cur.iov_len;
                    if ((iov[i].iov_len - cur_write_len) > IIO_IO_BUF_SIZE)
                    {
                        cur.iov_len = IIO_IO_BUF_SIZE;
                    }
                    else
                    {
                        cur.iov_len = (iov[i].iov_len - cur_write_len);
                    }
                }
            }
        }

        segcount = nsio - 1;
        vxhs_inc_acb_segment_count(ctx, segcount);
        /*
         * Split the IO and submit it to QNIO.
         * Reset the cur_offset before splitting the IO.
         */ 
        cur_offset = offset;
        nsio = 0;
        for (i = 0; i < iovcnt; i++)
        {
            /*
    	     * qnioDbg("Iteration = %d, iov_base=%p, iov_len = %lu\n",
             *           i ,iov[i].iov_base, iov[i].iov_len);
             */
            if (iov[i].iov_len <= IIO_IO_BUF_SIZE && iov[i].iov_len > 0)
            {
                errno = 0;
                /*
    		 * qnioDbg("External Frag : cur_offset = %lu and iov_len = %lu\n",
                 *           cur_offset, iov[i].iov_len);
                 */
                ret = iio_writev(qnio_ctx, rfd, &iov[i], 1, cur_offset, ctx,
                                 flags);
                if (ret == -1)
                {
    		    qnioDbg("We got an error for iteration : %d, iov_len = %lu "
                              "errno = %d\n", i, iov[i].iov_len, errno);
                    /*
                     * Need to adjust the AIOCB segment count to prevent
                     * blocking of AIOCB completion within QEMU block driver.
                     */
                    if (segcount > 0 && (segcount - nsio) > 0)
                    {
                        vxhs_dec_acb_segment_count(ctx, segcount - nsio);
                    }
                    return (ret);
                }
                else
                {
                    cur_offset += iov[i].iov_len;
                }
                nsio++;
            }
            else if (iov[i].iov_len > 0)
            {
                /*
                 * This case is where one element of the io vector is > 4MB.
                 * Two problems with the following code that breaks up elements:
                 * 1. Segment count is not updated, so app write will return early.
                 * 2. Offset is handled incorrectly - it's local, not included
                 *    in the acb for the QNIO callback to use.
                 * Short term plan is to fail the app io when this case occurs.
                 */
                cur.iov_base = iov[i].iov_base;
                cur.iov_len = IIO_IO_BUF_SIZE;
                cur_write_len = 0;
                while (1)
                {
                    nsio++;
            	    errno = 0;
                    /*
                     * qnioDbg("Internal Frag: cur_write_len = %lu, cur.iov_base=%p, "
                     *         "cur.iov_len = %lu \n",
                     *         cur_offset, cur.iov_base, cur.iov_len);
                     */
                    ret = iio_writev(qnio_ctx, rfd, &cur, 1, cur_offset, ctx,
                                     flags);
                    if (ret == -1)
                    {
                        /*
                         * qnioDbg("ERROR for iteration : %d, iov_len = %lu "
                         *           "errno = %d\n", i, cur.iov_len, errno);
                         */
                        /*
                         * Need to adjust the AIOCB segment count to prevent
                         * blocking of AIOCB completion within QEMU block driver.
                         */
                        if (segcount > 0 && (segcount - nsio) > 0)
                        {
                            vxhs_dec_acb_segment_count(ctx, segcount - nsio);
                        }
                        return (ret);
                    }
                    else
                    {
                        cur_write_len += cur.iov_len;
                        if (cur_write_len == iov[i].iov_len)
                        {
                            break;
                        }
                        cur_offset += cur.iov_len;
                        cur.iov_base += cur.iov_len;
                        if ((iov[i].iov_len - cur_write_len) > IIO_IO_BUF_SIZE)
                        {
                            cur.iov_len = IIO_IO_BUF_SIZE;
                        }
                        else
                        {
                            cur.iov_len = (iov[i].iov_len - cur_write_len);
                        }
                    }
                }
            }
        }
    }
    return (ret);
}

/*
 * At present readv is not implemented within QNIO hence
 * need to iterate over the i/o vector passed and send read
 * request to QNIO one by one.
 *
 */
int32_t
qemu_iio_readv(void *qnio_ctx, uint32_t rfd, struct iovec *iov, int iovcnt,
               uint64_t offset, void *ctx, uint32_t flags)
{
    uint64_t    read_offset = offset;
    void        *buffer = NULL;
    size_t      size;
    int         aligned, segcount;
    int         i, ret = 0;

    aligned = qemu_is_iovector_read_aligned(iov, iovcnt, QEMU_SECTOR_SIZE);
    size = qemu_calculate_iovec_size(iov, iovcnt);

    if (aligned == QEMU_VECTOR_NOT_ALIGNED)
    {
        qnioDbg("Unaligned read, ctx %p \n", ctx);
    	buffer = qemu_convert_iovector_to_buffer(iov, iovcnt, QEMU_DONOT_COPY,
                                                 QEMU_SECTOR_SIZE);
    	if (buffer == NULL)
    	{
    	    return (-ENOMEM);
    	}
    	errno = 0;
        ret = iio_read(qnio_ctx, rfd, buffer, size, read_offset, ctx, flags);
        if (ret != 0)
        {
            qnioDbg("Got an error while issuing read to QNIO. ctx %p "
                      "Error = %d, errno = %d\n", ctx, ret, errno);
            free(buffer);
            return (ret);
        }
        vxhs_set_acb_buffer(ctx, buffer);
        return (ret);
    }

    /*
     * Since read IO request is going to split based on
     * number of IOvectors hence increment the segment
     * count depending on the number of IOVectors before
     * submitting the read request to QNIO.
     * This is needed to protect the QEMU block driver
     * IO completion while read request for the same IO
     * is being submitted to QNIO.
     */
    segcount = iovcnt - 1;
    if (segcount > 0)
    {
        vxhs_inc_acb_segment_count(ctx, segcount);
    }

    for (i = 0; i < iovcnt; i++)
    {
        errno = 0;
        ret = iio_read(qnio_ctx, rfd, iov[i].iov_base, iov[i].iov_len,
                       read_offset, ctx, flags);
        if (ret != 0)
        {
            qnioDbg("Got an error while issuing read to QNIO. ctx %p "
                      "Error = %d errno = %d\n", ctx, ret, errno);
            /*
             * Need to adjust the AIOCB segment count to prevent
             * blocking of AIOCB completion within QEMU block driver.
             */
            if (segcount > 0 && (segcount - i) > 0)
            {
                vxhs_dec_acb_segment_count(ctx, segcount - i);
            }
            return (ret);
        }
        read_offset += iov[i].iov_len;
    }

    return (ret);
}

int32_t
qemu_iio_read(void *qnio_ctx, uint32_t rfd, unsigned char *buf, uint64_t size,
              uint64_t offset, void *ctx, uint32_t flags)
{
    return (iio_read(qnio_ctx, rfd, buf, size, offset, ctx, flags));
}

int32_t
qemu_extract_size_from_json(char *out, void *in)
{
    cJSON *json_obj;

    json_obj = cJSON_Parse(out);
    int32_t       ret;
    unsigned long size = 0;
    if (json_obj != NULL)
    {
        if (json_obj->type == cJSON_Object && json_obj->child != NULL)
        {
            if (json_obj->type != cJSON_Object)
            {
                qnioDbg("iio_ioctl_json invalid return type for VDISK_STAT "
                          "IOCTL. json_obj->type = %d\n", json_obj->type);
                ret = -EIO;
            }
            else
            {
                if (strncmp(json_obj->child->string, QNIO_QEMU_VDISK_SIZE_STR,
                            sizeof (QNIO_QEMU_VDISK_SIZE_STR)) == 0)
                {
                    size = (unsigned long)(json_obj->child->valueuint64);
                    *(unsigned long *)in = size;
                }
                else
                {
                    qnioDbg("iio_ioctl_json invalid response string for"
                              " VDISK_STAT IOCTL.i json_obj->type->string"
                              " = %s\n", json_obj->child->string);
                    ret = -EIO;
                }
            }
        }
    }
    cJSON_Delete(json_obj);
    return (ret);
}

int32_t
qemu_extract_geometry_from_json(char *out, void *in)
{
    cJSON       *json_obj;
    unsigned int size;
    int32_t      ret;

    json_obj = cJSON_Parse(out);
    if (json_obj != NULL)
    {
        if (json_obj->type == cJSON_Object && json_obj->child != NULL)
        {
            if (json_obj->type != cJSON_Object)
            {
                qnioDbg("iio_ioctl_json invalid return type for VDISK_GET_GEOMETRY"
                          "IOCTL. json_obj->type = %d\n",
                          json_obj->type);
                ret = -EIO;
            }
            else
            {
                if (strncmp(json_obj->child->string,
                            QNIO_QEMU_VDISK_GEOM_HEADS_U32,
                            sizeof (QNIO_QEMU_VDISK_GEOM_HEADS_U32)) == 0)
                {
                    size = (unsigned int)(json_obj->child->valueuint64);
                    qnioDbg("iio_ioctl_json size from iio_ioctl = %u\n",
                              size);
                    *(unsigned int *)in = size;
                }
                else
                {
                    qnioDbg("iio_ioctl_json invalid response string for"
                              " VDISK_GET_GEOMETRY IOCTL."
                              " json_obj->type->string = %s\n",
                              json_obj->child->string);
                    ret = -EIO;
                }
            }
        }
    }
    cJSON_Delete(json_obj);
    return (ret);
}

int32_t
qemu_extract_flush_response(char *out, void *in)
{
    cJSON  *json_obj;
    int32_t ret = 0;

    json_obj = cJSON_Parse(out);
    if (json_obj != NULL)
    {
        /*
         * At present we do not get any response from VSA when FLUSH is issued.
         * We will return success everytime.
         */
        ret = 0;
    }
    cJSON_Delete(json_obj);
    return (ret);
}

int32_t
qemu_iio_ioctl(void *apictx, uint32_t rfd, uint32_t opcode, void *in,
               void *ctx, uint32_t flags)
{
    int   ret = 0;
    char *out = NULL;

    switch (opcode)
    {
        case VDISK_STAT:
            *(unsigned long *)in = 0;
            ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_STAT, NULL, &out,
                                 NULL, 0);
            if (ret != QNIOERROR_SUCCESS)
            {
                qnioDbg("Error while executing the IOCTL. Opcode = %u\n",
                          opcode);
                ret = -EIO;
            }
            else
            {
                ret = qemu_extract_size_from_json(out, in);
            }
            break;
        case VDISK_GET_GEOMETRY:
            *(unsigned long *)in = 0;
            ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_GET_GEOMETRY, NULL,
                                 &out, NULL, 0);
            if (ret != QNIOERROR_SUCCESS)
            {
                qnioDbg("Error while executing the IOCTL. Opcode = %u\n",
                          opcode);
                ret = -EIO;
            }
            else
            {
                ret = qemu_extract_geometry_from_json(out, in);
            }
            break;
        case VDISK_AIO_FLUSH:
            *(unsigned long *)in = 0;
            ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_FLUSH, NULL, &out, ctx,
                                 flags);
            if (ret != QNIOERROR_SUCCESS)
            {
                qnioDbg("Error while executing the IOCTL. Opcode = %u\n",
                          opcode);
                ret = -EIO;
            }
            break;

        case VDISK_CHECK_IO_FAILOVER_READY:
            ret = iio_ioctl_json(apictx, rfd, IOR_VDISK_CHECK_IO_FAILOVER_READY,
                         NULL, &out, ctx, flags);
            if (flags & IIO_FLAG_ASYNC)
            {
               qnioDbg("qemu_iio_ioctl: submitted VDISK_CHECK_IO_FAILOVER_READY "
                         "for asynchronous processing (%d)\n", ret);
            }
            else
            {
                qnioDbg("qemu_iio_ioctl: VDISK_CHECK_IO_FAILOVER_READY "
                          "synchronously returning %d\n", ret);
            }
            break;

        default:
            ret = -ENOTSUP;
            qnioDbg("Invalid opcode used to call ioctl = %u\n", opcode);
            break;
    }
    if (out)
    {
    	/*
    	 * qemu_iio_ioctl() allocates the out for us. Done using it. Free it
    	 */
	free(out);
    }
    return (ret);
}

int32_t
qemu_iio_close(void *qnio_ctx, uint32_t cfd)
{
    return (iio_close(qnio_ctx, cfd));
}

void *
qemu_ck_initialize_lock(void)
{
    ck_spinlock_fas_t *lock;

    lock = (ck_spinlock_fas_t *) malloc (sizeof(ck_spinlock_fas_t)); 
    ck_spinlock_init(lock);
    return (void *) lock; 
}

void
qemu_ck_spin_lock(void *ptr)
{
    ck_spinlock_fas_t *lock = (ck_spinlock_fas_t *)ptr;

    ck_spinlock_lock (lock);
}

void
qemu_ck_spin_unlock(void *ptr)
{
    ck_spinlock_fas_t *lock = (ck_spinlock_fas_t *)ptr;

    ck_spinlock_unlock (lock);
}

void
qemu_ck_destroy_lock(void *ptr)
{
    ck_spinlock_fas_t *lock = (ck_spinlock_fas_t *)ptr;

    free(lock);
}
