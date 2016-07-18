/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <linux/unistd.h>
#include <sys/uio.h>
#include "qnio.h"
#include "datastruct.h"
#include <fcntl.h>
#include <signal.h>

/* global variables */
int verbose = 0;
int mem_only = 0;
int parallel = 0;
char *hostname = "127.0.0.1";

void *
pdispatch(void *data)
{
    int fd = 0;
    struct iovec iov,returnd;
    kvset_t *ps = NULL;
    struct qnio_msg *msg = (struct qnio_msg *) data;

    if(verbose)
        printf("In server callback for msg #%ld\n",msg->hinfo.cookie);

    if (mem_only)
        goto respond;

    fd = open(msg->hinfo.target, O_APPEND | O_NONBLOCK | O_WRONLY | O_CREAT, 0644);
    if (msg->hinfo.data_type == DATA_TYPE_PS)
    {
        qnio_stream *pstream = NULL;

        iov = io_vector_at(msg->send, 0);

        kvset_unmarshal((qnio_byte_t *)iov.iov_base, &ps);

        pstream = new_qnio_stream (0);

        kvset_print (pstream, 2, ps);

        if (pstream->size > 0)
        {
            write(fd, pstream->buffer, pstream->size);
        }

        qnio_delete_stream(pstream);
    }
    else
    {
        if (msg->send != NULL)
        {
            iov = io_vector_at(msg->send, 0);
            write(fd, iov.iov_base, iov.iov_len);
        }
        else
        {
            char recv[100] = {0};

            sprintf(recv, "Message recv for %ld\n", msg->hinfo.cookie);
            write(fd, recv, strlen(recv));
        }
    }

    close(fd);

respond:

    if (msg->hinfo.flags & QNIO_FLAG_REQ_NEED_ACK)
    {
        msg->hinfo.err = 0; /* Success */
        msg->recv = NULL;
        msg->hinfo.payload_size = 0;

        msg->hinfo.flags = QNIO_FLAG_RESP;
        msg->hinfo.io_flags = QNIO_FLAG_RESP;
        qnio_send_resp(msg);
    }
    else if (msg->hinfo.flags & QNIO_FLAG_REQ_NEED_RESP)
    {
        if (msg->hinfo.data_type == DATA_TYPE_PS)
        {
            ps = new_ps(0);
            key_value_t *kv = NULL;

            kv = new_kv ("name", 0, TYPE_STR, strlen ("katie")+1, "katie");
            kvset_add(ps, kv);

            kv = new_kv ("surname", 0, TYPE_STR, strlen ("holmes")+1, "holmes");
            kvset_add(ps, kv);

            returnd.iov_len = 0;
            returnd.iov_base = kvset_marshal(ps, (int *)&(returnd.iov_len));
            msg->hinfo.data_type = DATA_TYPE_PS;
            msg->recv = new_io_vector(1, NULL);
            io_vector_pushfront(msg->recv, returnd);
            msg->hinfo.payload_size = returnd.iov_len;
        }
        else if(msg->hinfo.data_type == DATA_TYPE_RAW)
        {
            returnd.iov_base = strdup("qnio_res");
            returnd.iov_len = 8;
            msg->hinfo.data_type = DATA_TYPE_RAW;
            msg->recv = new_io_vector(1, NULL);
            io_vector_pushfront(msg->recv, returnd);
            msg->hinfo.payload_size = returnd.iov_len;
        }
        if(msg->hinfo.flags & QNIO_FLAG_SYNC_REQ)
        {
            msg->hinfo.flags = QNIO_FLAG_SYNC_RESP;
            msg->hinfo.io_flags = QNIO_FLAG_SYNC_RESP;
        }
        else
        {
            msg->hinfo.flags = QNIO_FLAG_RESP;
            msg->hinfo.io_flags = QNIO_FLAG_RESP;
        }
        qnio_send_resp(msg);
    }
    else
    {
        qnio_free_msg(msg);
        qnio_free_io_pool_buf(msg);
    }

    return NULL;
}

void
server_callback (struct qnio_msg *msg)
{
    pthread_t thr;

    if(parallel)
    {
        pthread_create(&thr, NULL, pdispatch, msg);
    }
    else
    {
        pdispatch(msg);
    }
}

int main(int argc, char **argv)
{
    int err;
    int c;

    signal(SIGPIPE, SIG_IGN); 

    while((c = getopt(argc, argv, "h:mpv")) != -1)
    {
        switch(c)
        {
            case 'h':
                hostname = optarg;
                break;
            case 'm':
                mem_only = 1;
                break;
            case 'p':
                parallel = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                break;
        }
    }
    err = qnio_server_init(server_callback);
    if(err != 0)
    {
        printf("server init failed\n");
        exit(0);
    }
  
    printf("server initialized\n");

    err = qnio_server_start(hostname, QNIO_DEFAULT_PORT);
    if(err != 0)
    {
        printf("server start failed\n");
        exit(0);
    }
    printf("server started\n");
    while(1)
    {
        sleep(10000);
    }
    exit(0);
}

