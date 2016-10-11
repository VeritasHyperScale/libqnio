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
#include <libgen.h>
#include <linux/unistd.h>
#include <sys/uio.h>
#include "qnio.h"
#include "datastruct.h"
#include <fcntl.h>
#include <signal.h>
#include "qnio_api.h"

#define VDISK_SIZE_BYTES    "vdisk_size_bytes"
#define FAKE_DISK_SIZE      4194304

int verbose = 0;
int mem_only = 0;
int parallel = 0;
char *hostname = "127.0.0.1";
FILE *backing_file;

static int vdisk_read(struct qnio_msg *msg, struct iovec *returnd)
{
    size_t n;
    uint64_t offset;
    uint64_t size;
    char vdisk_path[NAME_SZ64];
    char *bname;

    offset = msg->hinfo.io_offset;
    size = msg->hinfo.io_size;
    strcpy(vdisk_path, msg->hinfo.target);
    bname = basename(vdisk_path);
    sprintf(vdisk_path, "/tmp/%s", bname);
    backing_file = fopen(vdisk_path, "r");
    if (!backing_file) {
        printf("Error opening file %s\n", vdisk_path);
        perror("fopen");
        return -1;
    }

    if (offset) {
        fseek(backing_file, offset, SEEK_SET);
    }
    returnd->iov_base = malloc(size);
    n = fread(returnd->iov_base, 1, size, backing_file);
    fclose(backing_file);

    if (verbose) {
        printf("read %ld bytes\n", n);
    }

    returnd->iov_len = n;
    msg->hinfo.data_type = DATA_TYPE_RAW;
    msg->recv = new_io_vector(1, NULL);
    io_vector_pushfront(msg->recv, *returnd);
    msg->hinfo.payload_size = returnd->iov_len;

    return 0;
}

static int vdisk_write(struct qnio_msg *msg)
{
    size_t n;
    uint64_t offset;
    struct iovec iov;
    char vdisk_path[NAME_SZ64];
    char *bname;

    offset = msg->hinfo.io_offset;
    iov = io_vector_at(msg->send, 0);

    strcpy(vdisk_path, msg->hinfo.target);
    bname = basename(vdisk_path);
    sprintf(vdisk_path, "/tmp/%s", bname);
    backing_file = fopen(vdisk_path, "r+");
    if (!backing_file) {
        printf("Error opening file %s\n", vdisk_path);
        perror("fopen");
        return -1;
    }

    if (offset) {
        fseek(backing_file, offset, SEEK_SET);
    }
    n = fwrite(iov.iov_base, 1, iov.iov_len, backing_file);
    fclose(backing_file);

    if (verbose) {
        printf("wrote %ld bytes\n", n);
    }

    msg->hinfo.err = 0;
    msg->recv = NULL;
    msg->hinfo.payload_size = 0;

    msg->hinfo.flags = QNIO_FLAG_RESP;
    msg->hinfo.io_flags = QNIO_FLAG_RESP;

    return 0;
}


void *pdispatch(void *data)
{
    struct iovec returnd;
    kvset_t *ps = NULL;
    key_value_t *kv = NULL;
    struct qnio_msg *msg = data;
    uint16_t opcode = msg->hinfo.opcode;
    uint64_t disk_size = FAKE_DISK_SIZE;

    if (verbose) {
        printf("In server callback for msg #%ld\n", msg->hinfo.cookie);
    }

    ps = new_ps(0);
    switch (opcode) {
    case IOR_VDISK_STAT:
        kv = new_kv(VDISK_SIZE_BYTES, 0, TYPE_UINT64,
                    sizeof (uint64_t), &disk_size);
        kvset_add(ps, kv);

        returnd.iov_len = 0;
        returnd.iov_base = kvset_marshal(ps, (int *)&(returnd.iov_len));
        msg->hinfo.data_type = DATA_TYPE_PS;
        msg->recv = new_io_vector(1, NULL);
        io_vector_pushfront(msg->recv, returnd);
        msg->hinfo.payload_size = returnd.iov_len;
        break;

    case IRP_READ_REQUEST:
        if (vdisk_read(msg, &returnd)) {
            exit(1);
        }
        break;

    case IRP_WRITE_REQUEST:
        if (vdisk_write(msg)) {
            exit(1);
        }

    default:
        break;
    }

    if (msg->hinfo.flags & QNIO_FLAG_SYNC_REQ) {
        msg->hinfo.flags = QNIO_FLAG_SYNC_RESP;
        msg->hinfo.io_flags = QNIO_FLAG_SYNC_RESP;
    }
    else {
        msg->hinfo.flags = QNIO_FLAG_RESP;
        msg->hinfo.io_flags = QNIO_FLAG_RESP;
    }
    qnio_send_resp(msg);
    qnio_free_msg(msg);
    return NULL;
}

void server_callback(struct qnio_msg *msg)
{
    pthread_t thr;

    if (parallel) {
        pthread_create(&thr, NULL, pdispatch, msg);
    } else {
        pdispatch(msg);
    }
}

int main(int argc, char **argv)
{
    int err;
    int c;

    signal(SIGPIPE, SIG_IGN); 

    while ((c = getopt(argc, argv, "h:mpv")) != -1) {
        switch (c) {
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
    if (err != 0) {
        printf("server init failed\n");
        exit(0);
    }
  
    printf("server initialized\n");

    err = qnio_server_start(hostname, QNIO_DEFAULT_PORT);
    if (err != 0) {
        printf("server start failed\n");
        exit(0);
    }
    printf("server started\n");
    while (1) {
        sleep(10000);
    }
    exit(0);
}

