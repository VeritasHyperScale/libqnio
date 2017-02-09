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
#include <libgen.h>
#include "defs.h"
#include "qnio.h"
#include "utils.h"
#include "qnio_server.h"

#define VDISK_SIZE_BYTES    "vdisk_size_bytes"

int verbose = 0;
int parallel = 0;
char *hostname = "127.0.0.1";
char *vdisk_dir = "/tmp";
FILE *backing_file;

static int vdisk_read(struct qnio_msg *msg, struct iovec *returnd)
{
    size_t n;
    uint64_t offset;
    uint64_t size;
    char vdisk_path_temp[DIR_NAME_SZ] = {0};
    char vdisk_path[DIR_NAME_SZ] = {0};
    char *bname;

    offset = msg->hinfo.io_offset;
    size = msg->hinfo.io_size;
    safe_strncpy(vdisk_path_temp, msg->hinfo.target, DIR_NAME_SZ);
    bname = basename(vdisk_path_temp);
    sprintf(vdisk_path, "%s/%s", vdisk_dir, bname);
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
    char vdisk_path_temp[DIR_NAME_SZ] = {0};
    char vdisk_path[DIR_NAME_SZ] = {0};
    char *bname;

    offset = msg->hinfo.io_offset;
    iov = io_vector_at(msg->send, 0);

    safe_strncpy(vdisk_path_temp, msg->hinfo.target, DIR_NAME_SZ);
    bname = basename(vdisk_path_temp);
    sprintf(vdisk_path, "%s/%s", vdisk_dir, bname);
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
    uint64_t disk_size = 0;
    char vdisk_path_temp[DIR_NAME_SZ] = {0};
    char vdisk_path[DIR_NAME_SZ] = {0};
    char *bname;
    struct stat stat;
    int fd;

    if (verbose) {
        printf("In server callback for msg #%ld\n", msg->hinfo.cookie);
    }

    switch (opcode) {
    case IOR_VDISK_STAT:
        ps = new_ps(0);
        safe_strncpy(vdisk_path_temp, msg->hinfo.target, DIR_NAME_SZ);
        bname = basename(vdisk_path_temp);
        sprintf(vdisk_path, "%s/%s", vdisk_dir, bname);
        fd = open(vdisk_path, O_RDONLY);
        if (fd >= 0) {
            if (fstat(fd, &stat)== 0) {
                disk_size = stat.st_size;
            } else {
                perror("fstat");
                disk_size = 0;
            }
            close(fd);
        } else {
            perror("open");
            disk_size = 0;
        }
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

    case IRP_VDISK_CHECK_IO_FAILOVER_READY:
        msg->hinfo.err = 0;
        msg->recv = NULL;
        msg->hinfo.payload_size = 0;
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
    qns_send_resp(msg);
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

void
usage()
{
    printf("Usage: qnio_server [-d <directory>] [-l <logfile>] [-p] [-v] [-h] \n"
            "\t d -> Directory where the backing file for volume is created\n"
            "\t l -> Log file\n"
            "\t p -> Parallelize IO dispatch\n"
            "\t h -> Help\n"
            "\t v -> Verbose\n");
}

static void termsig_handler(int signum)
{
    exit(0);
}

int main(int argc, char **argv)
{
    struct sigaction sa_sigterm;
    char *logfile = "/dev/null";
    int c;

    /*
     * Handle SIGTERM signal gracefully.
     */
    memset(&sa_sigterm, 0, sizeof(sa_sigterm));
    sa_sigterm.sa_handler = termsig_handler;
    sigaction(SIGTERM, &sa_sigterm, NULL);

    /*
     * Ignore SIGPIPE
     */ 
    signal(SIGPIPE, SIG_IGN); 

    while ((c = getopt(argc, argv, "d:l:hHpv")) != -1) {
        switch (c) {
        case 'd':
            vdisk_dir = optarg;
            break;
        case 'l':
            logfile = optarg;
            break;
        case 'p':
            parallel = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        case 'H':
        case 'h':
            usage();
            exit(0);
        default:
            break;
        }
    }
    /*
     * Redirect stdin to /dev/null
     */
    if (!freopen("/dev/null", "r", stdin)) {
        fprintf(stderr, "stdin redirection failed\n");
        exit(-1);
    }

    /*
     * Redirect stdout, stderr to
     * specified log device.
     */
    if (!freopen(logfile, "a+", stdout)) {
        fprintf(stderr, "stdout redirection failed for %s\n", logfile);
        exit(-1);
    }

    if(dup2(fileno(stdout), fileno(stderr)) < 0) {
        fprintf(stderr, "dup2 failed for stdout\n");
        exit(-1);
    }

    if (qns_server_init(server_callback) != 0) {
        fprintf(stderr, "Server init failed\n");
        exit(-1);
    }
    printf("Server initialized\n");
    
    if(qns_server_start(hostname, QNIO_DEFAULT_PORT) != 0) {
        fprintf(stderr, "Server start failed\n");
        exit(-1);
    }
    printf("Server started\n");
    while (1) {
        sleep(10000);
    }
    exit(0);
}
