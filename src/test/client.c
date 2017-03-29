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
#include <sys/uio.h>
#include "defs.h"
#include "qnio.h"
#include "qnio_client.h"

#define BILLION                     1E9

/*
 * Please ensure the following per-device certs are installed
 * for secure SSL testing
 */
#define CLIENT_KEY                  "/var/lib/libvxhs/testdevice.key"
#define CLIENT_CERT                 "/var/lib/libvxhs/testdevice.pem"
#define CACERT                      "/var/lib/libvxhs/cacert.pem"

/* global variables */
int iops = 10;
int iosize = 8192;
int verbose = 0;
char *hostname = "127.0.0.1";
char *target = "testdevice";
struct timespec start;
void *ctx = NULL;
void *handle;
char *instance = "testinstance";
int reply = 0;
struct timespec start;
struct timespec estart;
double t,l;

void
start_timer(struct timespec *t)
{
    clock_gettime(CLOCK_MONOTONIC, t);
}

double
stop_timer(struct timespec *t)
{
    struct timespec now;
    double diff;

    clock_gettime(CLOCK_MONOTONIC, &now);
    diff = (double) ( now.tv_sec - t->tv_sec )
         + ( now.tv_nsec - t->tv_nsec )
            / BILLION;

    return diff;
}

void 
iio_cb(void *ctx,  uint32_t opcode,  uint32_t error)
{
    ck_pr_inc_int(&reply);
    if (error != 0)
    {
        printf("Error in response %d\n", error);
    }
    if (reply == iops)
    {
        t = stop_timer(&start);
        printf("Total time: %f\n", t);
        printf("Submission time: %f\n", l);
        printf("IOPS: %f\n", iops/t);
        exit(0);
    }    
    return;
}

void
usage()
{
    printf("Usage: qnio_client [-t <target host>] [-b <block size>] [-c <count>] [-d device] [-v] [-h] \n"
            "\t t -> Target (default: localhost)\n"
            "\t b -> Block size in bytes (default: 8192)\n"
            "\t c -> Number of IOs (default: 10)\n"
            "\t d -> Device (default: testdevice)\n"
            "\t h -> Help\n");
}

int main(int argc, char **argv)
{
    struct iovec data;
    char *buf = NULL;
    int c,i=1;
    int ret;

    while((c = getopt(argc, argv, "b:t:c:d:vhr")) != -1)
    {
        switch(c)
        {
            case 't':
                hostname = optarg;
                break;
            case 'c':
                iops = atoi(optarg);
                break;
            case 'b':
                iosize = atoi(optarg);
                break;
            case 'd':
                target = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'h':
            default:
                usage();
                exit(0);
        }
    }

    ret = iio_init(34, iio_cb);
    if (ret != 0)
    {
        printf("Client init failed\n");
        exit(1);
    }

    handle = iio_open("of://localhost:9999", target, 0, CACERT,
                      CLIENT_KEY, CLIENT_CERT); 
    if (handle == NULL)
    {
        printf("Device open failed\n");
        exit(1);
    }

    buf = (char *) malloc(iosize); 
    buf = memset(buf, 0, iosize);
    printf("Starting IO test\n");
    start_timer(&start);
    start_timer(&estart);
    for(i=0;i<iops;i++)
    {
        data.iov_len = iosize;
        data.iov_base = buf;
        ret = iio_writev(handle, ctx, &data, 1, iosize, iosize, IIO_FLAG_ASYNC);
        if (ret != 0)
        {
            printf("Error in IO request\n");
        }
    }
    l = stop_timer(&estart);
    while(1)
    {
        sleep(1000);
    }

    ret = iio_close(handle);

    return 0;
}

