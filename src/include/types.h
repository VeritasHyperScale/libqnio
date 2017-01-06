/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef _BASE_TYPES_
#define _BASE_TYPES_    1

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

/*
 * Every API should be defined of type QNIO_API, as an example
 * QNIO_API_ (int) my_api(char *x, char *y);
 * QNIO_API_ (void) my_void_api(void);
 */
#define QNIO_API_(type)        type
#define OF_EXT_API_(type)    type


typedef struct _qnio_guid
{
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t  Data4[8];
} qnio_guid_t;

typedef uint8_t    qnio_byte_t;


/*
 * iobuf structure
 */
typedef struct _qnio_iobuf
{
    size_t     size;
    qnio_byte_t *bs;
} qnio_iobuf_t;

/*
 * Unterminated string
 */

typedef struct _ut_string
{
    size_t size;
    char  *str;
} qnio_utstring_t;


/*
 * Error return, it is an signed value
 */
typedef int32_t     qnio_error_t;

/*
 * 32 bit mask
 */
typedef uint32_t    qnio_bitmask_t;

/*
 * Storage I/O location offset
 */
typedef uint64_t    qnio_offset_t;

/*
 * File descriptor type
 */
typedef int32_t    io_fd_t;



/*
 * boolen type
 */


/* Complex types */


typedef void (*qnio_destructor) (void *);

typedef struct _qnio_vector
{
    uint32_t      _count;
    uint32_t      max;
    qnio_destructor _dtor;
    void        **_array;
} qnio_vector_t;


/*
 * A generic handle structure is defined, it can store a pointer or a number
 * The generic handle also has a type
 */

typedef struct _generic_handle
{
    uint32_t htype;
    union var1
    {
        void    *ptr;
        uint32_t num;
    } _u;
} generic_handle;

#define INVALID_HANDLE_VALUE    0xFFFFFFFF

/*
 * Opaque handle type, it is always a cast of generic_handle
 */
typedef void   *qnio_handle_t;

/*
 * Host info struct can support both ipv4 and ipv6.
 */

typedef struct host_info
{
    uint8_t ip_type;
    union addr
    {
        uint32_t            host_ip;
        struct sockaddr_in6 host_ipv6;
    }                 h_info;
    struct host_info *host_next;
}host_info_t;

/*
 * Scatter scatter iovec
 */
struct iovec_ss
{
    char    *ios_base;   /* Pointer to memory buffer */
    size_t   ios_len;    /* length of IO */
    uint64_t ios_offset; /* Offset on disk */
    int32_t  ios_nbytes; /* return value from read/write */
};
typedef void (*rd_free_buf_t) (void *iov, void *ctx);

#define VDBLK_SIZE         512  /* 512 bytes disk block size */
#define MAGIC_SZ           16
#define NAME_SZ64          64
#define NAME_SZ            128
#define DEVNAME_SZ         256
#define DIR_NAME_SZ        256
#define FILE_NAME_SZ       128
#define PORT_SZ            8
#define OF_GUID_STR_LEN    40
#define OF_GUID_STR_SZ     (OF_GUID_STR_LEN + 1)
#define MAX_HOSTS           4

#define GUID_EQ(guid1, guid2)    (!memcmp((guid1), (guid2), sizeof (qnio_guid_t)))
#define SET_HANDLE_PTR     (x, y)(((generic_handle *)(x))->_u.ptr = (y))
#define GET_HANDLE_PTR     (x)(((generic_handle *)(x))->_u.ptr)
#define SET_HANDLE_NUM     (x, y)(((generic_handle *)(x))->_u.num = (y))

#define GET_HANDLE_INDEX(x)      (((generic_handle *)(x))->_u.index)
#define SET_HANDLE_TYPE(x, y)    (((generic_handle *)(x))->type = (y))

#define CHECK_HANDLE(h, t)       (h == INVALID_HANDLE_VALUE ? FALSE : \
                                  (((generic_handle *)(h))->type !=   \
                                   (t)) ? FALSE : TRUE)


#ifdef __cplusplus
}
#endif

#endif                          /* _BASE_TYPES_ */
