/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef _BASE_PACK_H_
#define _BASE_PACK_H_
#include <stddef.h>
#include "types.h"
#ifdef __cplusplus
extern "C"
{
#endif

#define QNIO_INT8_SZ      (1)
#define QNIO_UINT8_SZ     (1)
#define QNIO_INT16_SZ     (2)
#define QNIO_UINT16_SZ    (2)
#define QNIO_INT32_SZ     (4)
#define QNIO_UINT32_SZ    (4)
#define QNIO_INT64_SZ     (8)
#define QNIO_UINT64_SZ    (8)

#define QNIO_INT8_PACK_SZ(x)        (1)
#define QNIO_INT8_UNPACK_SZ(x)      (1)
#define QNIO_UINT8_PACK_SZ(x)       (1)
#define QNIO_UINT8_UNPACK_SZ(x)     (1)
#define QNIO_INT16_PACK_SZ(x)       (2)
#define QNIO_INT16_UNPACK_SZ(x)     (2)
#define QNIO_UINT16_PACK_SZ(x)      (2)
#define QNIO_UINT16_UNPACK_SZ(x)    (2)
#define QNIO_INT32_PACK_SZ(x)       (4)
#define QNIO_INT32_UNPACK_SZ(x)     (4)
#define QNIO_UINT32_PACK_SZ(x)      (4)
#define QNIO_UINT32_UNPACK_SZ(x)    (4)
#define QNIO_INT64_PACK_SZ(x)       (8)
#define QNIO_INT64_UNPACK_SZ(x)     (8)
#define QNIO_UINT64_PACK_SZ(x)      (8)
#define QNIO_UINT64_UNPACK_SZ(x)    (8)

#define QNIO_INT8_PACK(x, p)                               \
    (((qnio_byte_t *)(p))[0] = (x) & 0xff,             \
     (p) += QNIO_INT8_SZ)

#define QNIO_INT8_UNPACK(x, p)                             \
    ((x) = ((qnio_byte_t)((qnio_byte_t *)(p))[0])),        \
    (p) += QNIO_INT8_SZ)

#define QNIO_UINT8_PACK(x, p)                              \
    (((qnio_byte_t *)(p))[0] = (x) & 0xff,             \
     (p) += QNIO_UINT8_SZ)

#define QNIO_UINT8_UNPACK(x, p)                            \
    ((x) = ((qnio_byte_t)((qnio_byte_t *)(p))[0]),         \
     (p) += QNIO_UINT8_SZ)

#define QNIO_INT16_PACK(x, p)                                \
    (((qnio_byte_t *)(p))[0] = ((x) >> 8) & 0xff,        \
     ((qnio_byte_t *)(p))[1] = (x) & 0xff,               \
     (p) += QNIO_INT16_SZ)

#define QNIO_INT16_UNPACK(x, p)                                \
    ((x) = (((int16_t)((qnio_byte_t *)(p))[0] << 8) |   \
            ((int16_t)((qnio_byte_t *)(p))[1])),            \
     (p) += QNIO_INT16_SZ)

#define QNIO_UINT16_PACK(x, p)                               \
    (((qnio_byte_t *)(p))[0] = ((x) >> 8) & 0xff,        \
     ((qnio_byte_t *)(p))[1] = (x) & 0xff,               \
     (p) += QNIO_UINT16_SZ)

#define QNIO_UINT16_UNPACK(x, p)                               \
    ((x) = (((uint16_t)((qnio_byte_t *)(p))[0] << 8) |  \
            ((uint16_t)((qnio_byte_t *)(p))[1])),           \
     (p) += QNIO_UINT16_SZ)

#define QNIO_INT32_PACK(x, p)                                \
    (((qnio_byte_t *)(p))[0] = ((x) >> 24) & 0xff,       \
     ((qnio_byte_t *)(p))[1] = ((x) >> 16) & 0xff,       \
     ((qnio_byte_t *)(p))[2] = ((x) >> 8) & 0xff,        \
     ((qnio_byte_t *)(p))[3] = (x) & 0xff,               \
     (p) += QNIO_INT32_SZ)

#define QNIO_INT32_UNPACK(x, p)                                \
    ((x) = (((int32_t)((qnio_byte_t *)(p))[0] << 24) |  \
            ((int32_t)((qnio_byte_t *)(p))[1] << 16) |      \
            ((int32_t)((qnio_byte_t *)(p))[2] << 8) |      \
            ((int32_t)((qnio_byte_t *)(p))[3])),            \
     (p) += QNIO_INT32_SZ)

#define QNIO_UINT32_PACK(x, p)                               \
    (((qnio_byte_t *)(p))[0] = ((x) >> 24) & 0xff,       \
     ((qnio_byte_t *)(p))[1] = ((x) >> 16) & 0xff,       \
     ((qnio_byte_t *)(p))[2] = ((x) >> 8) & 0xff,        \
     ((qnio_byte_t *)(p))[3] = (x) & 0xff,               \
     (p) += QNIO_UINT32_SZ)





#define QNIO_UINT32_UNPACK(x, p)                                \
    ((x) = (((uint32_t)((qnio_byte_t *)(p))[0] << 24) |  \
            ((uint32_t)((qnio_byte_t *)(p))[1] << 16) |      \
            ((uint32_t)((qnio_byte_t *)(p))[2] << 8) |      \
            ((uint32_t)((qnio_byte_t *)(p))[3])),            \
     (p) += QNIO_UINT32_SZ)

#define QNIO_INT64_PACK(x, p)                                \
    (((qnio_byte_t *)(p))[0] = (qnio_byte_t)((x) >> 56) & 0xff,       \
     ((qnio_byte_t *)(p))[1] = (qnio_byte_t)((x) >> 48) & 0xff,       \
     ((qnio_byte_t *)(p))[2] = (qnio_byte_t)((x) >> 40) & 0xff,       \
     ((qnio_byte_t *)(p))[3] = (qnio_byte_t)((x) >> 32) & 0xff,       \
     ((qnio_byte_t *)(p))[4] = (qnio_byte_t)((x) >> 24) & 0xff,       \
     ((qnio_byte_t *)(p))[5] = (qnio_byte_t)((x) >> 16) & 0xff,       \
     ((qnio_byte_t *)(p))[6] = (qnio_byte_t)((x) >> 8) & 0xff,        \
     ((qnio_byte_t *)(p))[7] = (qnio_byte_t)(x) & 0xff,               \
     (p) += QNIO_INT64_SZ)

#define QNIO_INT64_UNPACK(x, p)                                \
    ((x) = (((int64_t)((qnio_byte_t *)(p))[0] << 56) |  \
            ((int64_t)((qnio_byte_t *)(p))[1] << 48) |      \
            ((int64_t)((qnio_byte_t *)(p))[2] << 40) |      \
            ((int64_t)((qnio_byte_t *)(p))[3] << 32) |      \
            ((int64_t)((qnio_byte_t *)(p))[4] << 24) |      \
            ((int64_t)((qnio_byte_t *)(p))[5] << 16) |      \
            ((int64_t)((qnio_byte_t *)(p))[6] << 8) |      \
            ((int64_t)((qnio_byte_t *)(p))[7])),            \
     (p) += QNIO_INT64_SZ)

#define QNIO_UINT64_PACK(x, p)                               \
    (((qnio_byte_t *)(p))[0] = (qnio_byte_t)((x) >> 56) & 0xff,       \
     ((qnio_byte_t *)(p))[1] = (qnio_byte_t)((x) >> 48) & 0xff,       \
     ((qnio_byte_t *)(p))[2] = (qnio_byte_t)((x) >> 40) & 0xff,       \
     ((qnio_byte_t *)(p))[3] = (qnio_byte_t)((x) >> 32) & 0xff,       \
     ((qnio_byte_t *)(p))[4] = (qnio_byte_t)((x) >> 24) & 0xff,       \
     ((qnio_byte_t *)(p))[5] = (qnio_byte_t)((x) >> 16) & 0xff,       \
     ((qnio_byte_t *)(p))[6] = (qnio_byte_t)((x) >> 8) & 0xff,        \
     ((qnio_byte_t *)(p))[7] = (qnio_byte_t)(x) & 0xff,               \
     (p) += QNIO_UINT64_SZ)

#define QNIO_UINT64_UNPACK(x, p)                                \
    ((x) = (((uint64_t)((qnio_byte_t *)(p))[0] << 56) |  \
            ((uint64_t)((qnio_byte_t *)(p))[1] << 48) |      \
            ((uint64_t)((qnio_byte_t *)(p))[2] << 40) |      \
            ((uint64_t)((qnio_byte_t *)(p))[3] << 32) |      \
            ((uint64_t)((qnio_byte_t *)(p))[4] << 24) |      \
            ((uint64_t)((qnio_byte_t *)(p))[5] << 16) |      \
            ((uint64_t)((qnio_byte_t *)(p))[6] << 8) |      \
            ((uint64_t)((qnio_byte_t *)(p))[7])),            \
     (p) += QNIO_UINT64_SZ)


#define QNIO_GUID_PACK(guid, p)                              \
    (QNIO_UINT32_PACK(*(((uint32_t *)(guid))), (p)),                        \
     (QNIO_UINT16_PACK(*((((uint16_t *)(guid)) + 2)), (p))),                 \
     (QNIO_UINT16_PACK(*((((uint16_t *)(guid)) + 3)), (p))),                 \
     memcpy((p), (qnio_byte_t *)(guid) + offsetof(qnio_guid_t, Data4), 8), \
     (p) += 8)


#define QNIO_GUID_UNPACK(guid, p)                                      \
    (QNIO_UINT32_UNPACK(*(((uint32_t *)(guid))), (p)),          \
     (QNIO_UINT16_UNPACK(*(((uint16_t *)(guid) + 2)), (p))),    \
     (QNIO_UINT16_UNPACK(*(((uint16_t *)(guid) + 3)), (p))),    \
     memcpy((qnio_byte_t *)(guid) + offsetof(qnio_guid_t, Data4), (p), 8), \
     (p) += 8)

#ifdef __cplusplus
}
#endif

#endif                          /* _BASE_PACK_H_ */
