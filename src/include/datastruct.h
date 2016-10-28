/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef BASE_DATASTRUCT
#define BASE_DATASTRUCT    1

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "types.h"
#include "error.h"
#include "ck_spinlock.h"
#include "ck_fifo.h"
#include <assert.h>
#include <pthread.h>

#define RB_NODE_RED         0
#define RB_NODE_BLACK       1

#define RB_LEFT_VISITED     0x01000000
#define RB_RIGHT_VISITED    0x02000000


#define QNIO_MAP              0x02
#define QNIO_VECTOR           0x04

#define QNIO_ITER_BEGIN       0x01
#define QNIO_ITER_END         0x02

typedef uint64_t    qnio_time_t;
typedef uint64_t    qnio_mstime_t;
typedef uint64_t    qnio_ustime_t;

typedef void (*qnio_foreach) (void *, void *);
typedef int (*qnio_compare) (const void *, const void *);

typedef struct __qnio_vector
{
    int           _count;
    int           _max;
    qnio_destructor _dtor;
    void        **_array;
} qnio_vector;

typedef struct _qnio_pair
{
    void *key;
    void *value;
} qnio_pair;

typedef struct _rb_node
{
    struct _rb_node *left;      /* left child */
    struct _rb_node *right;     /* right child */
    struct _rb_node *parent;    /* parent */
    unsigned int     color;     /* node color (RB_NODE_BLACK, RB_NODE_RED) */
    qnio_pair          kv;        /* Key and value */
} qnio_rb_node;


typedef struct _rb_table
{
    unsigned int  type;
    size_t        count;
    qnio_rb_node    sentinel;     /* Sentinel */
    qnio_compare    cmp;          /* Comparison function */
    qnio_rb_node   *root;
    qnio_destructor key_d;        /* Key destructor */
    qnio_destructor val_d;        /* Value destructor */
} qnio_map;

QNIO_API_(void) qnio_vector_insert(qnio_vector * vec, void *p, int idx);
QNIO_API_(qnio_vector *) new_qnio_vector(int size, qnio_destructor fn);
QNIO_API_(void *) qnio_vector_at(const qnio_vector * vec, int idx);
QNIO_API_(int) qnio_vector_size(const qnio_vector * vec);
QNIO_API_(void *) qnio_vector_remove_at(qnio_vector * vec, int idx);
QNIO_API_(void *) qnio_vector_remove(qnio_vector * vec, int idx);
QNIO_API_(void) qnio_vector_clear(qnio_vector * vec, qnio_destructor delfn);
QNIO_API_(void) qnio_vector_delete(qnio_vector * vec);
QNIO_API_(void) qnio_vector_destroy(qnio_vector * vec);
QNIO_API_(void) qnio_vector_pushback(qnio_vector * vec, void *p);
QNIO_API_(void) qnio_vector_pushfront(qnio_vector * vec, void *data);
QNIO_API_(void *) qnio_vector_popfront(qnio_vector * vec);
QNIO_API_(void *) qnio_vector_popback(qnio_vector * vec);
QNIO_API_(void) qnio_vector_foreach(const qnio_vector * vec,
                                qnio_foreach eachfn, void *);
QNIO_API_(int) qnio_vector_find_sorted(const qnio_vector * vec,
                                   qnio_compare cmp, const void *ctx);

QNIO_API_(qnio_map *) new_qnio_map(qnio_compare cmp, qnio_destructor key_delete,
                             qnio_destructor val_delete);
QNIO_API_(int) qnio_map_insert(qnio_map * aMap, void *key, void *value);
QNIO_API_(int) qnio_map_delete(qnio_map * aMap, const void *key);
QNIO_API_(void *) qnio_map_find(const qnio_map * aMap, const void *key);
QNIO_API_(void) qnio_map_free(qnio_map * aMap);

typedef struct __qnio_stream
{
    unsigned char *buffer;
    size_t         pos;
    size_t         max;
    size_t         size;
} qnio_stream;

QNIO_API_(qnio_stream *) new_qnio_stream(size_t size);
QNIO_API_(size_t) qnio_write_stream(qnio_stream * stream,
                                unsigned char *buffer, size_t size);
QNIO_API_(int) qnio_print_stream(int fd, qnio_stream * stream);
QNIO_API_(void) qnio_delete_stream(qnio_stream * stream);
QNIO_API_(size_t) qnio_vprintf_stream_va(qnio_stream * stream, size_t size,
                                     const char *fmt, va_list ap);
QNIO_API_(size_t) qnio_vprintf_stream(qnio_stream * stream, const char *fmt,
                                  ...);
QNIO_API_(size_t) qnio_get_vprintf_size(const char *fmt, size_t * size,
                                    va_list ap);


typedef void   *value_ptr_t;

typedef struct _property_value
{
    unsigned int size;
    unsigned int type;
    value_ptr_t  data;
} property_value_t;


typedef struct _key_value
{
    unsigned int      flags;
    char             *key;
    property_value_t *data;
} key_value_t;


typedef struct _propertyset
{
    qnio_vector *_properties;
    uint32_t   _refcnt;
} kvset_t;


typedef struct _value_array
{
    unsigned int type;
    qnio_vector   *val_array;     /* This is an array of property_value_t * */
} value_array_t;


/*
 * Copy routines
 */
QNIO_API_(property_value_t *) value_copy(const property_value_t * src);
QNIO_API_(key_value_t *) kv_copy(const key_value_t * src);
QNIO_API_(value_array_t *) val_array_copy(const value_array_t * src);
QNIO_API_(kvset_t *) kvset_copy(const kvset_t * ps);

/*
 * Free routines
 */

QNIO_API_(void) value_free(property_value_t * data);
QNIO_API_(void) kv_free(key_value_t * src);
QNIO_API_(void) val_array_free(value_array_t * va);
QNIO_API_(void) kvset_free(kvset_t * p);

/*
 * Creation routines
 */

QNIO_API_(key_value_t *) new_kv(const char *k, unsigned int flag,
                              unsigned int type, unsigned int size,
                              const value_ptr_t data);
QNIO_API_(key_value_t *) new_kv_assign(char *k, unsigned int flags,
                                     unsigned int type,
                                     unsigned int size,
                                     value_ptr_t data);
QNIO_API_(value_array_t *) new_val_array(unsigned int initial_size,
                                       unsigned int type);
QNIO_API_(kvset_t *) new_ps(int size);
QNIO_API_(int) kv_update(key_value_t * dest, const key_value_t * src);
QNIO_API_(int) kv_check_update(key_value_t * dest,
                             const key_value_t * src);
QNIO_API_(int) kv_update_fast(key_value_t * dest, key_value_t * *src);
QNIO_API_(int) kvset_add(kvset_t * ps, key_value_t * kv);
QNIO_API_(key_value_t *) kvset_lookup(kvset_t * ps, const char *key);
QNIO_API_(int) kvset_update(kvset_t * ps, const key_value_t * kv);
QNIO_API_(int) kvset_check_update(kvset_t * ps,
                             const key_value_t * kv);
QNIO_API_(int) kvset_update_fast(kvset_t * ps, key_value_t * *kv);
QNIO_API_(int) kvset_merge(kvset_t * kvset_dest,
                      const kvset_t * kvset_source);
QNIO_API_(int) kvset_merge_fast(kvset_t * kvset_dest,
                           kvset_t * *kvset_source);
QNIO_API_(int) kvset_delete(kvset_t * ps, const char *key);
QNIO_API_(key_value_t *) kvset_remove(kvset_t * ps, const char *key);
QNIO_API_(int) kvset_compare(const kvset_t * s1,
                        const kvset_t * kvset_dest);
QNIO_API_(int) kv_compare(const key_value_t * kv1,
                        const key_value_t * kv2);
QNIO_API_(void) kvset_print(qnio_stream * str, int level,
                       const kvset_t * p);
QNIO_API_(key_value_t *) kvset_at(const kvset_t * ps, int idx);
QNIO_API_(int) kvset_getcount(const kvset_t * ps);

QNIO_API_(kvset_t *) parse_json(const char *data);




#define STRING_LEVEL_VALUE    0

#define TYPE_UNKNOWN          (0x00000000)                /* UnknownValueType */
#define TYPE_ARRAY            (0x80000000)                /* Array Type */
#define TYPE_MASQUERADE       (0x40000000)
#define TYPE_NOFREE           (0x20000000)                /* donot free the kv
                                                          **/

#define TYPE_BOOLEAN          (0x00000001)                /* BooleanValueType */
#define TYPE_BOOLEANZ         (TYPE_BOOLEAN | TYPE_ARRAY) /*
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *BooleanArrayValueType
                                                           **/
#define TYPE_INT32            (0x00000002)                /* Int32ValueType */
#define TYPE_INT32Z           (TYPE_INT32 | TYPE_ARRAY)   /* Int32ArrayValueType
                                                          **/
#define TYPE_ULONG            (0x00000003)                /* UInt32ValueType */
#define TYPE_UINT32           (0x00000003)                /* UInt32ValueType */
#define TYPE_UINT32Z          (TYPE_UINT32 | TYPE_ARRAY)  /*
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *UInt32ArrayValueType
                                                           **/
#define TYPE_LONGLONG         (0x00000004)                /* Int64ValueType */
#define TYPE_INT64            (0x00000004)                /* Int64ValueType */
#define TYPE_INT64Z           (TYPE_INT64 | TYPE_ARRAY)   /* Int64ArrayValueType
                                                          **/
#define TYPE_UINT64           (0x00000005)                /* UInt64ValueType */
#define TYPE_UINT64Z          (TYPE_UINT64 | TYPE_ARRAY)  /*
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *UInt64ArrayValueType
                                                           **/
#define TYPE_STR              (0x00000006)                /* StringValueType */
#define TYPE_STRZ             (TYPE_STR | TYPE_ARRAY)     /*
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *StringArrayValueType
                                                           **/
#define TYPE_PBYTE            (0x00000008)                /* BinaryValueType */
#define TYPE_BINARY           (0x00000008)                /* BinaryValueType */
#define TYPE_BINARYZ          (0x00000008 | TYPE_ARRAY)   /*
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *BinaryArrayValueType
                                                           **/
#define TYPE_GUID             (0x00000009)                /* GUIDValueType */
#define TYPE_GUIDZ            (TYPE_GUID | TYPE_ARRAY)    /* GUIDArrayValueType
                                                          **/
#define TYPE_PROPSET          (0x0000000a)                /* PropsetValueType */
#define TYPE_PROPSETZ         (TYPE_PROPSET | TYPE_ARRAY) /*
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *
                                                           *PropsetArrayValueType
                                                           **/
#define TYPE_TIME             (0x00010005)                /* TimeValueType */
#define TYPE_TIMEZ            (TYPE_TIME | TYPE_ARRAY)    /* TimeArrayValueType
                                                          **/

#define MAX_STR_VALUE_SIZE    (0x2000)

QNIO_API_(qnio_byte_t *) kvset_marshal(const kvset_t * p, int *s);
QNIO_API_(void) kvset_unmarshal(qnio_byte_t * bs, kvset_t * *p);

/*
 * Helper  macros for adding values to property set.
 */
#define kvset_add_boolean(p, k,                                      \
                       v)    (kvset_add((p),                         \
                                     new_kv((k), 0, TYPE_BOOLEAN, \
                                            sizeof (uint8_t), &(v))))
#define kvset_add_uint32(p, k,                                      \
                      v)     (kvset_add((p),                        \
                                     new_kv((k), 0, TYPE_UINT32, \
                                            sizeof (uint32_t), &(v))))
#define kvset_add_int32(p, k,                                      \
                     v)      (kvset_add((p),                       \
                                     new_kv((k), 0, TYPE_INT32, \
                                            sizeof (int32_t), &(v))))
#define kvset_add_uint64(p, k,                                      \
                      v)     (kvset_add((p),                        \
                                     new_kv((k), 0, TYPE_UINT64, \
                                            sizeof (uint64_t), &(v))))
#define kvset_add_int64(p, k,                                      \
                     v)      (kvset_add((p),                       \
                                     new_kv((k), 0, TYPE_INT64, \
                                            sizeof (int64_t), &(v))))
#define kvset_add_string(p, k,                                                    \
                      v)     (kvset_add((p),                                      \
                                     new_kv((k), 0, TYPE_STR, strlen((v)) + 1, \
                                            (v))))

/*
 * io_vector definition and APIs
 */
typedef void (*io_destructor) (struct iovec);
typedef struct __io_vector
{
    int           _count;      /* Number of iovecs */
    int           _max;        /* Max number of iovecs */
    uint64_t      _total_size; /* Total size of bufs in iovecs */
    struct iovec *_iovec;      /* List of iovecs */
    io_destructor _dtor;       /* destructor function */
} io_vector;

QNIO_API_(io_vector *) new_io_vector(int size, io_destructor fn);
QNIO_API_(void) io_vector_dup(io_vector * src, io_vector * dest);
QNIO_API_(void) io_vector_insert_at(io_vector * ivec, struct iovec vec, int idx);
QNIO_API_(void) io_vector_insert(io_vector * ivec, struct iovec vec, int idx);
QNIO_API_(struct iovec) io_vector_remove(io_vector *ivec, int idx);
QNIO_API_(struct iovec) io_vector_at(io_vector *ivec, int idx);
QNIO_API_(void) io_vector_pushfront(io_vector * ivec, struct iovec vec);
QNIO_API_(void) io_vector_pushback(io_vector * ivec, struct iovec vec);
QNIO_API_(struct iovec) io_vector_popfront(io_vector *ivec);
QNIO_API_(struct iovec) io_vector_popback(io_vector *ivec);
QNIO_API_(void) io_vector_clear(io_vector * ivec, io_destructor fn);
QNIO_API_(int) io_vector_count(io_vector * ivec);
QNIO_API_(int) io_vector_size(io_vector * ivec);
QNIO_API_(struct iovec *) io_vector_addr(io_vector *ivec);
QNIO_API_(void) io_vector_delete(io_vector * ivec);
QNIO_API_(void) io_vector_destroy(io_vector * ivec);

typedef struct fifo_node
{
    void *value;
    struct fifo_node *next;
}fifo_node_t;

typedef struct fifo
{
    fifo_node_t *head;
    fifo_node_t *tail;
    int size;
}fifo_t;
    
QNIO_API_(void) fifo_init(fifo_t *fifo);
QNIO_API_(void) fifo_enqueue(fifo_t *fifo, void *value);
QNIO_API_(void *) fifo_dequeue(fifo_t *fifo);
QNIO_API_(void *) fifo_first(fifo_t *fifo);
QNIO_API_(int) fifo_size(fifo_t *fifo);
QNIO_API_(void) fifo_enqueue_node(fifo_t *fifo, fifo_node_t *node, void *value);
QNIO_API_(void *) fifo_dequeue_node(fifo_t *fifo, fifo_node_t **garbage);

typedef struct slab
{
    fifo_t data;
    fifo_t nodes;
    uint32_t alloc_size;
    uint32_t size;
    size_t alignment;
    void * (*init_fptr) (void *);
    ck_spinlock_fas_t slock;
} slab_t;

QNIO_API_(void) slab_init(slab_t *slab, uint32_t size, uint32_t alloc_size, size_t alignment, void * (*fptr) (void *));
QNIO_API_(void) slab_put(slab_t *slab, void *entry);
QNIO_API_(void *) slab_get(slab_t *slab);
QNIO_API_(void) slab_put_unsafe(slab_t *slab, void *entry);
QNIO_API_(void *) slab_get_unsafe(slab_t *slab);
QNIO_API_(void) slab_free(slab_t *slab);


typedef struct safe_fifo
{
    fifo_t data;
    slab_t nodes;
    ck_spinlock_fas_t slock;
} safe_fifo_t;

#define MAX_SAFE_FIFO_NODES 4096 

QNIO_API_(void) safe_fifo_init(safe_fifo_t *fifo);
QNIO_API_(void) safe_fifo_enqueue(safe_fifo_t *fifo, void *entry);
QNIO_API_(void *) safe_fifo_dequeue(safe_fifo_t *fifo);
QNIO_API_(void *) safe_fifo_dequeue2(safe_fifo_t *fifo);
QNIO_API_(void *) safe_fifo_first(safe_fifo_t *fifo);
QNIO_API_(void *) safe_fifo_first2(safe_fifo_t *fifo);
QNIO_API_(int) safe_fifo_size(safe_fifo_t *fifo);
QNIO_API_(void) safe_fifo_free(safe_fifo_t *fifo);

typedef struct safe_map
{
    qnio_map *dmap;
    ck_spinlock_fas_t mlock;
} safe_map_t;

QNIO_API_(void) safe_map_init(safe_map_t *map);
QNIO_API_(void *) safe_map_find(safe_map_t *map, int key);
QNIO_API_(void) safe_map_insert(safe_map_t *map, int key, void *value);
QNIO_API_(void) safe_map_delete(safe_map_t *map, int key);
QNIO_API_(void) safe_map_free(safe_map_t *map);

#ifdef __cplusplus
}
#endif

#endif
