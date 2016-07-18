/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "types.h"
#include "datastruct.h"
#include "pack.h"
#include "base64.h"
#include "cJSON.h"
#include "ck_pr.h"

static void val_array_print(qnio_stream *stream, int level, int type,
                            const value_array_t *va);
static void value_print(qnio_stream *stream, int level,
                        const property_value_t *v);
static int value_compare(const property_value_t *s, const property_value_t *d);
static int value_array_compare(const value_array_t *s_array,
                               const value_array_t *d_array);
static void kv_print(qnio_stream *stream, int level, const key_value_t *kv);

/* ps marshal sub-routines */
static int value_binary_pack_size(const property_value_t *v);
static int kv_binary_pack_size(const key_value_t *kv);
static int val_array_binary_pack_size(const value_array_t *va);
static int kvset_binary_pack_size(const kvset_t *p);
static qnio_byte_t *value_binary_pack(qnio_byte_t *bs, const property_value_t *v);
static qnio_byte_t *kv_binary_pack(qnio_byte_t *bs, const key_value_t *kv);
static qnio_byte_t *val_array_binary_pack(qnio_byte_t *bs, const value_array_t *va);
static qnio_byte_t *kvset_binary_pack(qnio_byte_t *bs, const kvset_t *p);
static qnio_byte_t *value_binary_unpack(qnio_byte_t *bs, property_value_t **val,
                                      uint32_t type);
static qnio_byte_t *kvset_binary_unpack(qnio_byte_t *bs, kvset_t **p);

static uint32_t kvset_magic = ('P' << 24 | 'S' << 16 | '1' << 8 | '0');
#define PS_MAGIC_SZ            QNIO_UINT32_SZ

#define MARSHALED_LENGTH_SZ    QNIO_UINT32_SZ

#define ALIGN_DOWN(size, alignment) \
    ((uint32_t)(size) & ~((uint32_t)(alignment) - 1))

#define ALIGN_UP_U32(size, alignment) \
    (ALIGN_DOWN(((uint32_t)(size) + (uint32_t)(alignment) - 1), (alignment)))

static int
is_valid_type(int type)
{
    type &= ~TYPE_ARRAY;

    type &= ~TYPE_MASQUERADE;
    type &= ~TYPE_NOFREE;
    if (((type > 0) && (type < 0x00000012)) || type == 0x00010005)
    {
        return (1);
    }
    else
    {
        return (0);
    }
}

const char *json_hex_chars = "0123456789abcdef";

static void
print_json_string(qnio_stream *stream, int level, char *str_in)
{
    int i;
    int len_in;

    for (i = 0; i < level; i++)
    {
        qnio_vprintf_stream(stream, "  ");
    }

    qnio_write_stream(stream, (unsigned char *)"\"", 1);
    len_in = strlen(str_in);
    for (i = 0; i < len_in; i++)
    {
        char *str_out;
        char  tmp_buf[7];
        int   len_out;

        switch (str_in[i])
        {
            case '"':
                str_out = "\\\"";
                len_out = 2;
                break;
            case '\\':
                str_out = "\\\\";
                len_out = 2;
                break;
            case '\b':
                str_out = "\\b";
                len_out = 2;
                break;
            case '\f':
                str_out = "\\f";
                len_out = 2;
                break;
            case '\n':
                str_out = "\\n";
                len_out = 2;
                break;
            case '\r':
                str_out = "\\r";
                len_out = 2;
                break;
            case '\t':
                str_out = "\\t";
                len_out = 2;
                break;
            case '/':
                str_out = "\\/";
                len_out = 2;
                break;
            default:
                if (str_in[i] < ' ')
                {
                    snprintf(tmp_buf, 7, "\\u00%c%c",
                             json_hex_chars[str_in[i] >> 4],
                             json_hex_chars[str_in[i] & 0xf]);
                    str_out = tmp_buf;
                    len_out = 6;
                }
                else
                {
                    str_out = &str_in[i];
                    len_out = 1;
                }
                break;
        }
        qnio_write_stream(stream, (unsigned char *)str_out, len_out);
    }
    qnio_write_stream(stream, (unsigned char *)"\"", 1);
}

QNIO_API_(void)
print_string(qnio_stream * stream, int level, const char *fmt, ...)
{
    int     i;
    va_list va;
    size_t  size = 1024;
    int     rc = 0;

    for (i = 0; i < level; i++)
    {
        qnio_vprintf_stream(stream, "  ");
    }
    while (rc == 0)
    {
        va_start(va, fmt);
        rc = qnio_get_vprintf_size(fmt, &size, va);
        va_end(va);
    }
    va_start(va, fmt);
    qnio_vprintf_stream_va(stream, size, fmt, va);
    va_end(va);
}

QNIO_API_(int)
guidtostr(const qnio_guid_t * GUID, char *str)
{
    return (sprintf(str,
                    "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                    GUID->Data1, GUID->Data2, GUID->Data3,
                    GUID->Data4[0], GUID->Data4[1],
                    GUID->Data4[2], GUID->Data4[3],
                    GUID->Data4[4], GUID->Data4[5],
                    GUID->Data4[6], GUID->Data4[7]));
}

QNIO_API_(property_value_t *) value_copy(const property_value_t * src)
{
    int type;
    int size;
    value_ptr_t       p;
    property_value_t *prop_val;

    type = src->type;
    size = src->size;

    prop_val = (property_value_t *)malloc(sizeof (property_value_t));
    prop_val->size = src->size;
    prop_val->type = src->type;
    if (type & TYPE_ARRAY)
    {
        p = (value_ptr_t *)val_array_copy((value_array_t *)(src->data));
    }
    else
    {
        switch (type)
        {
            case TYPE_PROPSET:
                p = (value_ptr_t)kvset_copy((kvset_t *)src->data);
                break;
            default:
                p = (value_ptr_t)malloc(size);
                memcpy(p, src->data, size);
                break;
        }
    }
    prop_val->data = p;
    return (prop_val);
}

QNIO_API_(key_value_t *) kv_copy(const key_value_t * src)
{
    key_value_t *kv = (key_value_t *)malloc(sizeof (key_value_t));

    memcpy(kv, src, sizeof (key_value_t));
    kv->key = (char *)malloc(strlen(src->key) + 1);
    strcpy(kv->key, src->key);
    kv->data = value_copy(src->data);
    return (kv);
}

QNIO_API_(value_array_t *) val_array_copy(const value_array_t * src)
{
    value_array_t *va;
    int            i;
    value_ptr_t    tmp;
    qnio_vector     *src_vec;
    qnio_vector     *dest_vec;

    va = (value_array_t *)malloc(sizeof (value_array_t));
    src_vec = src->val_array;

    memcpy(va, src, sizeof (value_array_t));
    va->val_array = new_qnio_vector(src_vec->_count, src_vec->_dtor);

    dest_vec = va->val_array;
    for (i = 0; i < src_vec->_count; i++)
    {
        tmp = qnio_vector_at(src_vec, i);
        qnio_vector_pushback(dest_vec, value_copy(tmp));
    }
    return (va);
}

QNIO_API_(kvset_t *) kvset_copy(const kvset_t * ps)
{
    kvset_t *tmp_ps;
    qnio_vector     *props;
    key_value_t   *kv;
    int            i;

    props = ps->_properties;

    tmp_ps = new_ps(props->_count);
    /*
     * We will do a deep copy of all the kvs
     */
    for (i = 0; i < props->_count; i++)
    {
        kv = kv_copy((key_value_t *)qnio_vector_at(props, i));
        qnio_vector_pushback(tmp_ps->_properties, kv);
    }
    return (tmp_ps);
}

QNIO_API_(void) value_free(property_value_t * data)
{
    if (!data)
    {
        return;
    }
    if (data->type & TYPE_ARRAY)
    {
        val_array_free((value_array_t *)data->data);
    }
    else if (data->type & TYPE_NOFREE)
    {
    }
    else
    {
        switch (data->type)
        {
            case TYPE_PROPSET:
                kvset_free((kvset_t *)(data->data));
                break;
            default:
                free(data->data);
                break;
        }
    }
    free(data);
}

QNIO_API_(void)
kv_free(key_value_t * src)
{
    if (!src)
    {
        return;
    }
    value_free(src->data);
    free(src->key);
    free(src);
}

QNIO_API_(void) val_array_free(value_array_t * va)
{
    int i;

    if (!va)
    {
        return;
    }
    for (i = 0; i < va->val_array->_count; i++)
    {
        value_free(qnio_vector_at(va->val_array, i));
    }
    qnio_vector_delete(va->val_array);
    free(va);
}

QNIO_API_(void)
kvset_free(kvset_t * ps)
{
    int        i;
    qnio_vector *props;
    bool       zero;

    ck_pr_dec_32_zero(&ps->_refcnt, &zero);
    if (zero == true)
    {
        props = ps->_properties;
        if (props)
        {
            for (i = 0; i < props->_count; i++)
            {
                kv_free(qnio_vector_at(props, i));
            }
            qnio_vector_delete(props);
        }
        free(ps);
    }
}

QNIO_API_(key_value_t *)
new_kv_assign(char *k, unsigned int flags, unsigned int type,
              unsigned int size, value_ptr_t data)
{
    key_value_t *kv;

    kv = (key_value_t *)malloc(sizeof (key_value_t));
    kv->flags = flags;
    kv->data = (property_value_t *)malloc(sizeof (property_value_t));
    memset(kv->data, 0, sizeof (property_value_t));

    kv->key = k;
    kv->data->type = type;
    kv->data->size = size;
    kv->data->data = data;
    return (kv);
}

QNIO_API_(key_value_t *)
new_kv(const char *k, unsigned int flags, unsigned int type,
       unsigned int size, const value_ptr_t data)
{
    char            *x;
    key_value_t     *kv;
    property_value_t v, *pv;

    if (!is_valid_type(type))
    {
        return (NULL);
    }
    x = (char *)malloc(strlen(k) + 1);
    strcpy(x, k);
    v.data = (value_ptr_t)data;
    v.size = size;
    v.type = type;
    pv = value_copy(&v);
    kv = new_kv_assign(x, flags, type, size, pv->data);
    free(pv);
    return (kv);
}

QNIO_API_(kvset_t *) new_ps(int size)
{
    kvset_t *ps = (kvset_t *)malloc(sizeof (kvset_t));

    /*
     * We never need to free the elements of the vector since these are
     * * simply pointers. Hence NULL as destructor
     */
    ps->_properties = new_qnio_vector(size, NULL);

    /*
     * Hold a reference on the newly created property set
     */
    ps->_refcnt = 0;
    ck_pr_inc_32(&ps->_refcnt);

    return (ps);
}

QNIO_API_(int) kv_update_fast(key_value_t * dest, key_value_t * *src)
{
    if (dest->data->type != (*src)->data->type)
    {
        return (QNIOERROR_PROPERTY_MISMATCH);
    }
    value_free(dest->data);
    dest->flags = (*src)->flags;
    dest->data = (*src)->data;
    free((*src)->key);
    free(*src);
    *src = NULL;
    return (QNIOERROR_SUCCESS);
}

QNIO_API_(int) kv_update(key_value_t * dest, const key_value_t * src)
{
    property_value_t *pv;

    if (dest->data->type != src->data->type)
    {
        return (QNIOERROR_PROPERTY_MISMATCH);
    }
    value_free(dest->data);
    pv = value_copy(src->data);
    dest->data = pv;

    return (QNIOERROR_SUCCESS);
}

QNIO_API_(int) kv_check_update(key_value_t * dest, const key_value_t * src)
{
    property_value_t *pv;

    if (dest->data->type != src->data->type)
    {
        return (QNIOERROR_PROPERTY_MISMATCH);
    }
    if (value_compare(dest->data, src->data) == 1)
    {
        return (QNIOERROR_NOCHANGE);
    }
    value_free(dest->data);
    pv = value_copy(src->data);
    dest->data = pv;

    return (QNIOERROR_SUCCESS);
}


QNIO_API_(int) kvset_add(kvset_t * ps, key_value_t * kv)
{
    qnio_vector   *props;
    key_value_t *tmp;
    int          x = 0;
    int          low = 0;
    int          middle = 0;
    int          high;

    if (!kv || !kv->data->data)
    {
        return (QNIOERROR_INVALIDARG);
    }
    props = ps->_properties;
    high = qnio_vector_size(props) - 1;

    while (low <= high)
    {
        middle = (int)((low + high) / 2);
        tmp = (key_value_t *)qnio_vector_at(props, middle);
        x = strcmp(kv->key, tmp->key);
        if (x == 0)
        {
            return (QNIOERROR_DUPLICATE_KEY);
        }
        if (x < 0)
        {
            high = middle - 1;
        }
        else
        {
            low = middle + 1;
        }
    }
    qnio_vector_insert(props, kv, x <= 0 ? middle : middle + 1);
    return (QNIOERROR_SUCCESS);
}

static int
kvset_key_compare(const void *key, const void *var)
{
    return (strcmp((const char *)key,
                   (const char *)(((key_value_t *)var)->key)));
}

QNIO_API_(key_value_t *) kvset_lookup(kvset_t * ps, const char *key)
{
    int        indx;
    qnio_vector *props = ps->_properties;

    indx = qnio_vector_find_sorted(props, kvset_key_compare, key);
    if (indx < 0)
    {
        return (NULL);
    }
    else
    {
        return ((key_value_t *)(qnio_vector_at(props, indx)));
    }
}

QNIO_API_(int) kvset_update(kvset_t * ps, const key_value_t * kv)
{
    int          x;
    int          i;
    key_value_t *dest_kv;
    qnio_vector   *props = ps->_properties;

    if (!kv || !kv->data->data)
    {
        return (QNIOERROR_INVALIDARG);
    }
    for (i = 0; i < props->_count; i++)
    {
        dest_kv = (key_value_t *)qnio_vector_at(props, i);
        x = strcmp(dest_kv->key, kv->key);
        if (x == 0)
        {
            return (kv_update(dest_kv, kv));
        }
        else if (x > 0)
        {
            break;
        }
    }
    dest_kv = kv_copy(kv);
    qnio_vector_insert(props, dest_kv, i);
    return (QNIOERROR_SUCCESS);
}

QNIO_API_(int) kvset_check_update(kvset_t * ps, const key_value_t * kv)
{
    int          x;
    int          i;
    key_value_t *dest_kv;
    qnio_vector   *props = ps->_properties;

    for (i = 0; i < props->_count; i++)
    {
        dest_kv = (key_value_t *)qnio_vector_at(props, i);
        x = strcmp(dest_kv->key, kv->key);
        if (x == 0)
        {
            return (kv_check_update(dest_kv, kv));
        }
        else if (x > 0)
        {
            break;
        }
    }
    dest_kv = kv_copy(kv);
    qnio_vector_insert(props, dest_kv, i);
    return (QNIOERROR_SUCCESS);
}

QNIO_API_(int) kvset_update_fast(kvset_t * ps, key_value_t * *kv)
{
    int          x;
    int          i;
    key_value_t *dest_kv;
    qnio_vector   *props = ps->_properties;

    for (i = 0; i < props->_count; i++)
    {
        dest_kv = (key_value_t *)qnio_vector_at(props, i);
        x = strcmp(dest_kv->key, (*kv)->key);
        if (x == 0)
        {
            return (kv_update_fast(dest_kv, kv));
        }
        else if (x > 0)
        {
            break;
        }
    }
    qnio_vector_insert(props, *kv, i);
    *kv = NULL;
    return (QNIOERROR_SUCCESS);
}

QNIO_API_(int) kvset_delete(kvset_t * ps, const char *key)
{
    int        indx;
    qnio_vector *props = ps->_properties;

    indx = qnio_vector_find_sorted(props, kvset_key_compare, key);
    if (indx < 0)
    {
        return (QNIOERROR_NO_PROPERTY);
    }
    else
    {
        kv_free(qnio_vector_at(props, indx));
        qnio_vector_remove(props, indx);
    }
    return (QNIOERROR_SUCCESS);
}

QNIO_API_(int)
kvset_merge(kvset_t * kvset_dest, const kvset_t * kvset_source)
{
    int          x;
    int          i, j;
    qnio_vector   *src;
    qnio_vector   *dest;
    key_value_t *kv_src;
    key_value_t *kv_dest;
    key_value_t *kv;
    int          updated;

    src = kvset_source->_properties;
    dest = kvset_dest->_properties;
    for (j = 0, i = 0; i < src->_count; i++)
    {
        kv_src = qnio_vector_at(src, i);
        for (updated = 0; j < dest->_count; j++)
        {
            kv_dest = qnio_vector_at(dest, j);
            x = strcmp(kv_src->key, kv_dest->key);
            if (x == 0)
            {
                kv_update(kv_dest, kv_src);
                j++;
                updated = 1;
                break;
            }
            else if (x < 0)
            {
                kv = kv_copy(kv_src);
                qnio_vector_insert(dest, kv, j);
                updated = 1;
                j++;
                break;
            }
        }
        /*
         * if we have not found a position, then append it
         * * since j is already maxed all elements in the src after
         * * this will get appended
         */
        if (!updated)
        {
            kv = kv_copy(kv_src);
            j++;
            qnio_vector_pushback(dest, kv);
        }
    }
    return (0);
}

QNIO_API_(int)
kvset_merge_fast(kvset_t * kvset_dest, kvset_t * *kvset_source)
{
    int          x;
    int          i, j;
    qnio_vector   *src;
    qnio_vector   *dest;
    key_value_t *kv_src;
    key_value_t *kv_dest;
    int          updated;

    src = (*kvset_source)->_properties;
    dest = kvset_dest->_properties;
    for (j = 0, i = 0; i < src->_count; i++)
    {
        kv_src = qnio_vector_at(src, i);
        for (updated = 0; j < dest->_count; j++)
        {
            kv_dest = qnio_vector_at(dest, j);
            x = strcmp(kv_src->key, kv_dest->key);
            if (x == 0)
            {
                kv_update_fast(kv_dest, &kv_src);
                if (kv_src == NULL)
                {
                    qnio_vector_remove(src, i);
                }
                j++;
                updated = 1;
                break;
            }
            else if (x < 0)
            {
                qnio_vector_insert(dest, kv_src, j);
                qnio_vector_remove(src, i);
                j++;
                updated = 1;
                break;
            }
        }
        /*
         * if we have not found a position, then append it
         * * since j is already maxed all elements in the src after
         * * this will get appended
         */
        if (!updated)
        {
            j++;
            qnio_vector_pushback(dest, kv_src);
            qnio_vector_remove(src, i);
        }
    }
    kvset_free(*kvset_source);
    *kvset_source = NULL;
    return (0);
}


QNIO_API_(int)
kvset_compare(const kvset_t * kvset_source, const kvset_t * kvset_dest)
{
    int          i;
    int          result = 1;
    qnio_vector   *src;
    qnio_vector   *dest;
    key_value_t *kv_src;
    key_value_t *kv_dest;

    src = kvset_source->_properties;
    dest = kvset_dest->_properties;
    /*
     * Check number of properties in both propertyset
     */
    if (src->_count != dest->_count)
    {
        return (0);
    }
    /*
     * Compare all key_values in both properties
     */
    for (i = 0; i < src->_count; i++)
    {
        kv_src = qnio_vector_at(src, i);
        kv_dest = qnio_vector_at(dest, i);

        result = kv_compare(kv_src, kv_dest);
        if (result != 1)
        {
            break;
        }
    }
    /*
     * All properties in two kvset_t are identical
     */
    return (result);
}

QNIO_API_(int)
kv_compare(const key_value_t * kv_src, const key_value_t * kv_dest)
{
    property_value_t *src_data;
    property_value_t *dest_data;

    /*
     * compare key of source and dest
     */
    if (strcmp(kv_src->key, kv_dest->key) != 0)
    {
        return (0);
    }
    src_data = kv_src->data;
    dest_data = kv_dest->data;
    /*
     * compare type of source and dest
     */
    if (src_data->type != dest_data->type)
    {
        return (0);
    }
    /*
     * compare value of source and dest
     */
    if (value_compare(src_data, dest_data) != 1)
    {
        return (0);
    }
    return (1);
}

static int
value_compare(const property_value_t *s, const property_value_t *d)
{
    int result = 0;

    if (s->type & TYPE_ARRAY)
    {
        return (value_array_compare(s->data, d->data));
    }
    switch (s->type)
    {
        case TYPE_STR:
            if (strcmp((char *)s->data, (char *)d->data) == 0)
            {
                result = 1;
            }
            break;
        case TYPE_INT32:
            result = (*((int *)s->data) == *((int *)d->data)) ? 1 : 0;
            break;
        case TYPE_UINT32:
            result =
                (*((unsigned int *)s->data) ==
                 *((unsigned int *)d->data)) ? 1 : 0;
            break;
        case TYPE_PROPSET:
            result =
                kvset_compare((kvset_t *)s->data,
                           (kvset_t *)d->data) ? 1 : 0;
            break;
    }
    return (result);
}

static int
value_array_compare(const value_array_t *s_array, const value_array_t *d_array)
{
    int i;

    /*
     * initialize result to 1 to handle empty arrays
     */
    int        result = 1;
    qnio_vector *src_vec = s_array->val_array;
    qnio_vector *dest_vec = d_array->val_array;

    /*
     * No of elements in array should be identical
     */
    if (src_vec->_count != dest_vec->_count)
    {
        return (0);
    }
    /*
     * compare each element in array, using value_compare
     */
    for (i = 0; i < src_vec->_count; i++)
    {
        result =
            value_compare((property_value_t *)(qnio_vector_at(src_vec, i)),
                          (property_value_t *)(qnio_vector_at(dest_vec, i)));
        if (result != 1)
        {
            break;
        }
    }
    return (result);
}

QNIO_API_(key_value_t *) kvset_at(const kvset_t * ps, int idx)
{
    return (qnio_vector_at(ps->_properties, idx));
}

QNIO_API_(key_value_t *) kvset_remove(kvset_t * ps, const char *key)
{
    int        indx;
    qnio_vector *props = ps->_properties;

    indx = qnio_vector_find_sorted(props, kvset_key_compare, key);
    if (indx < 0)
    {
        return (NULL);
    }
    else
    {
        return ((key_value_t *)(qnio_vector_remove(props, indx)));
    }
}

QNIO_API_(int) kvset_getcount(const kvset_t * ps)
{
    return (ps->_properties->_count);
}

static qnio_byte_t *
val_array_binary_pack(qnio_byte_t *bs, const value_array_t *va)
{
    int        i;
    qnio_vector *vals = va->val_array;

    /*
     * Put the count
     */
    QNIO_UINT32_PACK(vals->_count, bs);
    /*
     * Put the values
     */
    for (i = 0; i < vals->_count; i++)
    {
        bs = value_binary_pack(bs,
                               (property_value_t *)(qnio_vector_at(vals, i)));
    }
    return (bs);
}

static qnio_byte_t *
value_binary_pack(qnio_byte_t *bs, const property_value_t *v)
{
    int size;

    if (v->type & TYPE_MASQUERADE)
    {
        memcpy(bs, v->data, v->size);
        bs += v->size;
        return (bs);
    }
    if (v->type & TYPE_ARRAY)
    {
        return (val_array_binary_pack(bs, (value_array_t *)(v->data)));
    }
    switch (v->type & ~TYPE_NOFREE)
    {
        case TYPE_GUID:
            QNIO_GUID_PACK(v->data, bs);
            break;
        case TYPE_STR:
            size = v->size - 1; /* Remove the space for the NULL */
            QNIO_UINT32_PACK(size, bs);
            memcpy(bs, v->data, size);
            bs += size;
            break;
        case TYPE_INT32:
        case TYPE_UINT32:
            {
                uint32_t x;

                x = *((uint32_t *)(v->data));
                QNIO_UINT32_PACK(x, bs);
            }
            break;
        case TYPE_UINT64:
        case TYPE_INT64:
        case TYPE_TIME:
            {
                uint64_t x;

                x = *((uint64_t *)(v->data));
                QNIO_UINT64_PACK(x, bs);
            }
            break;
        case TYPE_BOOLEAN:
            {
                bool x = *((bool *)(v->data));

                *bs = (qnio_byte_t)x;
                bs++;
            }
            break;
        case TYPE_PROPSET:
            bs = kvset_binary_pack(bs, (kvset_t *)(v->data));
            break;
        case TYPE_BINARY:
            size = v->size;
            QNIO_UINT32_PACK(size, bs);
            memcpy(bs, v->data, size);
            bs += size;
            break;
    }
    return (bs);
}

static qnio_byte_t *
kv_binary_pack(qnio_byte_t *bs, const key_value_t *kv)
{
    int      size;
    uint32_t type;

    type = (kv->data->type) & ~TYPE_MASQUERADE;
    type &= ~TYPE_NOFREE;
    /*
     * Put the type in for the Key-value
     */
    QNIO_UINT32_PACK(type, bs);
    /*
     * Put the size of the key
     */
    size = strlen(kv->key);
    QNIO_UINT32_PACK(size, bs);
    /*
     * Put the key
     */
    memcpy(bs, kv->key, size);
    bs += size;

    /*
     * Put the flags
     */
    QNIO_UINT32_PACK(kv->flags, bs);

    /*
     * Put the value
     */
    bs = value_binary_pack(bs, kv->data);
    return (bs);
}

static qnio_byte_t *
kvset_binary_pack(qnio_byte_t *bs, const kvset_t *p)
{
    int        i;
    int        size = 0;
    qnio_vector *props = p->_properties;

    /*
     * Put the number of entries in the array
     */

    size = props->_count;
    QNIO_UINT32_PACK(size, bs);
    /*
     * Marshal the elements of the array
     */
    for (i = 0; i < props->_count; i++)
    {
        bs = kv_binary_pack(bs, (key_value_t *)(qnio_vector_at(props, i)));
    }
    return (bs);
}

static int
val_array_binary_pack_size(const value_array_t *va)
{
    int        i;
    int        s = QNIO_UINT32_SZ;
    qnio_vector *vals = va->val_array;

    for (i = 0; i < vals->_count; i++)
    {
        s += value_binary_pack_size((property_value_t
                                     *)(qnio_vector_at(vals, i)));
    }
    return (s);
}

static int
value_binary_pack_size(const property_value_t *v)
{
    int s = 0;

    if (v->type & TYPE_MASQUERADE)
    {
        s += v->size;
        return (s);
    }
    if (v->type & TYPE_ARRAY)
    {
        s = val_array_binary_pack_size((value_array_t *)(v->data));
        return (s);
    }
    switch (v->type & ~TYPE_NOFREE)
    {
        case TYPE_STR:
            s += (QNIO_UINT32_SZ + v->size - 1);  /* There is no need to account
                                                 * for the NULL */
            break;
        case TYPE_BINARY:
            s += QNIO_UINT32_SZ;
        /*
         * FALLTHROUGH
         */
        case TYPE_INT32:
        case TYPE_UINT32:
        case TYPE_GUID:
        case TYPE_UINT64:
        case TYPE_INT64:
        case TYPE_TIME:
        case TYPE_BOOLEAN:
            s += v->size;
            break;
        case TYPE_PROPSET:
            s += kvset_binary_pack_size((kvset_t *)(v->data));
            break;
    }
    return (s);
}

static int
kv_binary_pack_size(const key_value_t *kv)
{
    /*
     * type + key size + key + flags + value
     */
    return (QNIO_INT32_SZ + QNIO_INT32_SZ + strlen(kv->key) + QNIO_INT32_SZ +
            value_binary_pack_size(kv->data));
}

static int
kvset_binary_pack_size(const kvset_t *p)
{
    int        i;
    int        s = QNIO_UINT32_SZ;
    qnio_vector *props = p->_properties;

    for (i = 0; i < props->_count; i++)
    {
        s += kv_binary_pack_size((key_value_t *)(qnio_vector_at(props, i)));
    }
    return (s);
}

QNIO_API_(qnio_byte_t *)
kvset_marshal(const kvset_t * ps, int *s)
{
    int        size = 0;
    qnio_byte_t *b = NULL;
    qnio_byte_t *cursor = NULL;

    size = kvset_binary_pack_size(ps) + (MARSHALED_LENGTH_SZ + PS_MAGIC_SZ);
    b = (qnio_byte_t *)malloc(size);
    if (b)
    {
        cursor = b; /* b is return val, leave pointing to beginning of buffer */
        QNIO_UINT32_PACK(kvset_magic, cursor);
        QNIO_UINT32_PACK(size, cursor);
        kvset_binary_pack(cursor, ps);
    }
    else
    {
        size = 0;
    }
    if (s)
    {
        *s = size;
    }
    return (b);
}

static qnio_byte_t *
val_array_binary_unpack(qnio_byte_t *bs, value_array_t **val_array, uint32_t type)
{
    uint32_t          i;
    value_array_t    *va;
    uint32_t          count;
    property_value_t *pv;

    va = (value_array_t *)malloc(sizeof (value_array_t));
    /*
     * Get the count
     */
    QNIO_UINT32_UNPACK(count, bs);
    /*
     * Allocate space to hold count
     */
    va->val_array = new_qnio_vector(count, NULL);
    /*
     * Put the values
     */
    for (i = 0; i < count; i++)
    {
        bs = value_binary_unpack(bs, &pv, type);
        qnio_vector_pushback(va->val_array, pv);
    }
    *val_array = va;
    return (bs);
}

static qnio_byte_t *
value_binary_unpack(qnio_byte_t *bs, property_value_t **val, uint32_t type)
{
    int size;
    property_value_t *v;

    v = (property_value_t *)malloc(sizeof (property_value_t));
    *val = v;
    v->type = type;
    if (v->type & TYPE_ARRAY)
    {
        qnio_byte_t     *ret;
        value_array_t *va = (value_array_t *)(v->data);

        ret = val_array_binary_unpack(bs, &va, ((v->type) & (~TYPE_ARRAY)));
        v->data = va;
        return (ret);
    }
    switch (v->type)
    {
        case TYPE_STR:
            QNIO_UINT32_UNPACK(size, bs);
            v->size = size + 1;
            v->data = malloc(v->size);
            memcpy(v->data, bs, size);
            ((char *)v->data)[size] = '\0';
            bs += size;
            break;
        case TYPE_INT32:
        case TYPE_UINT32:
            {
                uint32_t x;

                v->size = QNIO_INT32_SZ;
                v->data = malloc(v->size);
                QNIO_UINT32_UNPACK(x, bs);
                *((uint32_t *)(v->data)) = x;
            }
            break;
        case TYPE_INT64:
        case TYPE_UINT64:
        case TYPE_TIME:
            {
                uint64_t x;

                v->size = QNIO_INT64_SZ;
                v->data = malloc(v->size);
                QNIO_UINT64_UNPACK(x, bs);
                *((uint64_t *)(v->data)) = x;
            }
            break;
        case TYPE_BOOLEAN:
            v->size = 1;
            v->data = malloc(sizeof (bool));
            *((bool *)(v->data)) = *bs;
            bs++;
            break;
        case TYPE_GUID:
            v->size = sizeof (qnio_guid_t);
            v->data = malloc(v->size);
            QNIO_GUID_UNPACK(v->data, bs);
            break;
        case TYPE_BINARY:
            QNIO_UINT32_UNPACK(size, bs);
            v->size = size;
            v->data = malloc(size);
            memcpy(v->data, bs, size);
            bs += size;
            break;
        case TYPE_PROPSET:
            {
                kvset_t *p;

                v->size = sizeof (kvset_t);
                bs = kvset_binary_unpack(bs, &p);
                v->data = p;
            }
            break;
    }
    return (bs);
}

static qnio_byte_t *
kv_binary_unpack(qnio_byte_t *bs, key_value_t **keyval)
{
    int size;
    key_value_t      *kv;
    uint32_t          type;
    property_value_t *v;

    kv = (key_value_t *)malloc(sizeof (key_value_t));

    /*
     * unpack the type
     */
    QNIO_UINT32_UNPACK(type, bs);

    /*
     * Get the size of the key
     */

    QNIO_UINT32_UNPACK(size, bs);

    /*
     * Get the key
     */
    kv->key = malloc(size + 1);
    memcpy(kv->key, bs, size);
    kv->key[size] = '\0';
    bs += size;

    /*
     * get the flags
     */
    QNIO_UINT32_UNPACK(kv->flags, bs);

    /*
     * Put the value
     */
    bs = value_binary_unpack(bs, &v, type);
    kv->data = v;
    *keyval = kv;
    return (bs);
}

static qnio_byte_t *
kvset_binary_unpack(qnio_byte_t *bs, kvset_t **p)
{
    int          i;
    int          s = 0;
    key_value_t *kv;
    key_value_t *tmp;
    int          j;

    QNIO_UINT32_UNPACK(s, bs);
    *p = new_ps(s);
    /*
     * Marshal the elements of the array
     */
    for (i = 0; i < (int)s; i++)
    {
        bs = kv_binary_unpack(bs, &kv);
        for (j = 0; j < qnio_vector_size((*p)->_properties); j++)
        {
            tmp = (key_value_t *)qnio_vector_at((*p)->_properties, j);
            if (strcmp(tmp->key, kv->key) < 0)
            {
                continue;
            }
            else
            {
                break;
            }
        }
        qnio_vector_insert((*p)->_properties, kv, j);
    }
    return (bs);
}

QNIO_API_(void) kvset_unmarshal(qnio_byte_t * bs, kvset_t * *p)
{
    uint32_t bs_len __attribute__((unused)) = 0;
    uint32_t magic __attribute__((unused)) = 0;

    /*
     * Validate magic signature and length
     */
    QNIO_UINT32_UNPACK(magic, bs);
    assert(magic == kvset_magic);

    QNIO_UINT32_UNPACK(bs_len, bs);

    /*
     * Unpack properties
     */
    kvset_binary_unpack(bs, p);
}

QNIO_API_(qnio_byte_t *) kvset_unmarshal_ex(qnio_byte_t * bs, kvset_t * *p)
{
    uint32_t   bs_len = 0;
    uint32_t   magic __attribute__((unused)) = 0;
    qnio_byte_t *next_ptr = NULL;
    qnio_byte_t *start = bs;

    /*
     * Validate magic signature
     */
    QNIO_UINT32_UNPACK(magic, bs);
    assert(magic == kvset_magic);

    /*
     * Find end of marshaled ps in byte stream
     */
    QNIO_UINT32_UNPACK(bs_len, bs);
    next_ptr = start + bs_len;

    /*
     * Unpack properties
     */
    kvset_binary_unpack(bs, p);

    /*
     * Return pointer to the next thing in the byte stream
     */
    return (next_ptr);
}

static void
val_array_print(qnio_stream *stream, int level, int type, const value_array_t *va)
{
    int        i;
    qnio_vector *vals = va->val_array;

    print_string(stream, STRING_LEVEL_VALUE, "[\n");
    for (i = 0; i < vals->_count; i++)
    {
        value_print(stream, level + 1,
                    (property_value_t *)(qnio_vector_at(vals, i)));
        if (i < vals->_count - 1)
        {
            print_string(stream, STRING_LEVEL_VALUE, ",\n");
        }
        else
        {
            print_string(stream, STRING_LEVEL_VALUE, "\n");
        }
    }
    print_string(stream, level, "]");
}

static void
value_print(qnio_stream *stream, int level, const property_value_t *v)
{
    char  buf[64];
    char *x;
    bool  b;
    int   dest_size;
    char *dest;

    if (v->type & TYPE_ARRAY)
    {
        val_array_print(stream, level, (v->type & ~TYPE_ARRAY),
                        (value_array_t *)(v->data));
        return;
    }
    switch (v->type)
    {
        case TYPE_STR:
            print_json_string(stream, STRING_LEVEL_VALUE, (char *)v->data);
            break;
        case TYPE_BOOLEAN:
            {
                b = *((bool *)(v->data));
                x = (char *)(b != 0 ? "True" : "False");
                print_string(stream, STRING_LEVEL_VALUE, "\"%s\"", x);
            }
            break;

        case TYPE_INT32:
            print_string(stream, STRING_LEVEL_VALUE, "%d",
                         *((int *)(v->data)));
            break;

        case TYPE_UINT32:
            print_string(stream, STRING_LEVEL_VALUE, "%u",
                         *((uint32_t *)(v->data)));
            break;
        case TYPE_INT64:
            print_string(stream, STRING_LEVEL_VALUE, "%l",
                         *((int64_t *)(v->data)));
            break;
        case TYPE_UINT64:
            print_string(stream, STRING_LEVEL_VALUE, "%lu",
                         *((uint64_t *)(v->data)));
            break;
        case TYPE_TIME:
            print_string(stream, STRING_LEVEL_VALUE, "%I64u",
                         *((uint64_t *)(v->data)));
            break;

        case TYPE_GUID:
            (void)guidtostr((qnio_guid_t *)v->data, buf);
            print_string(stream, STRING_LEVEL_VALUE, "\"%s\"", buf);
            break;
        case TYPE_BINARY:
            /*
             * Binary data is Base 64 encoded. The output is null terminated
             */
            dest_size = (((v->size + 2) / 3) * 4) + 1;
            dest = (char *)malloc(dest_size);
            base64_encode(dest, dest_size, v->data, v->size);
            print_string(stream, STRING_LEVEL_VALUE, "\"%s\"", dest);
            free(dest);
            break;
        case TYPE_PROPSET:
            kvset_print(stream, level + 1, (kvset_t *)(v->data));
            break;
    }
    return;
}

static void
kv_print(qnio_stream *stream, int level, const key_value_t *kv)
{
    print_string(stream, level + 1, "\"%s\" : ", kv->key);
    value_print(stream, level + 1, kv->data);
    return;
}


QNIO_API_(void) kvset_print(qnio_stream * stream, int level, const kvset_t * p)
{
    int        i;
    qnio_vector *props = p->_properties;

    print_string(stream, level + 1, "{\n");
    for (i = 0; i < props->_count; i++)
    {
        kv_print(stream, level + 1, (key_value_t *)(qnio_vector_at(props, i)));
        if (i < props->_count - 1)
        {
            print_string(stream, STRING_LEVEL_VALUE, ",\n");
        }
        else
        {
            print_string(stream, STRING_LEVEL_VALUE, "\n");
        }
    }
    print_string(stream, level, "}");
    return;
}

static kvset_t *convert_json_ps(cJSON *json_obj);

void
array_destructor(void *p)
{
    value_free((property_value_t *)p);
}

QNIO_API_(value_array_t)
new_array(cJSON * json_obj)
{
    value_array_t    va, inner_va;
    property_value_t pv, *ptr;
    kvset_t   *ps;

    va.type = 0;
    va.val_array = new_qnio_vector(0, NULL);

    while (json_obj != NULL)
    {
        ps = NULL;
        switch (json_obj->type)
        {
            case cJSON_Object:
                ps = convert_json_ps(json_obj->child);
                if (!va.type)
                {
                    va.type = TYPE_PROPSET | TYPE_ARRAY;
                }
                pv.type = TYPE_PROPSET;
                pv.data = ps;
                pv.size = sizeof (ps);
                break;

            case cJSON_String:
                if (!va.type)
                {
                    va.type = TYPE_STR | TYPE_ARRAY;
                }
                pv.type = TYPE_STR;
                pv.data = json_obj->valuestring;
                pv.size = (strlen(json_obj->valuestring) + 1);
                break;

            case cJSON_Number:
                if (!va.type)
                {
                    va.type = TYPE_UINT64 | TYPE_ARRAY;
                }
                pv.type = TYPE_UINT64;
                pv.data = &json_obj->valueuint64;
                pv.size = sizeof (uint64_t);
                break;

            case cJSON_False:
                if (!va.type)
                {
                    va.type = TYPE_STR | TYPE_ARRAY;
                }
                pv.type = TYPE_STR;
                pv.data = "F";
                pv.size = sizeof (char);
                break;

            case cJSON_True:
                if (!va.type)
                {
                    va.type = TYPE_STR | TYPE_ARRAY;
                }
                pv.type = TYPE_STR;
                pv.data = "T";
                pv.size = sizeof (char);
                break;

            /*
             *  Note: Array of arrays is not supported yet by design. So the
             *  below code does not work as expected.
             */
            case cJSON_Array:
                inner_va = new_array(json_obj->child);
                if (!va.type)
                {
                    va.type = TYPE_ARRAY;
                }
                pv.type = TYPE_ARRAY;
                pv.data = &inner_va;
                pv.size = sizeof (inner_va);
                break;

            /*
             * case cJSON_NULL:  This will go into default handling itself
             */
            default:
                if (!va.type)
                {
                    va.type = TYPE_STR | TYPE_ARRAY;
                }
                pv.type = TYPE_STR;
                pv.data = "";
                pv.size = 1;
                break;
        }
        ptr = value_copy(&pv);
        qnio_vector_pushback(va.val_array, ptr);
        if (ps)
        {
            kvset_free(ps);
        }
        json_obj = json_obj->next;
    }
    return (va);
}

static kvset_t *
convert_json_ps(cJSON *json_obj)
{
    kvset_t *tmp_ps = NULL, *inner_ps = NULL;
    key_value_t   *tmp_kv = NULL;
    value_array_t  va;

    tmp_ps = new_ps(0);

    while (json_obj != NULL)
    {
        switch (json_obj->type)
        {
            case cJSON_Object:
                inner_ps = convert_json_ps(json_obj->child);
                tmp_kv = new_kv(json_obj->string, 0,
                                TYPE_PROPSET, sizeof (inner_ps), inner_ps);
                kvset_add(tmp_ps, tmp_kv);

                kvset_free(inner_ps);

                break;

            case cJSON_String:
                tmp_kv = new_kv(json_obj->string, 0,
                                TYPE_STR, (strlen(json_obj->valuestring) + 1),
                                (void *)json_obj->valuestring);
                kvset_add(tmp_ps, tmp_kv);

                break;

            case cJSON_Number:
                tmp_kv = new_kv(json_obj->string, 0, TYPE_UINT64,
                                sizeof (uint64_t), &json_obj->valueuint64);
                kvset_add(tmp_ps, tmp_kv);
                break;

            case cJSON_False:
                tmp_kv = new_kv(json_obj->string, 0,
                                TYPE_STR, sizeof (char), "F");
                kvset_add(tmp_ps, tmp_kv);

                break;

            case cJSON_True:
                tmp_kv = new_kv(json_obj->string, 0,
                                TYPE_STR, sizeof (char), "T");
                kvset_add(tmp_ps, tmp_kv);

                break;

            case cJSON_Array:
                va = new_array(json_obj->child);
                tmp_kv =
                    new_kv(json_obj->string, 0, va.type, sizeof (value_array_t),
                           &va);
                kvset_add(tmp_ps, tmp_kv);
                qnio_vector_clear(va.val_array, array_destructor);
                qnio_vector_delete(va.val_array);

                break;

            /*
             * case cJSON_NULL:  This will go into default handling itself
             */
            default:
                tmp_kv = new_kv(json_obj->string, 0, TYPE_STR, 1, "");
                kvset_add(tmp_ps, tmp_kv);

                break;
        }

        json_obj = json_obj->next;
    }

    return (tmp_ps);
}

QNIO_API_(kvset_t *) parse_json(const char *data)
{
    kvset_t *ps = NULL;
    cJSON         *json_obj;

    json_obj = cJSON_Parse(data);
    if (json_obj != NULL)
    {
        if (json_obj->type == cJSON_Object && json_obj->child != NULL)
        {
            ps = convert_json_ps(json_obj->child);
        }
        else
        {
            ps = convert_json_ps(json_obj);
        }
        cJSON_Delete(json_obj);
    }
    return (ps);
}
