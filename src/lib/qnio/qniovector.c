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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "datastruct.h"

QNIO_API_(void *)
qnio_vector_at(const qnio_vector * va, int idx)
{
    if (idx < va->_max) {
        return (va->_array[idx]);
    } else {
        return NULL;
    }        
}

QNIO_API_(void) qnio_vector_insert(qnio_vector * va, void *data, int idx)
{
    int tmp = va->_max * 2;

    if (va->_count == va->_max)
    {
        if (va->_max == 0)
        {
            va->_array = (void **)malloc(sizeof (void *) * 8);
            tmp = 8;
        }
        else
        {
            va->_array =
                (void **)realloc(va->_array, sizeof (void *) * tmp);
        }
        va->_max = tmp;
    }
    memmove(&(va->_array[idx + 1]),
            &(va->_array[idx]), (va->_count - idx) * sizeof (void *));
    va->_array[idx] = data;
    va->_count++;
}

QNIO_API_(void *)
qnio_vector_remove(qnio_vector * va, int idx)
{
    void *tmp;

    tmp = va->_array[idx];
    memmove(&(va->_array[idx]),
            &(va->_array[idx + 1]), (va->_count - idx - 1) * sizeof (void *));
    va->_array[(va->_count) - 1] = NULL;
    va->_count--;
    return (tmp);
}

QNIO_API_(int) qnio_vector_size(const qnio_vector * va)
{
    return (va->_count);
}

QNIO_API_(void)
qnio_vector_foreach(const qnio_vector * va, qnio_foreach fn, void *ctx)
{
    int i;

    for (i = 0; i < va->_count; i++)
    {
        fn(va->_array[i], ctx);
    }
}

QNIO_API_(void)
qnio_vector_clear(qnio_vector * va, qnio_destructor fn)
{
    int i;

    if (va->_count)
    {
        if (fn)
        {
            for (i = 0; i < va->_count; i++)
            {
                fn(va->_array[i]);
            }
        }
        i = va->_count;
        va->_count = 0;
        memset(va->_array, 0, sizeof (void *) * i);
    }
}


QNIO_API_(void)
qnio_vector_delete(qnio_vector * va)
{
    if (va->_array)
    {
        free(va->_array);
    }
    free(va);
}

QNIO_API_(void)
qnio_vector_destroy(qnio_vector * va)
{
    /*
     * _dtor may be NULL in some cases
     */
    if (va->_dtor)
    {
        qnio_vector_clear(va, va->_dtor);
    }
    qnio_vector_delete(va);
}

QNIO_API_(qnio_vector *) new_qnio_vector(int size, qnio_destructor fn)
{
    qnio_vector *vec;

    size = size < 8 ? 8 : size;
    vec = (qnio_vector *)malloc(sizeof (qnio_vector));
    memset(vec, 0, sizeof (qnio_vector));
    vec->_array = (void **)malloc(sizeof (void *) * size);
    memset(vec->_array, 0, (sizeof (void *) * size));
    vec->_max = size;
    vec->_dtor = fn;
    return (vec);
}

QNIO_API_(void) qnio_vector_pushback(qnio_vector * va, void *data)
{
    int tmp = va->_max * 2;

    if (va->_count == va->_max)
    {
        va->_array = (void **)realloc(va->_array, sizeof (void *) * tmp);
        va->_max = tmp;
    }
    va->_array[va->_count] = data;
    va->_count++;
}

QNIO_API_(void *)
qnio_vector_popback(qnio_vector * va)
{
    return (qnio_vector_remove(va, (va->_count) - 1));
}

QNIO_API_(void *) qnio_vector_popfront(qnio_vector * vec)
{
    return (qnio_vector_remove(vec, 0));
}

QNIO_API_(void) qnio_vector_pushfront(qnio_vector * va, void *data)
{
    qnio_vector_insert(va, data, 0);
}


QNIO_API_(int)
qnio_vector_find_sorted(const qnio_vector * va, qnio_compare cmp, const void *key)
{
    int   low = 0;
    int   high;
    int   middle;
    void *kv;
    int   x;

    high = va->_count - 1;

    while (low <= high)
    {
        middle = (int)((low + high) / 2);
        kv = qnio_vector_at(va, middle);
        x = cmp(key, kv);
        if (x == 0)
        {
            return (middle);
        }
        else if (x < 0)
        {
            high = middle - 1;
        }
        else
        {
            low = middle + 1;
        }
    }
    return (-1);
}
