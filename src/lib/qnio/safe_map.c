/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "datastruct.h"

int
cmp_int(const void *x, const void *y)
{
    if (*(int *) x > *(int *) y)
        return 1;
    if (*(int *) x < *(int *) y)
        return -1;
    return 0;
}

QNIO_API_(void)
safe_map_init(safe_map_t *map)
{
    ck_spinlock_init(&map->mlock);
    map->dmap = new_qnio_map(cmp_int, free, free);
}

QNIO_API_(void)
safe_map_insert(safe_map_t *map, int key, void *value)
{
    int *keyptr;
    ck_spinlock_lock(&map->mlock);
    keyptr = (int *) malloc(sizeof(int));
    *keyptr = key;
    if(qnio_map_insert(map->dmap, keyptr, value) != QNIOERROR_SUCCESS)
    {
        free(keyptr);
    }
    ck_spinlock_unlock(&map->mlock);
}

QNIO_API_(void)
safe_map_delete(safe_map_t *map, int key)
{
    ck_spinlock_lock(&map->mlock);
    qnio_map_delete(map->dmap, &key);
    ck_spinlock_unlock(&map->mlock);
}

QNIO_API_(void *)
safe_map_find(safe_map_t *map, int key)
{
    void *entry;
    ck_spinlock_lock(&map->mlock);
    entry = qnio_map_find(map->dmap, &key);
    ck_spinlock_unlock(&map->mlock);

    return entry;
}

QNIO_API_(void)
safe_map_free(safe_map_t *map)
{
    qnio_map_free(map->dmap);
}
