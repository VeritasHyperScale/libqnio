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

QNIO_API_(void)
safe_fifo_init(safe_fifo_t *fifo)
{
    ck_spinlock_init(&fifo->slock);
    fifo_init(&fifo->data);
    slab_init(&fifo->nodes, MAX_SAFE_FIFO_NODES, sizeof(fifo_node_t), 0, NULL);
}

QNIO_API_(void)
safe_fifo_enqueue(safe_fifo_t *fifo, void *entry)
{
    fifo_node_t *node = NULL;
    ck_spinlock_lock(&fifo->slock);
    node = slab_get(&fifo->nodes);
    fifo_enqueue_node(&fifo->data, node, entry);
    ck_spinlock_unlock(&fifo->slock);
}

QNIO_API_(void *)
safe_fifo_dequeue2(safe_fifo_t *fifo) 
{
    void *entry = NULL;
    fifo_node_t *node = NULL;

    ck_spinlock_lock(&fifo->slock);
    entry = fifo_dequeue_node(&fifo->data,&node);
    if(entry)
        slab_put(&fifo->nodes,node);
    ck_spinlock_unlock(&fifo->slock);

    return entry;
}

QNIO_API_(void *)
safe_fifo_dequeue(safe_fifo_t *fifo)
{
    void *entry = NULL;
    fifo_node_t *node = NULL;

    ck_spinlock_lock(&fifo->slock);
    entry = fifo_dequeue_node(&fifo->data, &node);
    slab_put(&fifo->nodes, node);
    ck_spinlock_unlock(&fifo->slock);

    return entry;
}

QNIO_API_(void *)
safe_fifo_first2(safe_fifo_t *fifo) {
    void *entry = NULL;

    ck_spinlock_lock(&fifo->slock);
    if(fifo->data.head)
        entry = fifo_first(&fifo->data);
    ck_spinlock_unlock(&fifo->slock);

    return entry;
}

QNIO_API_(void *)
safe_fifo_first(safe_fifo_t *fifo)
{
    void *entry = NULL;

    ck_spinlock_lock(&fifo->slock);
    entry = fifo_first(&fifo->data);
    ck_spinlock_unlock(&fifo->slock);

    return entry;
}

QNIO_API_(int)
safe_fifo_size(safe_fifo_t *fifo)
{
    int size = 0;

    ck_spinlock_lock(&fifo->slock);
    size = fifo_size(&fifo->data);
    ck_spinlock_unlock(&fifo->slock);

    return size;
}

QNIO_API_(void)
safe_fifo_free(safe_fifo_t *fifo)
{
    ck_spinlock_lock(&fifo->slock);
    slab_free(&fifo->nodes);
    ck_spinlock_unlock(&fifo->slock);
}
