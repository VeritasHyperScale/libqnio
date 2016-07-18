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
slab_init(slab_t *slab, uint32_t size, uint32_t alloc_size, 
          size_t alignment, void * (*fptr) (void *))
{
    int i;
    void *entry = NULL;
    fifo_node_t *node = NULL;

    ck_spinlock_init(&slab->slock);
    fifo_init(&slab->data);
    fifo_init(&slab->nodes);
    slab->alloc_size = alloc_size;
    slab->size = size;
    slab->alignment = alignment;
    slab->init_fptr = fptr;

    for(i=0;i<size;i++)
    {
        if(fptr != NULL)
            entry = fptr(NULL);
        else if(alignment != 0)
            posix_memalign(&entry, alignment, alloc_size);
        else
            entry = malloc(alloc_size);
        node = (fifo_node_t *) malloc(sizeof(fifo_node_t));
        fifo_enqueue_node(&slab->data, node, entry);
    }
}

QNIO_API_(void)
slab_put(slab_t *slab, void *entry)
{
    fifo_node_t *node;
    ck_spinlock_lock(&slab->slock);
    fifo_dequeue_node(&slab->nodes, &node);
    node->value = entry;
    fifo_enqueue_node(&slab->data, node, entry);
    ck_spinlock_unlock(&slab->slock);
}

QNIO_API_(void *)
slab_get(slab_t *slab)
{
    void *entry = NULL;
    fifo_node_t *node;

    ck_spinlock_lock(&slab->slock);
    if(fifo_size(&slab->data) > 0)
    {
        entry = fifo_dequeue_node(&slab->data, &node);
        fifo_enqueue_node(&slab->nodes, node, NULL);
    }
    else
    {
        if(slab->init_fptr != NULL)
            entry = slab->init_fptr(NULL);
        else if(slab->alignment != 0)
            posix_memalign(&entry, slab->alignment, slab->alloc_size);
        else
            entry = malloc(slab->alloc_size);
        node = (fifo_node_t *) malloc(sizeof(fifo_node_t));
        fifo_enqueue_node(&slab->nodes, node, NULL);
    }
    ck_spinlock_unlock(&slab->slock);

    return entry;
}

QNIO_API_(void)
slab_put_unsafe(slab_t *slab, void *entry)
{
    fifo_node_t *node;
    fifo_dequeue_node(&slab->nodes, &node);
    node->value = entry;
    fifo_enqueue_node(&slab->data, node, entry);
}

QNIO_API_(void *)
slab_get_unsafe(slab_t *slab)
{
    void *entry = NULL;
    fifo_node_t *node;

    if(fifo_size(&slab->data) > 0)
    {
        entry = fifo_dequeue_node(&slab->data, &node);
        fifo_enqueue_node(&slab->nodes, node, NULL);
    }
    else
    {
        if(slab->alignment != 0)
            posix_memalign(&entry, slab->alignment, slab->alloc_size);
        else
            entry = malloc(slab->alloc_size);
        node = (fifo_node_t *) malloc(sizeof(fifo_node_t));
        fifo_enqueue_node(&slab->nodes, node, NULL);
    }

    return entry;
}


QNIO_API_(void)
slab_free(slab_t *slab)
{
    void *entry = NULL;
    fifo_node_t *node;

    if(slab == NULL)
    {
        return;
    }

    while(fifo_size(&slab->data) > 0)
    {
        /*
         * It is ok if we don't protect the fifo_size call since even 
         * if size is dirty read with actual value as zero, 
         * fifo_dequeue will return null which is handled 
         * by subsequent free call.
         * TODO: Remove/replace spinlock with less contentious option
         */
        ck_spinlock_lock(&slab->slock);
        entry = fifo_dequeue_node(&slab->data, &node);
        ck_spinlock_unlock(&slab->slock);

        if(entry)
            free(entry);
        if(node)
            free(node);
    }
}
