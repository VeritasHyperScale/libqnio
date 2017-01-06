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
fifo_init(fifo_t *fifo)
{
    fifo->size = 0;
    fifo->head = fifo->tail = NULL;
}

QNIO_API_(void)
fifo_enqueue(fifo_t *fifo, void *value)
{
    fifo_node_t *node = (fifo_node_t *)malloc(sizeof(fifo_node_t));
    node->value = value;
    node->next = NULL;
    if (fifo->head == NULL)
    {
        fifo->head = node;
    }
    else
    {
        fifo->tail->next = node;
    }
    fifo->tail = node;
    fifo->size++;
}

QNIO_API_(void *)
fifo_dequeue(fifo_t *fifo)
{
    void *value = NULL;
    fifo_node_t* head = fifo->head;
    value = head->value;

    fifo->head = head->next;
    fifo->size--;
    free(head);

    return value;
}


QNIO_API_(void)
fifo_enqueue_node(fifo_t *fifo, fifo_node_t *node, void *value)
{
    node->value = value;
    node->next = NULL;
    if (fifo->head == NULL)
    {
        fifo->head = node;
    }
    else
    {
        fifo->tail->next = node;
    }
    fifo->tail = node;
    fifo->size++;
}

QNIO_API_(void *)
fifo_dequeue_node(fifo_t *fifo, fifo_node_t **garbage)
{
    void *value = NULL;
    fifo_node_t* head = fifo->head;

    if(head == NULL)
    {
        *garbage = NULL;
        return NULL;
    }

    value = head->value;
    fifo->head = head->next;
    fifo->size--;
    *garbage = head;
    return value;
}

QNIO_API_(void *)
fifo_first(fifo_t *fifo)
{
    return fifo->head->value;
}

QNIO_API_(int)
fifo_size(fifo_t *fifo)
{
    return fifo->size;
}
