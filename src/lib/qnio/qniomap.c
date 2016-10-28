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

#define RB_SENTINEL    &aMap->sentinel /* all leafs are sentinels */

static void
rotate_left(qnio_map *aMap, qnio_rb_node *x)
{
    qnio_rb_node *y;

    y = x->right;
    x->right = y->left;
    if (y->left != RB_SENTINEL)
    {
        y->left->parent = x;
    }
    if (y != RB_SENTINEL)
    {
        y->parent = x->parent;
    }
    if (x->parent)
    {
        if (x == x->parent->left)
        {
            x->parent->left = y;
        }
        else
        {
            x->parent->right = y;
        }
    }
    else
    {
        aMap->root = y;
    }
    y->left = x;
    if (x != RB_SENTINEL)
    {
        x->parent = y;
    }
}

static void
rotate_right(qnio_map *aMap, qnio_rb_node *x)
{
    qnio_rb_node *y = x->left;

    x->left = y->right;
    if (y->right != RB_SENTINEL)
    {
        y->right->parent = x;
    }
    if (y != RB_SENTINEL)
    {
        y->parent = x->parent;
    }
    if (x->parent)
    {
        if (x == x->parent->right)
        {
            x->parent->right = y;
        }
        else
        {
            x->parent->left = y;
        }
    }
    else
    {
        aMap->root = y;
    }
    y->right = x;
    if (x != RB_SENTINEL)
    {
        x->parent = y;
    }
}

static void
rebalance_on_insert(qnio_map *aMap, qnio_rb_node *x)
{
    /*
     * check Red-Black properties
     */
    while (x != aMap->root && x->parent->color == RB_NODE_RED)
    {
        /*
         * we have a violation
         */
        if (x->parent == x->parent->parent->left)
        {
            qnio_rb_node *y = x->parent->parent->right;
            if (y->color == RB_NODE_RED)
            {
                /*
                 * uncle is RB_NODE_RED
                 */
                x->parent->color = RB_NODE_BLACK;
                y->color = RB_NODE_BLACK;
                x->parent->parent->color = RB_NODE_RED;
                x = x->parent->parent;
            }
            else
            {
                /*
                 * uncle is RB_NODE_BLACK
                 */
                if (x == x->parent->right)
                {
                    x = x->parent;
                    rotate_left(aMap, x);
                }
                x->parent->color = RB_NODE_BLACK;
                x->parent->parent->color = RB_NODE_RED;
                rotate_right(aMap, x->parent->parent);
            }
        }
        else
        {
            /*
             * mirror image of above code
             */
            qnio_rb_node *y = x->parent->parent->left;
            if (y->color == RB_NODE_RED)
            {
                /*
                 * uncle is RB_NODE_RED
                 */
                x->parent->color = RB_NODE_BLACK;
                y->color = RB_NODE_BLACK;
                x->parent->parent->color = RB_NODE_RED;
                x = x->parent->parent;
            }
            else
            {
                /*
                 * uncle is RB_NODE_BLACK
                 */
                if (x == x->parent->left)
                {
                    x = x->parent;
                    rotate_right(aMap, x);
                }
                x->parent->color = RB_NODE_BLACK;
                x->parent->parent->color = RB_NODE_RED;
                rotate_left(aMap, x->parent->parent);
            }
        }
    }
    aMap->root->color = RB_NODE_BLACK;
}

QNIO_API_(int)
qnio_map_insert(qnio_map * aMap, void *key, void *value)
{
    qnio_rb_node *current, *parent, *x;
    int         c;

    /*
     * find future parent
     */
    current = aMap->root;
    parent = 0;
    while (current != RB_SENTINEL)
    {
        c = aMap->cmp(key, current->kv.key);
        if (c == 0)
        {
            return (QNIOERROR_DUPLICATE_KEY);
        }
        parent = current;
        current = c < 0 ? current->left : current->right;
    }

    /*
     * setup new node
     */
    x = malloc(sizeof (qnio_rb_node));
    x->parent = parent;
    x->left = RB_SENTINEL;
    x->right = RB_SENTINEL;
    x->color = RB_NODE_RED;
    x->kv.key = key;
    x->kv.value = value;
    /*
     * insert node in tree
     */
    if (parent)
    {
        if (aMap->cmp(key, parent->kv.key) < 0)
        {
            parent->left = x;
        }
        else
        {
            parent->right = x;
        }
    }
    else
    {
        aMap->root = x;
    }
    rebalance_on_insert(aMap, x);
    aMap->count++;
    return (0);
}

static void
rebalance_on_delete(qnio_map *aMap, qnio_rb_node *x)
{
    while (x != aMap->root && x->color == RB_NODE_BLACK)
    {
        if (x == x->parent->left)
        {
            qnio_rb_node *w = x->parent->right;
            if (w->color == RB_NODE_RED)
            {
                w->color = RB_NODE_BLACK;
                x->parent->color = RB_NODE_RED;
                rotate_left(aMap, x->parent);
                w = x->parent->right;
            }
            if (w->left->color == RB_NODE_BLACK
                && w->right->color == RB_NODE_BLACK)
            {
                w->color = RB_NODE_RED;
                x = x->parent;
            }
            else
            {
                if (w->right->color == RB_NODE_BLACK)
                {
                    w->left->color = RB_NODE_BLACK;
                    w->color = RB_NODE_RED;
                    rotate_right(aMap, w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = RB_NODE_BLACK;
                w->right->color = RB_NODE_BLACK;
                rotate_left(aMap, x->parent);
                x = aMap->root;
            }
        }
        else
        {
            qnio_rb_node *w = x->parent->left;
            if (w->color == RB_NODE_RED)
            {
                w->color = RB_NODE_BLACK;
                x->parent->color = RB_NODE_RED;
                rotate_right(aMap, x->parent);
                w = x->parent->left;
            }
            if (w->right->color == RB_NODE_BLACK
                && w->left->color == RB_NODE_BLACK)
            {
                w->color = RB_NODE_RED;
                x = x->parent;
            }
            else
            {
                if (w->left->color == RB_NODE_BLACK)
                {
                    w->right->color = RB_NODE_BLACK;
                    w->color = RB_NODE_RED;
                    rotate_left(aMap, w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = RB_NODE_BLACK;
                w->left->color = RB_NODE_BLACK;
                rotate_right(aMap, x->parent);
                x = aMap->root;
            }
        }
    }
    x->color = RB_NODE_BLACK;
}

static qnio_rb_node *
qnio_map_remove_from_tree(qnio_map *aMap, qnio_rb_node *z)
{
    qnio_rb_node *x, *y;
    void       *tmp;

    if (z->left == RB_SENTINEL || z->right == RB_SENTINEL)
    {
        /*
         * y has a RB_SENTINEL node as a child
         */
        y = z;
    }
    else
    {
        /*
         * find tree successor with a RB_SENTINEL node as a child
         */
        y = z->right;
        while (y->left != RB_SENTINEL)
        {
            y = y->left;
        }
    }
    /*
     * x is y's only child
     */
    if (y->left != RB_SENTINEL)
    {
        x = y->left;
    }
    else
    {
        x = y->right;
    }
    /*
     * remove y from the parent chain
     */
    x->parent = y->parent;
    if (y->parent)
    {
        if (y == y->parent->left)
        {
            y->parent->left = x;
        }
        else
        {
            y->parent->right = x;
        }
    }
    else
    {
        aMap->root = x;
    }
    if (y != z)
    {
        /*
         * Since we are swapping y and z we need
         * to save of z's pair in y so that it
         * can be freed
         */
        tmp = z->kv.key;
        z->kv.key = y->kv.key;
        y->kv.key = tmp;
        tmp = z->kv.value;
        z->kv.value = y->kv.value;
        y->kv.value = tmp;
    }
    if (y->color == RB_NODE_BLACK)
    {
        rebalance_on_delete(aMap, x);
    }
    aMap->count--;
    return (y);
}

static qnio_rb_node *
qnio_map_delete_internal(qnio_map *aMap, const void *key)
{
    qnio_rb_node *z;

    /*
     * find node in tree
     */
    z = aMap->root;
    while (z != RB_SENTINEL)
    {
        if (aMap->cmp(key, z->kv.key) == 0)
        {
            break;
        }
        else
        {
            z = (aMap->cmp(key, z->kv.key) < 0) ? z->left : z->right;
        }
    }
    if (z == RB_SENTINEL)
    {
        return (NULL);
    }
    return (qnio_map_remove_from_tree(aMap, z));
}

QNIO_API_(qnio_map *)
new_qnio_map(qnio_compare cmp, qnio_destructor key_delete, qnio_destructor val_delete)
{
    qnio_map *aMap;

    aMap = (qnio_map *)malloc(sizeof (qnio_map));

    aMap->sentinel.left = RB_SENTINEL;
    aMap->sentinel.right = RB_SENTINEL;
    aMap->sentinel.color = RB_NODE_BLACK;
    aMap->sentinel.parent = NULL;
    aMap->sentinel.kv.key = NULL;
    aMap->sentinel.kv.value = NULL;
    aMap->root = RB_SENTINEL;
    aMap->cmp = cmp;
    aMap->key_d = key_delete;
    aMap->val_d = val_delete;
    aMap->type = QNIO_MAP;
    aMap->count = 0;
    return (aMap);
}

QNIO_API_(int) qnio_map_size(const qnio_map * aMap)
{
    return (aMap->count);
}

QNIO_API_(int) qnio_map_delete(qnio_map * aMap, const void *key)
{
    qnio_rb_node *x = qnio_map_delete_internal(aMap, key);

    if (!x)
    {
        return (QNIOERROR_NOT_FOUND);
    }
    if (aMap->key_d)
    {
        aMap->key_d(x->kv.key);
    }
    if (aMap->val_d)
    {
        if (aMap->type == QNIO_MAP)
        {
            aMap->val_d(x->kv.value);
        }
    }
    free(x);
    return (0);
}

QNIO_API_(void *) qnio_map_find(const qnio_map * aMap, const void *key)
{
    qnio_rb_node *current = aMap->root;
    int         c;

    while (current != RB_SENTINEL)
    {
        c = aMap->cmp(key, current->kv.key);
        if (c == 0)
        {
            return (current->kv.value);
        }
        else
        {
            current = c < 0 ? current->left : current->right;
        }
    }
    return (NULL);
}

QNIO_API_(void) qnio_map_free(qnio_map *aMap)
{
    assert(aMap->count == 0);
    free(aMap);
}
