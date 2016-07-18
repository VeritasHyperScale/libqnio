/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef LIST_H
#define LIST_H    1


typedef struct list_head
{
    struct list_head *next;
    struct list_head *prev;
}list_t;
#define LIST_INIT(N)           ((N)->next = (N)->prev = (N))
#define LIST_HEAD_INIT(H)      struct list_head H = { &H, &H }
#define LIST_ENTRY(P, T, N)    ((T *)((char *)(P)-offsetof(T, N)))
#define    LIST_ADD(H, N)                      \
    do {                                \
        ((H)->next)->prev = (N);                \
        (N)->next = ((H)->next);                \
        (N)->prev = (H);                        \
        (H)->next = (N);                        \
    } while (0)

#define    LIST_TAIL(H, N)              \
    do {                                \
        ((H)->prev)->next = (N);                \
        (N)->prev = ((H)->prev);                \
        (N)->next = (H);                    \
        (H)->prev = (N);                    \
    } while (0)

#define    LIST_DEL(N)                            \
    do {                                \
        ((N)->next)->prev = ((N)->prev);            \
        ((N)->prev)->next = ((N)->next);            \
        LIST_INIT(N);                        \
    } while (0)

#define    LIST_EMPTY(N)          ((N)->next == (N))

#define    LIST_FOREACH(H, N)     for (N = (H)->next; N != (H); N = (N)->next)

#define    LIST_FOREACHR(H, N)    for (N = (H)->prev; N != (H); N = (N)->prev)

#define LIST_FOREACH_SAFE(H, N, T)                        \
    for (N = (H)->next, T = (N)->next; N != (H);            \
         N = (T), T = (N)->next)

#define LIST_FOREACHR_SAFE(H, N, T)                        \
    for (N = (H)->prev, T = (N)->prev; N != (H);            \
         N = (T), T = (N)->prev)

#define LIST_DEL_SAFE(N, T)                             \
    do {                                                \
        if ((N) == T) {                                 \
            T = T->next;                                \
        }                                               \
        LIST_DEL(N);                                    \
    } while (0)

#endif /* LIST_H */
