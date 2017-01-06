/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef UTILS_HEADER_DEFINED
#define UTILS_HEADER_DEFINED    1

void set_close_on_exec(int fd);
int make_socket_non_blocking(int sfd);
char *safe_strncpy(char *dest, const char *src, size_t n);
int compare_key(const void *x, const void *y);
int compare_int(const void *x, const void *y);

#endif /* UTILS_HEADER_DEFINED */
