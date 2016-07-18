/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef _BASE_BASE64_H
#define _BASE_BASE64_H    1

#include "types.h"

QNIO_API_(int)
base64_encode(char *dest, int destlen, const void *src, int srclen);

QNIO_API_(int)
base64_decode(void *dest, int destlen, const char *src, int srclen);

#endif
