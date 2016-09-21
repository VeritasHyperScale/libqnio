/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#ifndef _BASE_ERROR_H
#define _BASE_ERROR_H                   1

#define QNIOERROR_SUCCESS               0
#define QNIOERROR_DUPLICATE_KEY         1
#define QNIOERROR_NOT_FOUND             2
#define QNIOERROR_PROPERTY_MISMATCH     3
#define QNIOERROR_NO_PROPERTY           QNIOERROR_NOT_FOUND
#define QNIOERROR_NOCHANGE              4
#define QNIOERROR_INVALIDARG            5
#define QNIOERROR_VDISK_SIZE_INVALID    61
#define QNIOERROR_NOT_SUPPORTED         62

#endif
