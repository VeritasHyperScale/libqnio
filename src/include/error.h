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
#define _BASE_ERROR_H                     1

#define QNIOERROR_SUCCESS                   0
#define QNIOERROR_DUPLICATE_KEY             1                 /* Duplicate key */
#define QNIOERROR_NOT_FOUND                 2                 /* Resource is not
                                                             * found */
#define QNIOERROR_PROPERTY_MISMATCH         3                 /* Update did not
                                                             * give the right
                                                             * type */
#define QNIOERROR_NO_PROPERTY               QNIOERROR_NOT_FOUND /* Key not found
                                                            **/
#define QNIOERROR_NOCHANGE                  4                 /* Routine resulted
                                                             * in no change
                                                             **/
#define QNIOERROR_INVALIDARG                5                 /* Bad arguments to
                                                             * the function
                                                             **/
#define QNIOERROR_VDISK_SIZE_INVALID        61
#define QNIOERROR_NOT_SUPPORTED             62

#define QNIOERROR_HUP                       901
#define QNIOERROR_NOCONN                    902
#define QNIOERROR_CHANNEL_HUP               903

#endif
