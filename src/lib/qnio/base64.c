/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "types.h"

static char _base64[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
    'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

/**
 * Encodes source data into base64 format and stores result in 'dest'.
 * The base64 string is null terminated. Returns the length of encoded
 * bytes, -1 in case of error.
 */
QNIO_API_(int)
base64_encode(char *dest, int destlen, const void *src, int srclen)
{
    unsigned char        c1, c2;
    char                *to = dest;
    const unsigned char *from = (unsigned char *)src;

    /*
     * The length including terminating null character
     */
    int reqlen = ((srclen + 2) / 3) * 4 + 1;

    if (destlen < reqlen)
    {
        return (-1);
    }
    while (srclen > 0)
    {
        c1 = *from++;
        srclen--;
        /*
         * The first character
         */
        *to++ = _base64[c1 >> 2];

        c1 = (c1 << 4) & 0x30;
        /*
         * Padding with 2 '=' if srclen mod 3 is 2
         */
        if (srclen <= 0)
        {
            *to++ = _base64[c1];
            *to++ = '=';
            *to++ = '=';
            break;
        }
        c2 = *from++;
        srclen--;
        c1 |= (c2 >> 4) & 0x0f;
        /*
         * The second character
         */
        *to++ = _base64[c1];

        c1 = (c2 << 2) & 0x3f;
        /*
         * Padding with a '=' if srclen mod 3 is 1
         */
        if (srclen <= 0)
        {
            *to++ = _base64[c1];
            *to++ = '=';
            break;
        }
        c2 = *from++;
        srclen--;
        c1 |= (c2 >> 6) & 0x03;
        /*
         * 3rd and 4th characters
         */
        *to++ = _base64[c1];
        *to++ = _base64[c2 & 0x3f];
    }

    *to = '\0';

    return (to - dest);
}

static const char _index64[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};

/**
 * Decodes base64 data to raw bytes and store it in 'dest'.
 * Returns the length of bytes decoded, -1 if error occurs.
 */
QNIO_API_(int)
base64_decode(void *dest, int destlen, const char *src, int srclen)
{
    const unsigned char *p, *q;
    unsigned char       *t;
    int c1, c2;

    /*
     * Remove all beginning and trailing space
     */
    for (p = (const unsigned char *)src; srclen > 0 && isspace(*p);
         p++, srclen--)
    {
    }
    for (q = p + srclen - 1; q >= p && isspace(*q); q--, srclen--)
    {
    }
    if (((srclen / 4) * 3) > destlen)
    {
        return (-1);
    }
    t = (unsigned char *)dest;

    while (srclen > 0)
    {
        srclen -= 4;
        if (*p >= 128 || (c1 = _index64[*p++]) == -1)
        {
            return (-1);
        }
        if (*p >= 128 || (c2 = _index64[*p++]) == -1)
        {
            return (-1);
        }
        /*
         * First decoded byte
         */
        *t++ = (c1 << 2) | ((c2 & 0x30) >> 4);
        if (p[0] == '=' && p[1] == '=')
        {
            break;
        }
        if (*p >= 128 || (c1 = _index64[*p++]) == -1)
        {
            return (-1);
        }
        /*
         * Second decoded byte
         */
        *t++ = ((c2 << 4) & 0xf0) | ((c1 & 0x3c) >> 2);
        if (p[0] == '=')
        {
            break;
        }
        if (*p >= 128 || (c2 = _index64[*p++]) == -1)
        {
            return (-1);
        }
        /*
         * Third decoded byte
         */
        *t++ = ((c1 << 6) & 0xc0) | c2;
    }
    return (t - (unsigned char *)dest);
}
