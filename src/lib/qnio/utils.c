/*
 * Network IO library for VxHS QEMU block driver (Veritas Technologies)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2014-08-15 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "defs.h"
#include "qnio.h"

SSL_CTX *
init_server_ssl_ctx()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;

    nioDbg("initializing server ssl ctx with key %s, cert %s\n",
           SERVER_KEY, SERVER_CERT);

    if (access(SERVER_KEY, F_OK) != 0)
    {
        nioDbg("Server key not found");
        return NULL;
    }

    if (access(SERVER_CERT, F_OK) != 0)
    {
        nioDbg("Server cert not found");
        return NULL;
    }

    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) 
    {
        nioDbg("Unable to create SSL context");
        return NULL;
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT, SSL_FILETYPE_PEM) < 0) 
    {
        nioDbg("Unable to use server certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) < 0 ) 
    {
        nioDbg("Unable to use server key file");
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/*
 * None of the arguments can be NULL
 */
SSL_CTX *
init_client_ssl_ctx(const char *cacert, const char *clientkey,
             const char *clientcert)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;

    if (access(cacert, F_OK) != 0)
    {
        nioDbg("cacert not found %s", cacert);
        return NULL;
    }

    if (access(clientkey, F_OK) != 0)
    {
        nioDbg("Client key not found %s", clientkey);
        return NULL;
    }

    if (access(clientcert, F_OK) != 0)
    {
        nioDbg("Client cert not found");
        return NULL;
    }

    SSL_load_error_strings();   
    OpenSSL_add_ssl_algorithms();
    method = SSLv23_client_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) 
    {
        nioDbg("Unable to create client SSL context");
        return NULL;
    }

    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, clientcert, SSL_FILETYPE_PEM) < 0) 
    {
        nioDbg("Unable to use client certificate");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, clientkey, SSL_FILETYPE_PEM) < 0) 
    {
        nioDbg("Unable to use client key file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_load_verify_locations(ctx, cacert, NULL) < 0)
    {
        nioDbg("Unable to use client cacert file");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

void
set_close_on_exec(int fd)
{
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
}

int
make_socket_non_blocking(int sfd)
{
    int flags, s;
    int nodelay = 1;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        nioDbg("fcntl error");
        return (-1);
    }
    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        nioDbg("fcntl error");
        return (-1);
    }
    setsockopt(sfd, SOL_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    return (0);
}

/*
 * Make sure string is always NULL terminated.
 */
char *
safe_strncpy(char *dest, const char *src, size_t n)
{
    char *cp;

    cp = strncpy(dest, src, n);
    dest[n-1] = '\0';
    return cp;
}

int
compare_key(const void *x, const void *y)
{
    return (strcmp((const char *)x, (const char *)y));
}

int
compare_int(const void *x, const void *y)
{
    return ((*(int *)x) - (*(int *)y));
}
