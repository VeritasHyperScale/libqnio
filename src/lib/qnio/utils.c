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

int 
is_secure()
{
    if (access(SECURE_IMPL, F_OK) != 0)
    {
        nioDbg("Secure implementation not enabled\n");
        return 0;
    }
    return 1;
}

SSL_CTX *
init_server_ssl_ctx()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx = NULL;

    nioDbg("initializing server ssl ctx %s\n", SERVER_KEY);
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
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY, SSL_FILETYPE_PEM) < 0 ) 
    {
        nioDbg("Unable to use server key file");
        return NULL;
    }
    return ctx;
}

SSL_CTX *
init_client_ssl_ctx(char *instanceid)
{
    const SSL_METHOD *method;
    char clientkey[512] = { 0 };
    char clientcert[512] = { 0 };
    SSL_CTX *ctx = NULL;

    strcpy(clientkey, CLIENT_KEYSTORE);
    strncat(clientkey, instanceid, 64);
    strncat(clientkey, ".key", 4);

    if (access(clientkey, F_OK) != 0)
    {
        nioDbg("Client key not found");
        return NULL;
    }

    strcpy(clientcert, CLIENT_KEYSTORE);
    strncat(clientcert, instanceid, 64);
    strncat(clientcert, ".cert", 5);

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
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, clientkey, SSL_FILETYPE_PEM) < 0 ) 
    {
        nioDbg("Unable to use server key file");
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
