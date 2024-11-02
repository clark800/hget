#define _POSIX_C_SOURCE 200112L
#define _GNU_SOURCE   // sometimes needed for fopencookie (e.g. musl)
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <tls.h>
#include "shim.h"
#include "tls.h"

static int isdir(const char* path) {
    // "If the named file is a symbolic link, the stat() function shall
    // continue pathname resolution using the contents of the symbolic link,
    // and shall return information pertaining to the resulting file if the
    // file exists."
    // (https://pubs.opengroup.org/onlinepubs/000095399/functions/stat.html)
    struct stat sb;
    return path != NULL && stat(path, &sb) == 0 && S_ISDIR(sb.st_mode);
}

static void fail(const char* message, struct tls* tls) {
    fputs(message, stderr);
    if (tls) {
        fputs(": ", stderr);
        fputs(tls_error(tls), stderr);
    }
    fputs("\n", stderr);
    exit(1);
}

static ssize_t read_tls(void* tls, char* buf, size_t len) {
    while (1) {
        ssize_t n = tls_read((struct tls*)tls, buf, len);
        if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT)
            continue;
        if (n < 0)
            fail("read error", tls);
        return n;
    }
}

static ssize_t write_tls(void* tls, const char* buf, size_t len) {
    ssize_t n = 0;
    for (size_t i = 0; i < len; i += n) {
        n = tls_write((struct tls*)tls, (const char*)buf + i, len - i);
        if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT)
            n = 0;      // try again
        else if (n < 0)
            fail("write error", tls);
    }
    return n;
}

static struct tls* new_tls_client(const char* cacerts, const char* cert,
        const char* key, int insecure) {
    struct tls_config* tls_config = tls_config_new();
    if (!tls_config)
        fail("failed to create tls config", NULL);
    if (insecure) {
        tls_config_insecure_noverifycert(tls_config);
        tls_config_insecure_noverifyname(tls_config);
        tls_config_insecure_noverifytime(tls_config);
    } else if (cacerts) {
        if (isdir(cacerts)) {
            if (tls_config_set_ca_path(tls_config, cacerts) != 0)
                fail("failed to set CA directory", NULL);
        } else if (tls_config_set_ca_file(tls_config, cacerts) != 0)
            fail("failed to load CA bundle", NULL);
    }
    if (cert && key)
        if (tls_config_set_keypair_file(tls_config, cert, key) != 0)
            fail("failed to load client certificate and/or private key", NULL);

    struct tls* tls = tls_client();
    if (!tls)
        fail("failed to create tls client", NULL);
    if (tls_configure(tls, tls_config) != 0)
        fail("tls_configure", tls);
    tls_config_free(tls_config);
    return tls;
}

static int end_tls(void* tls) {
    if (tls) {
        // ignore errors (not all servers close properly)
        tls_close((struct tls*)tls);
        tls_free((struct tls*)tls);
    }
    return 0;
}

static FILE* fopentls(struct tls* tls) {
    return fopencookie(tls, "r+",
        (cookie_io_functions_t){read_tls, write_tls, NULL, end_tls});
}

static ssize_t reader(struct tls *tls, void *buf, size_t n, void *sock) {
    (void)tls;
    return fread(buf, 1, n, sock);
}

static ssize_t writer(struct tls *tls, const void *buf, size_t n, void *sock) {
    (void)tls;
    return fwrite(buf, 1, n, sock);
}

FILE* wrap_tls(FILE* sock, const char* host, const char* cacerts,
        const char* cert, const char* key, int insecure) {
    struct tls* tls = new_tls_client(cacerts, cert, key, insecure);
    if (tls_connect_cbs(tls, reader, writer, sock, host) != 0)
        fail("tls_connect_cbs", tls);
    return fopentls(tls);
}

FILE* start_tls(int sock, const char* host, const char* cacerts,
        const char* cert, const char* key, int insecure) {
    struct tls* tls = new_tls_client(cacerts, cert, key, insecure);
    if (tls_connect_socket(tls, sock, host) != 0)
        fail("tls_connect_socket", tls);
    return fopentls(tls);
}
