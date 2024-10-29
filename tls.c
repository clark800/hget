#define _GNU_SOURCE   // sometimes needed for fopencookie (e.g. musl)
#include <stdio.h>
#include <stdlib.h>
#include <tls.h>
#include "shim.h"
#include "tls.h"

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

static void* start_tls(int sock, const char* host, const char* cacerts,
        int insecure) {
    struct tls_config* tls_config = tls_config_new();
    if (!tls_config)
        fail("failed to create tls config", NULL);
    if (insecure) {
        tls_config_insecure_noverifycert(tls_config);
        tls_config_insecure_noverifyname(tls_config);
        tls_config_insecure_noverifytime(tls_config);
    } else if (tls_config_set_ca_file(tls_config, cacerts) != 0) {
        fail("failed to load CA bundle", NULL);
    }

    struct tls* tls = tls_client();
    if (!tls)
        fail("failed to create tls client", NULL);
    if (tls_configure(tls, tls_config) != 0)
        fail("tls_configure", tls);
    tls_config_free(tls_config);
    if (tls_connect_socket(tls, sock, host) != 0)
        fail("tls_connect_socket", tls);
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

FILE* fopentls(int sock, const char* host, const char* cacerts, int insecure) {
    void* tls = start_tls(sock, host, cacerts, insecure);
    return fopencookie(tls, "r+",
        (cookie_io_functions_t){read_tls, write_tls, NULL, end_tls});
}
