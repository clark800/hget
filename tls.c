#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tls.h>
#include "tls.h"

enum {EFAIL = 1};

static void fail(const char* message, struct tls* tls) {
    fputs(message, stderr);
    if (tls) {
        fputs(": ", stderr);
        fputs(tls_error((struct tls*)tls), stderr);
    }
    fputs("\n", stderr);
    exit(EFAIL);
}

// read_tls_until reads in a loop until the stop sequence is read
// read_tls_until may read past stop, but it won't block if stop has been read
size_t read_tls_until(TLS* tls, void* buf, size_t len, char* stop) {
    size_t i = 0, stoplen = strlen(stop);
    for (ssize_t n = 0; i < len; i += n) {
        n = tls_read((struct tls*)tls, (char*)buf + i, len - i);
        if (n == 0)
            return i;   // end of file
        if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT)
            n = 0;      // try again
        else if (n < 0) {
            // if connection closed by server without close_notify, just
            // treat this like a clean close
            // https://github.com/openssl/openssl/discussions/22690
            if (strstr(tls_error((struct tls*)tls), "0A000126"))
                return i;
            fail("receive failed", (struct tls*)tls);
        }
        if (i + n == len)
            return len;
        ((char*)buf)[i + n] = '\0';   // add null terminator for strstr
        // stop could span a chunk boundary, so we must search before buf + i
        if (strstr(i <= stoplen ? buf : (char*)buf + i - stoplen, stop))
            return i + n;
    }
    return i;
}

void write_tls(TLS* tls, const void* buf, size_t len) {
    ssize_t n = 0;
    for (size_t i = 0; i < len; i += n) {
        n = tls_write((struct tls*)tls, (const char*)buf + i, len - i);
        if (n == TLS_WANT_POLLIN || n == TLS_WANT_POLLOUT)
            n = 0;      // try again
        else if (n < 0)
            fail("send failed", (struct tls*)tls);
    }
}

TLS* start_tls(int sock, const char* host, const char* cacerts, int insecure) {
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
    return (TLS*)tls;
}

void end_tls(TLS* tls) {
    if (tls) {
        // ignore errors (not all servers close properly)
        tls_close((struct tls*)tls);
        tls_free((struct tls*)tls);
    }
}
