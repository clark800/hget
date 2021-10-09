#include <stdio.h>
#include <stdlib.h>
#include "tls.h"

static void stub(void) {
    fputs("https not supported\n", stderr);
    exit(1);
}

TLS* start_tls(int sock, const char* host) {
    return (void)sock, (void)host, stub(), NULL;
}
void end_tls(TLS* tls) {
    (void)tls, stub();
}
size_t read_tls(TLS* tls, void* buf, size_t len, char* stop) {
    return (void)tls, (void)buf, (void)len, (void)stop, stub(), 0;
}
void write_tls(TLS* tls, const void* buf, size_t len) {
    (void)tls, (void)buf, (void)len, stub();
}
