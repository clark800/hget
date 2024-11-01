#define _BSD_SOURCE
#include <stdio.h>
#include "shim.h"

// we always call with the same cookie io functions so we can use a global
static cookie_io_functions_t IO;

static int reader(void* cookie, char* buf, int n) {
    return (int)IO.read(cookie, buf, (size_t)n);
}

static int writer(void* cookie, const char* buf, int n) {
    return (int)IO.write(cookie, buf, (size_t)n);
}

FILE* fopencookie(void* cookie, const char* mode, cookie_io_functions_t io) {
    (void)mode;
    IO = io;
    return funopen(cookie, reader, writer, NULL, io.close);
}
