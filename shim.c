#include <stdio.h>
#include "shim.h"

FILE* fopencookie(void* cookie, const char* mode, cookie_io_functions_t io) {
    (void)mode;
    return funopen(cookie, (int (*)(void*, char*, int))io.read,
            (int (*)(void*, const char*, int))io.write, NULL, io.close);
}
