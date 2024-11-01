#ifdef NEED_FOPENCOOKIE
typedef struct {
    ssize_t (*read)(void*, char*, size_t);
    ssize_t (*write)(void*, const char*, size_t);
    int (*seek)(void*, void*, int); // changed off64_t* to void* (not used)
    int (*close)(void*);
} cookie_io_functions_t;

FILE* fopencookie(void* cookie, const char* mode, cookie_io_functions_t io);
#endif
