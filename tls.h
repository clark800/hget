#ifdef TLS
FILE* fopentls(int sock, const char* host, const char* cacerts, int insecure);
#else
#define fopentls(...) fail("https not supported", EFAIL)
#endif
