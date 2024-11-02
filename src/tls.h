#ifdef TLS
FILE* start_tls(int sock, const char* host, const char* cacerts,
                const char* cert, const char* key, int insecure);
FILE* wrap_tls(FILE* sock, const char* host, const char* cacerts,
                const char* cert, const char* key, int insecure);
#else
#define start_tls(...) fail("https not supported", EUSAGE)
#define wrap_tls(...) fail("https not supported", EUSAGE)
#endif
