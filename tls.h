#ifdef TLS
FILE* start_tls(int sock, const char* host, const char* cacerts, int insecure);
FILE* wrap_tls(FILE* sock, const char* host, const char* cacerts, int insecure);
#else
#define start_tls(...) fail("https not supported", EFAIL)
#define wrap_tls(...) fail("https not supported", EFAIL)
#endif
