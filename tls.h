typedef struct TLS TLS;
#ifndef NO_TLS
TLS* start_tls(int sock, const char* host);
void end_tls(TLS* tls);
size_t read_tls(TLS* tls, void* buf, size_t len, char* stop);
void write_tls(TLS* tls, const void* buf, size_t len);
#else
#define stub() fail("https not supported", EFAIL)
#define start_tls(...) (TLS*)stub()
#define end_tls(...) (void)stub()
#define read_tls(...) (size_t)stub()
#define write_tls(...) (void)stub()
#endif
