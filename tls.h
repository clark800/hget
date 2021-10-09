typedef struct TLS TLS;
TLS* start_tls(int sock, const char* host);
void end_tls(TLS* tls);
size_t read_tls(TLS* tls, void* buf, size_t len, char* stop);
void write_tls(TLS* tls, const void* buf, size_t len);
