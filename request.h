typedef struct {
    char *scheme, *userinfo, *host, *port, *path, *query, *fragment;
} URL;

void* fail(const char* message, int status);
void sfail(const char* message);
int is_stdout(char* dest);
void swrite(FILE* sock, const char* buf);
void request(char* buffer, FILE* sock, URL url, URL proxy, char* auth,
             char* method, char** headers, char* body, char* upload, char* dest,
             int update);
void send_proxy_connect(char* buffer, FILE* sock, URL url, URL proxy);
