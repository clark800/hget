void request(char* buffer, FILE* sock, URL url, URL proxy, char* auth,
             char* method, char** headers, char* body, char* upload, char* dest,
             char* newer, int resume, int verbose);
void send_proxy_connect(char* buffer, FILE* sock, URL url, URL proxy);
