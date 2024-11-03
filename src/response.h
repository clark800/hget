char* get_header(char* response, char* name);
int handle_response(char* buffer, FILE* sock, URL url, char* dest, int resume,
        char* method, int entire, int direct, int lax, int zip, FILE* bar);
void check_proxy_connect(char* buffer, FILE* sock);
