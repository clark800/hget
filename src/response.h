char* get_header(char* response, char* name);
int handle_response(char* buffer, FILE* sock, URL url, char* dest,
        char* method, int explicit, FILE* bar);
void check_proxy_connect(char* buffer, FILE* sock);
