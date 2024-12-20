enum {OK, ENOTFOUND, EREQUEST, ESERVER, EREDIRECT, EPROXY, EPROTOCOL, ETIMEOUT,
      ESYSTEM, EUSAGE};

typedef struct {
    char *scheme, *userinfo, *host, *port, *path, *query, *fragment;
} URL;

void* fail(const char* message, int status);
void sfail(const char* message);
int is_stdout(char* dest);
void swrite(FILE* sock, const char* buf);
int isdir(const char* path);
char* get_filename(char* path);
size_t get_file_size(char* path);
URL parse_url(char* str);
