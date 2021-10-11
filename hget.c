#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include "tls.h"

enum {OK, EFAIL, EUSAGE, ENOTFOUND, EREQUEST, ESERVER};

typedef struct {
    char *scheme, *userinfo, *host, *port, *path, *query, *fragment;
} URL;

static int get(URL url, char* dest, FILE* bar);

static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

static void fail(const char* message, int status) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(status);
}

static void sfail(const char* message) {
    perror(message);
    exit(EFAIL);
}

static size_t sread(FILE* sock, TLS* tls, void* buf, size_t len) {
    size_t n = tls ? read_tls(tls, buf, len, NULL) : fread(buf, 1, len, sock);
    if (!tls && ferror(sock))
        sfail("receive failed");
    return n;
}

static void swrite(FILE* sock, TLS* tls, const char* buf) {
    size_t size = strlen(buf);
    if (tls) {
        write_tls(tls, buf, size);
    } else if (fwrite(buf, 1, size, sock) < size)
        sfail("send failed");
}

static void write_body(FILE* out, void* buf, size_t len,
        size_t progress, size_t size, FILE* bar) {
    if (fwrite(buf, 1, len, out) != len)
        sfail("write failed");
    if (bar && len > 0 && size > 0)
        fprintf(bar, "%zu %zu\n", progress + len, size);
}

static URL parse_url(char* str) {
    URL url = {.scheme="http", .userinfo="", .path="", .query="", .fragment=""};
    url.port = strncmp(str, "https://", 8) == 0 ? "443" : "80";

    // fragment can contain any character, so chop off first
    char* hash = strchr(str, '#');
    if (hash) {
        hash[0] = '\0';
        url.fragment = hash + 1;
    }

    char* question = strchr(str, '?');
    if (question) {
        question[0] = '\0';
        url.query = question + 1;
    }

    char* sep = strstr(str, "://");
    if (sep && sep < strchr(str, '/')) {
        sep[0] = '\0';
        url.scheme = str;
        str = sep + 3;
    }

    // path can contain '@' and ':', so chop off first
    char* slash = strchr(str, '/');
    if (slash) {
        slash[0] = '\0';
        url.path = slash + 1;
    }

    char* at = strchr(str, '@');
    if (at) {
        at[0] = '\0';
        url.userinfo = str;
        str = at + 1;
    }

    char* colon = strchr(str, ':');
    if (colon) {
        colon[0] = '\0';
        url.port = colon + 1;
    }

    url.host = str;
    return url;
}

static int conn(char* host, char* port) {
    struct addrinfo *server, hints = {.ai_socktype = SOCK_STREAM};
    if (getaddrinfo(host, port, &hints, &server) != 0)
        sfail("getaddrinfo failed");

    int sockfd = socket(server->ai_family, server->ai_socktype,
        server->ai_protocol);

    if (sockfd == -1)
        sfail("socket create failed");

    if (connect(sockfd, server->ai_addr, server->ai_addrlen) != 0)
        sfail("connect failed");

    freeaddrinfo(server);
    return sockfd;
}

static void request(FILE* sock, TLS* tls, URL url, char* dest) {
    struct stat sb;
    swrite(sock, tls, "GET /");
    swrite(sock, tls, url.path);
    if (url.query[0]) {
        swrite(sock, tls, "?");
        swrite(sock, tls, url.query);
    }
    swrite(sock, tls, " HTTP/1.0\r\nHost: ");
    swrite(sock, tls, url.host);
    if (strcmp(dest, "-") != 0 && stat(dest, &sb) == 0) {
        char buffer[32];
        struct tm* timeinfo = gmtime(&sb.st_mtime);
        strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
        swrite(sock, tls, "\r\nIf-Modified-Since: ");
        swrite(sock, tls, buffer);
    }
    swrite(sock, tls, "\r\nAccept-Encoding: identity\r\n\r\n");
}

static int parse_status_line(char* response) {
    if (response[0] == 0)
        fail("error: no response", EFAIL);
    if (strncmp(response, "HTTP/", 5) != 0)
        fail("error: invalid http response", EFAIL);

    char* space = strchr(response, ' ');
    if (space == NULL)
        fail("error: invalid http response", EFAIL);
    long status_code = strtol(space+1, NULL, 10);
    if (status_code < 100 || status_code >= 600)
        fail("error: invalid http response", EFAIL);
    return status_code;
}

static char* get_header(char* response, char* name) {
    char* endline = strstr(response, "\r\n");
    while (endline != NULL) {
        if (strncmp(endline, "\r\n\r\n", 4) == 0)
            return NULL; // end of headers
        char* header = endline + 2;
        if (strncmp(header, name, strlen(name)) == 0) {
            char* value = header + strlen(name);
            return value + strspn(value, " \t");
        }
        endline = strstr(header, "\r\n");
    }
    fail("error: response headers too long", EFAIL);
    return NULL;
}

static char* skip_head(char* response) {
    char* end = strstr(response, "\r\n\r\n");
    if (end == NULL)
        fail("error: response headers too long", EFAIL);
    return end + 4;
}

static int redirect(char* location, char* dest, FILE* bar) {
    if (location == NULL)
        fail("error: redirect missing location", EFAIL);
    char* endline = strstr(location, "\r\n");
    if (endline == NULL)
        fail("error: response headers too long", EFAIL);
    endline[0] = '\0';
    return get(parse_url(location), dest, bar);
}

static FILE* open_file(char* dest) {
    if (strcmp(dest, "-") == 0)
        return stdout;
    FILE* out = fopen(dest, "w");
    if (out == NULL)
        sfail("open failed");
    return out;
}

static size_t read_head(FILE* sock, TLS* tls, char* buf, size_t len) {
    if (tls)
        return read_tls(tls, buf, len, "\r\n\r\n");

    size_t n;
    for (n = 0; n < len && fgets(buf + n, len - n, sock); n += strlen(buf + n))
        if (strcmp(buf + n, "\r\n") == 0)
            return n + 2;
    return n;
}

static int get(URL url, char* dest, FILE* bar) {
    char buffer[8192];
    int sockfd = conn(url.host, url.port);
    int https = strcmp(url.scheme, "https") == 0;
    TLS* tls = https ? start_tls(sockfd, url.host) : NULL;
    FILE* sock = fdopen(sockfd, "rw+");
    if (sock == NULL)
        sfail("fdopen failed");

    request(sock, tls, url, dest);

    size_t N = sizeof(buffer);
    size_t n = read_head(sock, tls, buffer, N);
    buffer[n] = '\0';

    int status_code = parse_status_line(buffer);
    if (status_code / 100 == 2) {
        char* length = get_header(buffer, "Content-Length:");
        size_t size = length ? strtoll(length, NULL, 10) : 0;
        char* body = skip_head(buffer);
        FILE* out = open_file(dest);
        size_t headlen = body - buffer;
        write_body(out, body, n - headlen, 0, size, bar);
        size_t progress = n - headlen;
        for (n = N; n == N && (size == 0 || progress < size); progress += n) {
            n = sread(sock, tls, buffer, size ? min(size - progress, N) : N);
            write_body(out, buffer, n, progress, size, bar);
        }
        if (fclose(out) != 0)
            sfail("close failed");
        if (size && progress != size)
            fail("connection closed before all data was received", EFAIL);
    }

    if (tls)
        end_tls(tls);
    fclose(sock);
    if (status_code / 100 == 3 && status_code != 304)
        return redirect(get_header(buffer, "Location:"), dest, bar);
    return status_code;
}

static char* get_filename(char* path) {
    char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static FILE* open_pipe(char* command, char* arg) {
    int fd[2] = {0, 0};  // fd[0] is read end, fd[1] is write end

    if (command == NULL)
        return NULL;
    if (pipe(fd) != 0)
        sfail("pipe failed");
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        sfail("signal failed");

    switch (fork()) {
        case -1:
            sfail("fork failed");
            return NULL;
        case 0:  // child
            close(fd[1]);
            dup2(fd[0], STDIN_FILENO);
            close(fd[0]);
            execlp(command, arg);
            sfail(command);
    }
    close(fd[0]);
    FILE* file = fdopen(fd[1], "w");
    if (file == NULL)
        sfail("fdopen failed");
    setbuf(file, NULL);
    return file;
}

int main(int argc, char *argv[]) {
    if (argc < 2 || argc > 3 || argv[1][0] == '-')
        fail("usage: hget <url> [<dest>]", EUSAGE);

    FILE* bar = open_pipe(getenv("PROGRESS"), argv[1]);

    URL url = parse_url(argv[1]);
    char* dest = argc > 2 ? argv[2] : get_filename(url.path);
    if (dest[0] == '\0')
        fail("error: filename not found", EUSAGE);
    int status = get(url, dest, bar);

    if (bar) {
        fclose(bar); // this will cause bar to get EOF and exit soon
        wait(NULL);  // wait for bar to finish drawing
    }

    if (status / 100 == 2 || status == 304)
        return OK;

    fprintf(stderr, "HTTP %d\n", status);
    if (status == 404 || status == 410)
        return ENOTFOUND;
    if (status / 100 == 4)
        return EREQUEST;
    if (status / 100 == 5)
        return ESERVER;
    return EFAIL;
}
