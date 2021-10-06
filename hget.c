#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "tls.h"

static long long SIZE = 0, PROGRESS = 0;

enum {OK, EFAIL, EUSAGE, ENOTFOUND, EREQUEST, ESERVER};

typedef struct {
    char *scheme, *userinfo, *host, *port, *path, *query, *fragment;
} URL;

static int get(URL url, char* dest, FILE* pipe);

static void fail(const char* message, int status) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(status);
}

static void sfail(const char* message) {
    perror(message);
    exit(EFAIL);
}

// blocking read, always fills buffer or reaches eof or returns an error
static ssize_t bread(int fd, void* buf, size_t len) {
    size_t i = 0;
    for (ssize_t n = 0; i < len; i += n) {
        n = read(fd, (char*)buf + i, len - i);
        if (n == 0)
            return i;   // end of file
        if (n < 0) {
            if (errno == EINTR)
                n = 0;  // try again
            else
                return -1;
        }
    }
    return i;
}

// blocking write, always sends full buffer or returns an error
static ssize_t bwrite(int fd, const void* buf, size_t len) {
    ssize_t n = 0;
    for (size_t i = 0; i < len; i += n) {
        n = write(fd, (const char*)buf + i, len - i);
        if (n < 0) {
            if (errno == EINTR)
                n = 0;  // try again
            else
                return -1;
        }
    }
    return n;
}

static ssize_t sread(int fd, TLS* tls, void* buf, size_t len) {
    ssize_t n = tls ? read_tls(tls, buf, len) : bread(fd, buf, len);
    if (n < 0)
        sfail("receive failed");
    return n;
}

static void swrite(int fd, TLS* tls, const char* buf) {
    if (tls) {
        write_tls(tls, buf, strlen(buf));
    } else if (bwrite(fd, buf, strlen(buf)) < 0)
        sfail("send failed");
}

static ssize_t write_body(int fd, const void* buf, size_t len, FILE* pipe) {
    ssize_t n = bwrite(fd, buf, len);
    if (n < 0)
        sfail("write failed");
    if (n > 0) {
        PROGRESS += n;
        if (pipe && SIZE > 0)
            fprintf(pipe, "%lld %lld\n", PROGRESS, SIZE);
    }
    return n;
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

    int sock = socket(server->ai_family, server->ai_socktype,
        server->ai_protocol);

    if (sock == -1)
        sfail("socket create failed");

    if (connect(sock, server->ai_addr, server->ai_addrlen) != 0)
        sfail("connect failed");

    freeaddrinfo(server);
    return sock;
}

static void request(int sock, TLS* tls, URL url, char* dest) {
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

static int redirect(char* location, char* dest, FILE* pipe) {
    if (location == NULL)
        fail("error: redirect missing location", EFAIL);
    char* endline = strstr(location, "\r\n");
    if (endline == NULL)
        fail("error: response headers too long", EFAIL);
    endline[0] = '\0';
    return get(parse_url(location), dest, pipe);
}

static int open_file(char* dest) {
    if (strcmp(dest, "-") == 0)
        return STDOUT_FILENO;
    int out = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0)
        sfail("open failed");
    return out;
}

static int get(URL url, char* dest, FILE* pipe) {
    char buffer[8192];
    int sock = conn(url.host, url.port);
    int https = strcmp(url.scheme, "https") == 0;
    TLS* tls = https ? start_tls(sock, url.host) : NULL;
    request(sock, tls, url, dest);

    ssize_t nread = sread(sock, tls, buffer, sizeof(buffer) - 1);
    buffer[nread] = 0;

    int status_code = parse_status_line(buffer);
    if (status_code / 100 == 2) {
        char* length = get_header(buffer, "Content-Length:");
        SIZE = length ? strtoll(length, NULL, 10) : 0;
        char* body = skip_head(buffer);
        int out = open_file(dest);
        write_body(out, body, nread - (body - buffer), pipe);
        while (nread > 0) {
            nread = sread(sock, tls, buffer, sizeof(buffer));
            write_body(out, buffer, nread, pipe);
        }
        if (close(out) != 0)
            sfail("close failed");
    }

    end_tls(tls);
    close(sock);
    if (status_code / 100 == 3 && status_code != 304)
        return redirect(get_header(buffer, "Location:"), dest, pipe);
    return status_code;
}

static char* get_filename(char* path) {
    char* slash = strrchr(path, '/');
    char* filename = slash ? slash + 1 : path;
    return filename[0] ? filename : "index.html";
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3)
        fail("usage: hget <url> [<dest>]", EUSAGE);

    // use fd 3 for progress updates if it has been opened
    FILE* pipe = fcntl(3, F_GETFD) != -1 ? fdopen(3, "w") : NULL;

    URL url = parse_url(argv[1]);
    char* dest = argc > 2 && argv[2][0] ? argv[2] : get_filename(url.path);
    int status = get(url, dest, pipe);

    if (pipe)
        fclose(pipe);

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
