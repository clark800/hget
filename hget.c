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
    char *scheme, *userinfo, *host, *port, *pathquery, *fragment;
} URL;

static int get(URL url, char* dest);

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

static ssize_t write_body(int fd, const void* buf, size_t len) {
    ssize_t n = bwrite(fd, buf, len);
    if (n < 0)
        sfail("write failed");
    if (n > 0) {
        PROGRESS += n;
        if (SIZE > 0)
            fprintf(stderr, "%lld %lld\n", PROGRESS, SIZE);
    }
    return n;
}

static URL parse_url(char* url) {
    URL result = {.scheme="http", .userinfo="", .pathquery="", .fragment=""};
    result.port = strncmp(url, "https://", 8) == 0 ? "443" : "80";

    // fragment can contain any character, so chop off first
    char* hash = strchr(url, '#');
    if (hash) {
        hash[0] = '\0';
        result.fragment = hash + 1;
    }

    char* sep = strstr(url, "://");
    if (sep && sep < strchr(url, '/')) {
        sep[0] = '\0';
        result.scheme = url;
        url = sep + 3;
    }

    // path can contain '@' and ':', so chop off first
    char* slash = strchr(url, '/');
    if (slash) {
        slash[0] = '\0';
        result.pathquery = slash + 1;
    }

    char* at = strchr(url, '@');
    if (at) {
        at[0] = '\0';
        result.userinfo = url;
        url = at + 1;
    }

    char* colon = strchr(url, ':');
    if (colon) {
        colon[0] = '\0';
        result.port = colon + 1;
    }

    result.host = url;
    return result;
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

static void request(int sock, TLS* tls, char* host, char* pathq, char* dest) {
    struct stat sb;
    swrite(sock, tls, "GET /");
    swrite(sock, tls, pathq);
    swrite(sock, tls, " HTTP/1.0\r\nHost: ");
    swrite(sock, tls, host);
    if (dest && stat(dest, &sb) == 0) {
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

static int redirect(char* location, char* dest) {
    if (location == NULL)
        fail("error: redirect missing location", EFAIL);
    char* endline = strstr(location, "\r\n");
    if (endline == NULL)
        fail("error: response headers too long", EFAIL);
    endline[0] = '\0';
    return get(parse_url(location), dest);
}

static int open_file(char* dest) {
    int out = STDOUT_FILENO;
    if (dest)
        out = open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0)
        sfail("open failed");
    return out;
}

static int get(URL url, char* dest) {
    char buffer[8192];
    int sock = conn(url.host, url.port);
    int https = strcmp(url.scheme, "https") == 0;
    TLS* tls = https ? start_tls(sock, url.host) : NULL;
    request(sock, tls, url.host, url.pathquery, dest);

    ssize_t nread = sread(sock, tls, buffer, sizeof(buffer) - 1);
    buffer[nread] = 0;

    int status_code = parse_status_line(buffer);
    if (status_code / 100 == 2) {
        if (!isatty(STDERR_FILENO)) {
            char* length = get_header(buffer, "Content-Length:");
            if (length != NULL)
                SIZE = strtoll(length, NULL, 10);
        }
        char* body = skip_head(buffer);
        int out = open_file(dest);
        write_body(out, body, nread - (body - buffer));
        while (nread > 0) {
            nread = sread(sock, tls, buffer, sizeof(buffer));
            write_body(out, buffer, nread);
        }
        close(out);
    }

    end_tls(tls);
    close(sock);
    if (status_code / 100 == 3 && status_code != 304)
        return redirect(get_header(buffer, "Location:"), dest);
    return status_code;
}

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3)
        fail("usage: hget <url> [<dest>]", EUSAGE);

    int status = get(parse_url(argv[1]), argv[2]);
    if (status / 100 == 2 || (status == 304 && argc == 3))
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
