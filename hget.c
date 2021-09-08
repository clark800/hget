#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "tls.h"

static long long SIZE = 0, PROGRESS = 0;

// status <= 127 indicates a valid http response
enum {OK, E1XX, E2XX, E3XX, E4XX, E5XX, ENOTFOUND=44, EUSAGE=254, EFAIL=255};

static int get_exit_status(long status) {
    if (status >= 200 && status <= 299 && status != 203)
        return OK;
    if (status == 404 || status == 410)
        return ENOTFOUND;
    return status/100;
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

static long parse_status_line(char* response) {
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

    if (get_exit_status(status_code) != OK) {
        char* endline = strstr(space, "\r\n");
        if (endline == NULL)
            fail("error: invalid http response", EFAIL);
        bwrite(STDERR_FILENO, response, endline - response);
        bwrite(STDERR_FILENO, "\n", 1);
    }
    return status_code;
}

static char* parse_headers(char* response) {
    char* endline = strstr(response, "\r\n");
    while (endline != NULL) {
        if (strncmp(endline, "\r\n\r\n", 4) == 0)
            break; // end of headers
        char* header = endline + 2;
        if (strncmp(header, "Content-Length:", 15) == 0) {
            char* value = header + 15;
            if (!isatty(STDERR_FILENO))
                SIZE = strtoll(value + strspn(value, " \t"), NULL, 10);
        }
        endline = strstr(header, "\r\n");
    }

    if (endline == NULL)
        fail("error: response headers too long", EFAIL);

    return endline + 4; // skip past \r\n\r\n
}

static long stream(int sock, TLS* tls, int fd) {
    char buffer[8192];
    ssize_t nread = sread(sock, tls, buffer, sizeof(buffer) - 1);
    buffer[nread] = 0;

    long status_code = parse_status_line(buffer);
    char* body = parse_headers(buffer);

    write_body(fd, body, nread - (body - buffer));

    while (nread > 0) {
        nread = sread(sock, tls, buffer, sizeof(buffer));
        write_body(fd, buffer, nread);
    }

    return status_code;
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

static long get(int https, char* host, char* port, char* path) {
    int sock = conn(host, port);
    TLS* tls = https ? start_tls(sock, host) : NULL;

    swrite(sock, tls, "GET ");
    swrite(sock, tls, path);
    swrite(sock, tls, " HTTP/1.0\r\nHost: ");
    swrite(sock, tls, host);
    swrite(sock, tls, "\r\nAccept-Encoding: identity\r\n\r\n");

    long status = stream(sock, tls, STDOUT_FILENO);

    if (tls)
        end_tls(tls);
    close(sock);
    return status;
}

int main(int argc, char **argv) {
    int https = 0;
    char host[256], authority[512];

    if (argc != 2)
        fail("usage: hget <url>", EUSAGE);

    char* url = argv[1];

    // skip past optional scheme and separator
    char* sep = strstr(url, "://");
    char* start = sep ? sep + 3 : url;
    if (sep && strncmp(url, "https://", 8) == 0)
        https = 1;
    else if (sep && strncmp(url, "http://", 7) != 0)
        fail("error: unsupported scheme", EUSAGE);

    // get path
    char* slash = strchr(start, '/');
    char* path = slash ? slash : "/";

    // load authority into buffer
    size_t authlen = slash ? (size_t)(slash - start) : strlen(start);
    if (authlen >= sizeof(authority))
        fail("error: authority too long", EUSAGE);
    strncpy(authority, start, authlen);
    authority[authlen] = '\0';
    if (strchr(authority, '@'))
        fail("error: userinfo not supported", EUSAGE);

    // split host and port by the colon if present
    char* colon = strchr(authority, ':');
    char* defaultport = https ? "443" : "80";
    char* port = colon ? colon + 1 : defaultport;
    size_t hostlen = colon ? (size_t)(colon - authority) : strlen(authority);
    if (hostlen >= sizeof(host))
        fail("error: host too long", EUSAGE);
    strncpy(host, authority, hostlen);
    host[hostlen] = '\0';

    return get_exit_status(get(https, host, port, path));
}
