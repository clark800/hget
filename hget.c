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

static int hget(char* url);

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

static void send_request(int sock, TLS* tls, char* host, char* path) {
    swrite(sock, tls, "GET ");
    swrite(sock, tls, path);
    swrite(sock, tls, " HTTP/1.0\r\nHost: ");
    swrite(sock, tls, host);
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

    if (status_code >= 400) {
        char* endline = strstr(space, "\r\n");
        if (endline == NULL)
            fail("error: invalid http response", EFAIL);
        bwrite(STDERR_FILENO, response, endline - response);
        bwrite(STDERR_FILENO, "\n", 1);
    }
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

static int redirect(char* location) {
    if (location == NULL)
        fail("error: redirect missing location", E3XX);
    char* endline = strstr(location, "\r\n");
    if (endline == NULL)
        fail("error: response headers too long", EFAIL);
    endline[0] = '\0';
    return hget(location);
}

static int get(int https, char* host, char* port, char* path) {
    char buffer[8192];
    int sock = conn(host, port);
    TLS* tls = https ? start_tls(sock, host) : NULL;
    send_request(sock, tls, host, path);

    ssize_t nread = sread(sock, tls, buffer, sizeof(buffer) - 1);
    buffer[nread] = 0;

    int status_code = parse_status_line(buffer);
    if (status_code / 100 == 3 && status_code != 304) {
        end_tls(tls);
        close(sock);
        return redirect(get_header(buffer, "Location:"));
    }
    if (!isatty(STDERR_FILENO)) {
        char* length = get_header(buffer, "Content-Length:");
        if (length != NULL)
            SIZE = strtoll(length, NULL, 10);
    }

    char* body = skip_head(buffer);
    write_body(STDOUT_FILENO, body, nread - (body - buffer));
    while (nread > 0) {
        nread = sread(sock, tls, buffer, sizeof(buffer));
        write_body(STDOUT_FILENO, buffer, nread);
    }

    end_tls(tls);
    close(sock);
    return status_code;
}

static int hget(char* url) {
    int https = 0;
    char host[256], authority[512];

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

    return get(https, host, port, path);
}

int main(int argc, char **argv) {
    if (argc != 2)
        fail("usage: hget <url>", EUSAGE);
    int status = hget(argv[1]);

    if (status >= 200 && status <= 299 && status != 203)
        return OK;
    if (status == 404 || status == 410)
        return ENOTFOUND;
    return status / 100;
}
