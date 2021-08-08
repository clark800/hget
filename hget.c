#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>

static long long SIZE = 0, PROGRESS = 0;

typedef enum {OK, ESTATUS, EPROTOCOL, ESOCKET, EUSAGE} Status;

static void fail(const char* message, Status status) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(status);
}

static void pfail(const char* message) {
    perror(message);
    exit(ESOCKET);
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

static ssize_t writebody(int fd, const void* buf, size_t len) {
    ssize_t n = bwrite(fd, buf, len);
    if (n > 0) {
        PROGRESS += n;
        if (SIZE > 0)
            fprintf(stderr, "%lld %lld\n", PROGRESS, SIZE);
    }
    return n;
}

static void swrite(int fd, const char* buf) {
    if (bwrite(fd, buf, strlen(buf)) < 0)
        pfail("send failed");
}

static int stream(int sock, int fd) {
    char buffer[8192];

    // read into buffer to get headers
    ssize_t nread = bread(sock, buffer, sizeof(buffer));
    if (nread == 0)
        fail("error: no response", EPROTOCOL);
    if (nread < 0)
        pfail("receive failed");

    // validate response status line prefix
    if (strncmp(buffer, "HTTP/", 5) != 0)
        fail("error: invalid http response", EPROTOCOL);

    // parse http status code
    const char* space = strchr(buffer, ' ');
    if (space == NULL || space[1] < '2' || space[1] > '5')
        fail("error: invalid http response", EPROTOCOL);
    Status status = space[1] == '2' ? OK : ESTATUS;

    const char* endline = strstr(space, "\r\n");
    if (endline == NULL)
        fail("error: invalid http response", EPROTOCOL);

    if (status != OK) {
        bwrite(STDERR_FILENO, buffer, endline - buffer);
        bwrite(STDERR_FILENO, "\n", 1);
    }

    // parse headers for content length
    while (endline != NULL) {
        if (strncmp(endline, "\r\n\r\n", 4) == 0)
            break; // end of headers
        const char* header = endline + 2;
        if (strncmp(header, "Content-Length:", 15) == 0) {
            const char* value = header + 15;
            if (!isatty(STDERR_FILENO))
                SIZE = strtoll(value + strspn(value, " \t"), NULL, 10);
        }
        endline = strstr(header, "\r\n");
    }

    if (endline == NULL)
        fail("error: response headers too long", EPROTOCOL);

    // stream body portion of the first chunk
    const char* body = endline + 4;
    if (writebody(fd, body, nread - (body - buffer)) < 0)
        pfail("write failed");

    // stream remainder of body
    while (nread > 0) {
        nread = bread(sock, buffer, sizeof(buffer));
        if (nread < 0)
            pfail("receive failed");
        if (writebody(fd, buffer, nread) < 0)
            pfail("write failed");
    }

    return status;
}

static int get(const char* host, const char* port, const char* path) {
    // connect to server
    struct addrinfo *server, hints = {.ai_socktype = SOCK_STREAM};
    if (getaddrinfo(host, port, &hints, &server) != 0)
        pfail("getaddrinfo failed");

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock == -1)
        pfail("socket create failed");

    if (connect(sock, server->ai_addr, server->ai_addrlen) != 0)
        pfail("connect failed");

    freeaddrinfo(server);

    // send request
    swrite(sock, "GET ");
    swrite(sock, path);
    swrite(sock, " HTTP/1.0\r\nHost: ");
    swrite(sock, host);
    swrite(sock, "\r\nAccept-Encoding: identity\r\n\r\n");
    if (shutdown(sock, SHUT_WR) != 0)
        pfail("shutdown failed");

    // stream response to stdout
    int status = stream(sock, STDOUT_FILENO);
    close(sock);
    return status;
}

int main(int argc, char **argv) {
    char host[256], authority[512];

    if (argc != 2)
        fail("usage: hget <url>", EUSAGE);

    const char* url = argv[1];

    // skip past optional scheme and separator
    const char* sep = strstr(url, "://");
    const char* start = sep ? sep + 3 : url;
    if (sep && strncmp(url, "http", sep - url) != 0)
        fail("error: only http is supported", EUSAGE);

    // get path
    const char* slash = strchr(start, '/');
    const char* path = slash ? slash : "/";

    // load authority into buffer
    size_t authlen = slash ? (size_t)(slash - start) : strlen(start);
    if (authlen >= sizeof(authority))
        fail("error: authority too long", EUSAGE);
    strncpy(authority, start, authlen);
    authority[authlen] = '\0';
    if (strchr(authority, '@'))
        fail("error: userinfo not supported", EUSAGE);

    // split host and port by the colon if present
    const char* colon = strchr(authority, ':');
    const char* port = colon ? colon + 1 : "80";
    size_t hostlen = colon ? (size_t)(colon - authority) : strlen(authority);
    if (hostlen >= sizeof(host))
        fail("error: host too long", EUSAGE);
    strncpy(host, authority, hostlen);
    host[hostlen] = '\0';

    return get(host, port, path);
}
