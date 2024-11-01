#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // strncasecmp
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include "util.h"
#include "tls.h"
#include "request.h"
#include "interact.h"

static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

static size_t sreadln(FILE* sock, void* buf, size_t len) {
    char* s = fgets(buf, len, sock);
    if (ferror(sock))
        sfail("receive failed");
    return s ? strlen(buf) : 0;
}

// reads until len bytes are read or EOF is reached
static size_t sread(FILE* sock, void* buf, size_t len) {
    size_t n = fread(buf, 1, len, sock);
    if (ferror(sock))
        sfail("receive failed");
    return n;
}

static size_t write_out(FILE* out, char* buf, size_t len) {
    if (fwrite(buf, 1, len, out) != len)
        sfail("write failed");
    return len;
}

static size_t write_body_span(FILE* out, void* buf, size_t len,
        size_t progress, size_t size, FILE* bar) {
    write_out(out, buf, len);
    if (bar && len > 0 && size > 0)
        fprintf(bar, "%zu %zu\n", progress + len, size);
    return len;
}

static int try_conn(char* host, char* port, sa_family_t family) {
    struct addrinfo *server;
    struct addrinfo hints = {.ai_family = family, .ai_socktype = SOCK_STREAM};

    if (getaddrinfo(host, port, &hints, &server) != 0)
        sfail("getaddrinfo failed");

    int sockfd = socket(server->ai_family, server->ai_socktype,
        server->ai_protocol);
    if (sockfd == -1)
        sfail("socket create failed");

    int result = connect(sockfd, server->ai_addr, server->ai_addrlen);

    freeaddrinfo(server);
    if (result != 0)
        close(sockfd);
    return result == 0 ? sockfd : -1;
}

static int conn(char* scheme, char* host, char* port, int timeout) {
    alarm(timeout);
    if (!port || port[0] == 0)
        port = strcmp(scheme, "https") == 0 ? "443" : "80";

    int sockfd = try_conn(host, port, AF_UNSPEC);

    // host could have both an ipv6 and ipv4 address and ipv6 will be returned
    // first, but it's possible that the ipv6 address is blocked, so we try
    // the ipv4 (AF_INET) address also
    if (sockfd == -1)
        sockfd = try_conn(host, port, AF_INET);
    if (sockfd == -1)
        sfail("connect failed");

    alarm(0);
    return sockfd;
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

// name parameter must include the colon
static char* get_header(char* response, char* name) {
    char* endline = strstr(response, "\r\n");
    while (endline != NULL) {
        if (strncmp(endline, "\r\n\r\n", 4) == 0)
            return NULL; // end of headers
        char* header = endline + 2;
        if (strncasecmp(header, name, strlen(name)) == 0) {
            char* value = header + strlen(name);
            return value + strspn(value, " \t");
        }
        endline = strstr(header, "\r\n");
    }
    fail("error: response headers too long", EFAIL);
    return NULL;
}

static FILE* open_file(char* dest, URL url) {
    if (is_stdout(dest))
        return stdout;

    if (isdir(dest)) {
        dest = get_filename(url.path);  // already chdir to dest in main
        if (dest == NULL || dest[0] == '\0')
            dest = "index.html";
    }

    FILE* out = fopen(dest, "w");
    if (out == NULL)
        sfail("open failed");
    return out;
}

static size_t read_head(FILE* sock, char* buf, size_t len) {
    size_t n;
    for (n = 0; n < len && fgets(buf + n, len - n, sock); n += strlen(buf + n))
        if (strcmp(buf + n, "\r\n") == 0)
            return n + 2;
    if (n >= len)
        fail("error: response header too long", EFAIL);
    fail("error: invalid response header", EFAIL);
    return 0;
}

static size_t write_body(FILE* sock, char* buffer, FILE* out, FILE* bar) {
    size_t N = BUFSIZE;
    char* length = get_header(buffer, "Content-Length:");
    size_t size = length ? strtoll(length, NULL, 10) : 0;
    if (size == 0 && length[0] == '0')
        return 0;
    size_t progress = 0;
    for (size_t n = 1; n > 0 && (size == 0 || progress < size); progress += n) {
        n = sread(sock, buffer, size ? min(size - progress, N) : N);
        write_body_span(out, buffer, n, progress, size, bar);
    }
    if (size && progress != size)
        fail("connection closed before all data was received", EFAIL);
    return progress;
}

static size_t write_chunk(FILE* sock, char* buffer, FILE* out) {
    size_t N = BUFSIZE;
    size_t n = sreadln(sock, buffer, N);
    size_t size = (size_t)strtoul(buffer, NULL, 16);
    if (size == 0 && buffer[0] != '0')
        fail("error: invalid chunked encoding (no terminator)", EFAIL);
    if (size == 0)
        return 0;
    size_t progress = 0;
    for (; n > 0 && progress < size + 2; progress += n) {
        n = sread(sock, buffer, min((size + 2) - progress, N));
        write_out(out, buffer, min(size - min(progress, size), n));
    }
    if (progress < size + 2)
        fail("error: invalid chunked encoding (incorrect length)", EFAIL);
    if (n == 0 || buffer[n - 1] != '\n')
        fail("error: invalid chunked encoding (missing \\r\\n)", EFAIL);
    fflush(out);
    return size;
}

static size_t write_chunks(FILE* sock, char* buffer, FILE* out) {
    size_t n = 0;
    for (size_t m = 1; m > 0; n += m)
        m = write_chunk(sock, buffer, out);
    return n;
}

static int is_chunked(char* header) {
    char* encodings = get_header(header, "Transfer-Encoding:");
    if (!encodings)
        return 0;
    char *p = NULL, *comma = NULL;
    while ((p = strtok(encodings, ",\n")) && *p == ',')
        comma = p;
    char* encoding = comma ? (comma + 1) + strspn(comma + 1, " \t") : encodings;
    return strncasecmp(encoding, "chunked", 7) == 0;
}

static void print_status_line(char* response) {
    char* space = strchr(response, ' ');
    if (space == NULL)
        fail("error: invalid http response", EFAIL);
    fwrite(space + 1, 1, strcspn(space + 1, "\r\n"), stderr);
    fputc('\n', stderr);
}

static int handle_response(char* buffer, FILE* sock, URL url, char* dest,
        char* method, int explicit, FILE* bar) {
    size_t headlen = read_head(sock, buffer, BUFSIZE);
    int status_code = parse_status_line(buffer);
    if (explicit || status_code / 100 == 2) {
        FILE* out = open_file(dest, url);
        if (explicit)
            write_out(out, buffer, headlen);
        if (strcmp(method, "HEAD") != 0) {
            if (is_chunked(buffer))
                write_chunks(sock, buffer, out);
            else
                write_body(sock, buffer, out, bar);
        }
        if (fclose(out) != 0)
            sfail("close failed");
    }
    else if (status_code >= 400)
        print_status_line(buffer);
    return status_code;
}

static FILE* opensock(URL server, char* cacerts, char* cert, char* key,
        int insecure, int timeout) {
    (void)cacerts, (void)insecure, (void)cert, (void)key;
    int sockfd = conn(server.scheme, server.host, server.port, timeout);
    int https = strcmp(server.scheme, "https") == 0;
    FILE* sock = https ?
        start_tls(sockfd, server.host, cacerts, cert, key, insecure) :
        fdopen(sockfd, "r+");
    if (sock == NULL)
        sfail(https ? "error: start_tls failed" : "error: fdopen failed");
    return sock;
}

static FILE* proxy_connect(char* buffer, FILE* proxysock, URL url, URL proxy,
        char* cacerts, char* cert, char* key, int insecure) {
    (void)cacerts, (void)insecure, (void)cert, (void)key;
    send_proxy_connect(buffer, proxysock, url, proxy);
    read_head(proxysock, buffer, BUFSIZE);

    int status_code = parse_status_line(buffer);
    if (status_code != 200) {
        fprintf(stderr, "proxy: ");
        print_status_line(buffer);
        exit(EFAIL);
    }

    if (strcmp(url.scheme, "https") != 0)
        return proxysock;

    FILE* sock = wrap_tls(proxysock, url.host, cacerts, cert, key, insecure);
    if (sock == NULL)
        fail("error: wrap_tls failed", EFAIL);
    return sock;
}

int interact(URL url, URL proxy, int relay, char* auth, char* method,
        char** headers, char* body, char* upload, char* dest, int explicit,
        int update, char* cacerts, char* cert, char* key, int insecure,
        int timeout, FILE* bar, int redirects) {
    char buffer[BUFSIZE];
    FILE* proxysock = proxy.host ?
        opensock(proxy, cacerts, cert, key, 0, timeout) : NULL;
    FILE* sock = proxy.host ? (relay ? proxysock : proxy_connect(buffer,
                 proxysock, url, proxy, cacerts, cert, key, insecure)) :
                 opensock(url, cacerts, cert, key, insecure, timeout);

    request(buffer, sock, url, relay ? proxy : (URL){0}, auth, method, headers,
            body, upload, dest, update);
    int status_code = handle_response(buffer, sock, url, dest, method,
                                      explicit, bar);
    fclose(sock);
    if (proxysock && proxysock != sock)
        fclose(proxysock);

    if (!explicit && status_code / 100 == 3 && status_code != 304) {
        if (redirects >= 20)
            fail("error: too many redirects", EFAIL);
        char* location = get_header(buffer, "Location:");
        if (location == NULL)
            fail("error: redirect missing location", EFAIL);
        return interact(parse_url(location), proxy, relay, auth,
            status_code == 303 ? "GET" : method, headers, body, upload, dest,
            explicit, update, cacerts, cert, key, insecure, timeout, bar,
            redirects + 1);
    }
    return status_code;
}
