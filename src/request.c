#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h> // intmax_t
#include <sys/stat.h>
#include "util.h"
#include "request.h"

static void swritefile(FILE* sock, const char* path, char* buf) {
    FILE* file = fopen(path, "r");
    if (!file)
        sfail("failed to open upload file");
    for (size_t n = 0; (n = fread(buf, 1, BUFSIZE, file)) > 0;)
        if (fwrite(buf, 1, n, sock) != n)
            sfail("send failed");
}

static size_t base64encode(const char* in, size_t n, char* out) {
    char* E = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    for (size_t i = 0, j = 0, w = 0; i < 4 * ((n + 2) / 3); i++) {
        if (i % 4 != 3)
            w = w << 8 | (j < n ? (unsigned char)in[j++] : 0);
        out[i] = i <= (4 * n) / 3 ? E[(w >> 2 * ((i + 1) % 4)) & 63] : '=';
    }
    out[4 * ((n + 2) / 3)] = 0;
    return 4 * ((n + 2) / 3);
}

static size_t write_auth(char* buffer, size_t N, char* name, char* auth) {
    size_t m = strlen(auth);
    size_t n = snprintf(buffer, N, "%s: Basic ", name);
    if (4 * ((m + 2) / 3) + 2 > (n < N ? N - n : 0))
        fail("error: auth string too long", EUSAGE);
    n += base64encode(auth, m, buffer + n);
    n += snprintf(buffer + n, n < N ? N - n : 0, "\r\n");
    return n;
}

static size_t get_content_length(char* body, char* upload) {
    if (body || !upload)
        return body ? strlen(body) : 0;
    return get_file_size(upload);
}

void request(char* buffer, FILE* sock, URL url, URL proxy, char* auth,
        char* method, char** headers, char* body, char* upload, char* dest,
        char* newer, int resume, int verbose, int zip) {
    struct stat sb;
    char time[32];
    size_t n = 0, N = BUFSIZE;

    n += snprintf(buffer + n, n < N ? N - n : 0, "%s ", method);
    if (proxy.host) {
        char* scheme = url.scheme[0] ? url.scheme : "http";
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s://", scheme);
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s", url.host);
        if (url.port[0])
            n += snprintf(buffer + n, n < N ? N - n : 0, ":%s", url.port);
    }
    n += snprintf(buffer + n, n < N ? N - n : 0, "/%s", url.path);
    if (url.query[0])
        n += snprintf(buffer + n, n < N ? N - n : 0, "?%s", url.query);
    n += snprintf(buffer + n, n < N ? N - n : 0, " HTTP/1.1\r\n");
    if (proxy.userinfo && proxy.userinfo[0])
        n += write_auth(buffer + n, n < N ? N - n : 0, "Proxy-Authorization",
                proxy.userinfo);

    n += snprintf(buffer + n, n < N ? N - n : 0, "Host: %s\r\n", url.host);
    n += snprintf(buffer + n, n < N ? N - n : 0, "Connection: close\r\n");
    n += snprintf(buffer + n, n < N ? N - n : 0, zip ?
            "Accept-Encoding: gzip\r\n" : "Accept-Encoding: identity\r\n");
    if (!auth)
        auth = url.userinfo;
    if (auth && auth[0])
        n += write_auth(buffer + n, n < N ? N - n : 0, "Authorization", auth);
    if (newer) {
        if (stat(newer, &sb) != 0)
            fail("error: failed to read original file", EUSAGE);
        struct tm* timeinfo = gmtime(&sb.st_mtime);
        strftime(time, sizeof(time), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
        n += snprintf(buffer + n, n < N ? N - n : 0,
                "If-Modified-Since: %s\r\n", time);
    }
    if (resume) {
        if (is_stdout(dest) || isdir(dest) || stat(dest, &sb) != 0)
            fail("error: failed to read partial download file", EUSAGE);
        struct tm* timeinfo = gmtime(&sb.st_mtime);
        strftime(time, sizeof(time), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
        n += snprintf(buffer + n, n < N ? N - n : 0,
                "Range: bytes=%jd-\r\n", (intmax_t)sb.st_size);
        n += snprintf(buffer + n, n < N ? N - n : 0, "If-Range: %s\r\n", time);
    }
    while (*headers != NULL)
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s\r\n", *(headers++));
    if (body || upload)
        n += snprintf(buffer + n, n < N ? N - n : 0,
                "Content-Length: %zu\r\n", get_content_length(body, upload));
    n += snprintf(buffer + n, n < N ? N - n : 0, "\r\n");

    if (n >= N)  // equal is a failure because of null terminator
        fail("error: request too large", EUSAGE);

    if (verbose) {
        fputs("================= REQUEST HEADER ==================\n", stderr);
        fwrite(buffer, 1, n, stderr);
        fputs("======================= END =======================\n", stderr);
    }

    if (body && strlen(body) < (n < N ? N - n : 0)) {
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s", body);
        swrite(sock, buffer);  // write header and body
    } else {
        swrite(sock, buffer);  // write header
        if (body)
            swrite(sock, body);
        else if (upload)
            swritefile(sock, upload, buffer);
    }
}

void send_proxy_connect(char* buffer, FILE* sock, URL url, URL proxy) {
    size_t n = 0, N = BUFSIZE;
    int url_https = strcmp(url.scheme, "https") == 0;
    char* port = url.port[0] ? url.port : (url_https ? "443" : "80");
    n += snprintf(buffer, N, "CONNECT %s:%s HTTP/1.1\r\n", url.host, port);
    n += snprintf(buffer + n, n < N ? N - n : 0, "Host: %s:%s\r\n",
            url.host, port);
    if (proxy.userinfo[0])
        n += write_auth(buffer + n, n < N ? N - n : 0, "Proxy-Authorization",
                proxy.userinfo);
    n += snprintf(buffer + n, n < N ? N - n : 0, "\r\n");
    if (n >= N)  // equal is a failure because of null terminator
        fail("error: proxy connect request too long", EUSAGE);
    swrite(sock, buffer);
}
