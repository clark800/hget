#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // strncasecmp
#include "util.h"
#include "response.h"

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

static int parse_status_line(char* response) {
    if (response[0] == 0)
        fail("error: no response", EPROTOCOL);
    if (strncmp(response, "HTTP/", 5) != 0)
        fail("error: invalid http response", EPROTOCOL);

    char* space = strchr(response, ' ');
    if (space == NULL)
        fail("error: invalid http response", EPROTOCOL);
    long status_code = strtol(space+1, NULL, 10);
    if (status_code < 100 || status_code >= 600)
        fail("error: invalid http response", EPROTOCOL);
    return status_code;
}

// name parameter must include the colon
char* get_header(char* response, char* name) {
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
    fail("error: response headers too long", EPROTOCOL);
    return NULL;
}

static FILE* open_file(char* dest, int status_code, char* header, int resume,
        URL url) {
    if (status_code == 206) {
        if (!resume)
            fail("error: unexpected partial content response", EPROTOCOL);
        char* range = get_header(header, "Content-Range:");
        if (!range)
            fail("error: missing content-range header", EPROTOCOL);
        if (is_stdout(dest) || isdir(dest))
            fail("error: invalid partial download", EUSAGE);
        char* space = strchr(range, ' ');
        size_t range_start = space ? strtoul(space + 1, NULL, 10) : 0;
        if (get_file_size(dest) != range_start)
            fail("error: content-range does not match file size", EPROTOCOL);
        FILE* out = fopen(dest, "a");
        if (out == NULL)
            sfail("open failed");
        return out;
    } else if (resume)
        fail("error: resume not supported or source file modified", EPROTOCOL);

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
        fail("error: response header too long", EPROTOCOL);
    fail("error: invalid response header", EPROTOCOL);
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
        fail("error: response content shorter than expected", EPROTOCOL);
    return progress;
}

static size_t write_chunk(FILE* sock, char* buffer, FILE* out) {
    size_t N = BUFSIZE;
    size_t n = sreadln(sock, buffer, N);
    size_t size = (size_t)strtoul(buffer, NULL, 16);
    if (size == 0 && buffer[0] != '0')
        fail("error: invalid chunked encoding (no terminator)", EPROTOCOL);
    if (size == 0)
        return 0;
    size_t progress = 0;
    for (; n > 0 && progress < size + 2; progress += n) {
        n = sread(sock, buffer, min((size + 2) - progress, N));
        write_out(out, buffer, min(size - min(progress, size), n));
    }
    if (progress < size + 2)
        fail("error: invalid chunked encoding (incorrect length)", EPROTOCOL);
    if (n == 0 || buffer[n - 1] != '\n')
        fail("error: invalid chunked encoding (missing \\r\\n)", EPROTOCOL);
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
        fail("error: invalid http response", EPROTOCOL);
    fwrite(space + 1, 1, strcspn(space + 1, "\r\n"), stderr);
    fputc('\n', stderr);
}

int handle_response(char* buffer, FILE* sock, URL url, char* dest, int resume,
        char* method, int entire, int direct, int lax, FILE* bar) {
    size_t headlen = read_head(sock, buffer, BUFSIZE);
    int status_code = parse_status_line(buffer);
    if (status_code/100 == 2 || (direct && status_code/100 == 3) ||
            (lax && (status_code/100 != 3 || status_code == 304))) {
        FILE* out = open_file(dest, status_code, buffer, resume, url);
        if (entire)
            write_out(out, buffer, headlen);
        if (strcmp(method, "HEAD") != 0) {
            if (is_chunked(buffer))
                write_chunks(sock, buffer, out);
            else
                write_body(sock, buffer, out, bar);
        }
        if (fclose(out) != 0)
            sfail("close failed");
    } else if (status_code >= 400)
        print_status_line(buffer);
    return status_code;
}

void check_proxy_connect(char* buffer, FILE* sock) {
    read_head(sock, buffer, BUFSIZE);

    int status_code = parse_status_line(buffer);
    if (status_code != 200) {
        fprintf(stderr, "proxy: ");
        print_status_line(buffer);
        exit(EPROXY);
    }
}
