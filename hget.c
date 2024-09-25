#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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

static int get(URL url, char* method, char* body, int dump, char* dest,
        FILE* bar);

static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

static int isdir(const char* path) {
    // "If the named file is a symbolic link, the stat() function shall
    // continue pathname resolution using the contents of the symbolic link,
    // and shall return information pertaining to the resulting file if the
    // file exists."
    // (https://pubs.opengroup.org/onlinepubs/000095399/functions/stat.html)
    struct stat sb;
    return path != NULL && stat(path, &sb) == 0 && (sb.st_mode & S_IFDIR);
}

static void* fail(const char* message, int status) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(status);
    return NULL;
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

static void request(FILE* sock, TLS* tls, URL url, char* method, char* body,
        char* dest) {
    struct stat sb;
    swrite(sock, tls, method);
    swrite(sock, tls, " /");
    swrite(sock, tls, url.path);
    if (url.query[0]) {
        swrite(sock, tls, "?");
        swrite(sock, tls, url.query);
    }
    swrite(sock, tls, " HTTP/1.0\r\nHost: ");
    swrite(sock, tls, url.host);
    if (dest != NULL && strcmp(dest, "-") != 0 && stat(dest, &sb) == 0) {
        char buffer[32];
        struct tm* timeinfo = gmtime(&sb.st_mtime);
        strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
        swrite(sock, tls, "\r\nIf-Modified-Since: ");
        swrite(sock, tls, buffer);
    }
    swrite(sock, tls, "\r\nAccept-Encoding: identity");
    if (body) {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "%zu", strlen(body));
        swrite(sock, tls, "\r\nContent-Length: ");
        swrite(sock, tls, buffer);
    }
    swrite(sock, tls, "\r\n\r\n");
    if (body) {
        swrite(sock, tls, body);
    }
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
        if (strncasecmp(header, name, strlen(name)) == 0) {
            char* value = header + strlen(name);
            return value + strspn(value, " \t");
        }
        endline = strstr(header, "\r\n");
    }
    return fail("error: response headers too long", EFAIL);
}

static char* skip_head(char* response) {
    char* end = strstr(response, "\r\n\r\n");
    if (end == NULL)
        fail("error: response headers too long", EFAIL);
    return end + 4;
}

static int redirect(char* location, char* method, char* body, int dump,
        char* dest, FILE* bar) {
    if (location == NULL)
        fail("error: redirect missing location", EFAIL);
    char* endline = strstr(location, "\r\n");
    if (endline == NULL)
        fail("error: response headers too long", EFAIL);
    endline[0] = '\0';
    return get(parse_url(location), method, body, dump, dest, bar);
}

static FILE* open_file(char* dest) {
    if (dest == NULL || strcmp(dest, "-") == 0)
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

static int get(URL url, char* method, char* body, int dump, char* dest,
        FILE* bar) {
    char buffer[8192];
    int sockfd = conn(url.host, url.port);
    int https = strcmp(url.scheme, "https") == 0;
    TLS* tls = https ? start_tls(sockfd, url.host) : NULL;
    FILE* sock = fdopen(sockfd, "r+");
    if (sock == NULL)
        sfail("fdopen failed");

    request(sock, tls, url, method, body, dest);

    size_t N = sizeof(buffer);
    size_t n = read_head(sock, tls, buffer, N);
    buffer[n] = '\0';

    int status_code = parse_status_line(buffer);
    if (status_code / 100 == 2) {
        char* length = get_header(buffer, "Content-Length:");
        size_t size = length ? strtoll(length, NULL, 10) : 0;
        char* response_body = dump ? buffer : skip_head(buffer);
        FILE* out = open_file(dest);
        size_t headlen = response_body - buffer;
        write_body(out, response_body, n - headlen, 0, size, bar);
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
        return redirect(get_header(buffer, "Location:"),
            status_code == 303 ? "GET" : method, body, dump, dest, bar);
    return status_code;
}

static char* get_filename(char* path) {
    char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static FILE* open_pipe(char* command, char* arg) {
    int fd[2] = {0, 0};  // fd[0] is read end, fd[1] is write end

    if (command == NULL || command[0] == '\0')
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
            dup2(STDERR_FILENO, STDOUT_FILENO);
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
    int opt = 0, quiet = 0, dump = 0;
    int wget = strcmp(get_filename(argv[0]), "wget") == 0;
    char* dest = wget ? "." : NULL;
    char* method = "GET";
    char* body = NULL;
    const char* opts = wget ? "O:q" : "o:m:b:dq";

    while ((opt = getopt(argc, argv, opts)) != -1) {
        switch (opt) {
            case 'd':
                dump = 1;
                break;
            case 'b':
                body = optarg;
                break;
            case 'm':
                method = optarg;
                break;
            case 'o':
            case 'O':
                dest = optarg;
                break;
            case 'q':
                quiet = 1;
                break;
            default:
                exit(EUSAGE);
        }
    }

    if (optind != argc - 1)
        fail(
            "usage: hget [-d] [-q] [-o <dest>] [-m <method>] [-b <body>] <url>",
            EUSAGE);

    if ((dest == NULL || strcmp(dest, "-") == 0) && isatty(1))
        quiet = 1;   // prevent mixing progress bar with output on stdout

    char* arg = argv[optind++];
    URL url = parse_url(arg);

    if (dest != NULL && strcmp(dest, "-") != 0 && isdir(dest)) {
        if (chdir(dest) != 0)
            fail("Directory is not accessible", EUSAGE);
        dest = get_filename(url.path);
        if (dest == NULL || dest[0] == '\0')
            dest = "index.html";
    }

    FILE* bar = quiet ? NULL : open_pipe(getenv("PROGRESS"), arg);
    int status = get(url, method, body, dump, dest, bar);

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
