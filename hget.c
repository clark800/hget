#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>  // strncasecmp
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
    char *url, *scheme, *userinfo, *host, *port, *path, *query, *fragment;
} URL;

static int get(URL url, URL proxy, char* auth, char* method, char** headers,
        char* body, int dump, int ignore, char* dest, int update, char* cacerts,
        int insecure, int timeout, FILE* bar, int redirects);

static size_t min(size_t a, size_t b) {
    return a < b ? a : b;
}

static int is_stdout(char* dest) {
    // "-" is interpreted as stdout for compatibility with wget
    return dest == NULL || strcmp(dest, "-") == 0;
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

static char* get_filename(char* path) {
    char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
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

static void* fail(const char* message, int status) {
    fputs(message, stderr);
    fputs("\n", stderr);
    exit(status);
    return NULL;
}

static void timeout_fail(int signal) {
    (void)signal;
    fail("error: timeout", EFAIL);
}

static void sfail(const char* message) {
    perror(message);
    exit(EFAIL);
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

static void swrite(FILE* sock, const char* buf) {
    size_t size = strlen(buf);
    if (fwrite(buf, 1, size, sock) < size)
        sfail("send failed");
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

static URL parse_url(char* str, char* buffer) {
    // truncate at \r or \n in case this is a location header
    str[strcspn(str, "\r\n")] = 0;

    // url.url is the full url without the fragment
    URL url = {.url=str, .scheme="http", .userinfo="", .path="", .query="",
               .fragment=""};
    url.port = strncmp(str, "https://", 8) == 0 ? "443" : "80";

    // fragment can contain any character, so chop off first
    char* hash = strchr(str, '#');
    if (hash) {
        hash[0] = '\0';
        url.fragment = hash + 1;
    }

    str = strcpy(buffer, str);

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

static int conn(char* host, char* port, int timeout) {
    alarm(timeout);
    struct addrinfo *server, hints = {.ai_socktype = SOCK_STREAM};
    if (getaddrinfo(host, port, &hints, &server) != 0)
        sfail("getaddrinfo failed");

    int sockfd = socket(server->ai_family, server->ai_socktype,
        server->ai_protocol);

    if (sockfd == -1)
        sfail("socket create failed");

    if (connect(sockfd, server->ai_addr, server->ai_addrlen) != 0)
        sfail("connect failed");

    alarm(0);
    freeaddrinfo(server);
    return sockfd;
}

static size_t write_auth(char* buffer, size_t N, char* name, char* auth) {
    size_t m = strlen(auth);
    size_t n = snprintf(buffer, N, "%s: Basic ", name);
    if (4 * ((m + 2) / 3) >= (n < N ? N - n : 0))
        fail("error: auth string too long", EFAIL);
    n += base64encode(auth, m, buffer + n);
    n += snprintf(buffer + n, n < N ? N - n : 0, "\r\n");
    return n;
}

static void request(char* buffer, FILE* sock, URL url, URL proxy, char* auth,
        char* method, char** headers, char* body, char* dest, int update) {
    struct stat sb;
    size_t n = 0, N = BUFSIZE;

    n += snprintf(buffer + n, n < N ? N - n : 0, "%s ", method);
    if (proxy.host) {
        if (!strstr(url.url, "://"))
            n += snprintf(buffer + n, n < N ? N - n : 0, "%s://", url.scheme);
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s", url.url);
    } else {
        n += snprintf(buffer + n, n < N ? N - n : 0, "/%s", url.path);
        if (url.query[0])
            n += snprintf(buffer + n, n < N ? N - n : 0, "?%s", url.query);
    }
    n += snprintf(buffer + n, n < N ? N - n : 0, " HTTP/1.1\r\n");
    if (proxy.userinfo && proxy.userinfo[0])
        n += write_auth(buffer + n, n < N ? N - n : 0, "Proxy-Authorization",
                proxy.userinfo);

    n += snprintf(buffer + n, n < N ? N - n : 0, "Host: %s\r\n", url.host);
    n += snprintf(buffer + n, n < N ? N - n : 0, "Connection: close\r\n");
    n += snprintf(buffer + n, n < N ? N - n : 0,
            "Accept-Encoding: identity\r\n");
    if (!auth)
        auth = url.userinfo;
    if (auth && auth[0])
        n += write_auth(buffer + n, n < N ? N - n : 0, "Authorization", auth);
    if (update && !is_stdout(dest) && stat(dest, &sb) == 0) {
        char time[32];
        struct tm* timeinfo = gmtime(&sb.st_mtime);
        strftime(time, sizeof(time), "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
        n += snprintf(buffer + n, n < N ? N - n : 0,
                "If-Modified-Since: %s\r\n", time);
    }
    while (*headers != NULL)
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s\r\n", *(headers++));
    if (body)
        n += snprintf(buffer + n, n < N ? N - n : 0,
                "Content-Length: %zu\r\n", strlen(body));
    n += snprintf(buffer + n, n < N ? N - n : 0, "\r\n");

    if (n >= N)
        fail("error: request too large", EFAIL);

    if (body && strlen(body) < (n < N ? N - n : 0)) {
        n += snprintf(buffer + n, n < N ? N - n : 0, "%s", body);
        swrite(sock, buffer);
    } else {
        swrite(sock, buffer);
        if (body)
            swrite(sock, body);
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
    return fail("error: response headers too long", EFAIL);
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
        char* method, int dump, int ignore, FILE* bar) {
    size_t headlen = read_head(sock, buffer, BUFSIZE);
    if (headlen == 0)
        fail("error: response headers too long", EFAIL);
    int status_code = parse_status_line(buffer);
    if (ignore || status_code / 100 == 2) {
        FILE* out = open_file(dest, url);
        if (dump)
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

static FILE* opensock(URL server, char* cacerts, int insecure, int timeout) {
    (void)cacerts, (void)insecure; // prevent unused warning for non-https build
    int sockfd = conn(server.host, server.port, timeout);
    int https = strcmp(server.scheme, "https") == 0;
    FILE* sock = https ? fopentls(sockfd, server.host, cacerts, insecure) :
        fdopen(sockfd, "r+");
    if (sock == NULL)
        sfail(https ? "start TLS failed" : "fdopen failed");
    return sock;
}

static int get(URL url, URL proxy, char* auth, char* method, char** headers,
        char* body, int dump, int ignore, char* dest, int update, char* cacerts,
        int insecure, int timeout, FILE* bar, int redirects) {
    char buffer[BUFSIZE];
    FILE* sock = opensock(proxy.host ? proxy : url, cacerts, insecure, timeout);
    request(buffer, sock, url, proxy, auth, method, headers, body, dest, update);
    int status_code = handle_response(buffer, sock, url, dest, method,
                                      dump, ignore, bar);
    fclose(sock);
    if (!ignore && status_code / 100 == 3 && status_code != 304) {
        if (redirects >= 20)
            fail("error: too many redirects", EFAIL);
        char* location = get_header(buffer, "Location:");
        if (location == NULL)
            fail("error: redirect missing location", EFAIL);
        char urlbuf[strlen(location)];
        URL locurl = parse_url(location, urlbuf);
        method = status_code == 303 ? "GET" : method;
        return get(locurl, proxy, auth, method, headers, body, dump, ignore,
               dest, update, cacerts, insecure, timeout, bar, redirects + 1);
    }
    return status_code;
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
            execlp(command, arg, (char*)0);
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
    int opt = 0, quiet = 0, dump = 0, update = 0, insecure = 0, nheaders = 0;
    int ignore = 0, timeout = 0;
    int wget = strcmp(get_filename(argv[0]), "wget") == 0;
    char* dest = wget ? "." : NULL;
    char* proxyurl = NULL;
    char* auth = NULL;
    char* cacerts = CA_BUNDLE;
    char* method = "GET";
    char* headers[32] = {0};
    char* body = NULL;
    const char* opts = wget ? "O:q" : "o:p:t:a:c:m:h:b:dfqui";

    if (getenv("CA_BUNDLE"))
        cacerts = getenv("CA_BUNDLE");
    if (getenv("HGET_CA_BUNDLE"))
        cacerts = getenv("HGET_CA_BUNDLE");

    while ((opt = getopt(argc, argv, opts)) != -1) {
        switch (opt) {
            case 'd':
                dump = 1;
                break;
            case 'p':
                proxyurl = optarg;
                break;
            case 'f':
                insecure = 1;
                break;
            case 't':
                timeout = atoi(optarg);
                break;
            case 'a':
                auth = optarg;
                break;
            case 'c':
                cacerts = optarg;
                break;
            case 'u':
                update = 1;
                break;
            case 'i':
                ignore = 1;
                break;
            case 'b':
                body = optarg;
                break;
            case 'm':
                method = optarg;
                break;
            case 'h':
                if (nheaders >= (int)(sizeof(headers)/sizeof(char*) - 2))
                    fail("Too many header arguments", EUSAGE);
                headers[nheaders++] = optarg;
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

    if (optind != argc - 1) {
        if (wget)
            fail("Usage: wget [-q] [-O <path>] <url>", EUSAGE);
        else
            fail("Usage: hget [options] <url>\n"
            "Options:\n"
            "  -o <path>       write output to the specified file or directory\n"
            "  -p <url>        use HTTP/HTTPS proxy\n"
            "  -t <seconds>    set connection timeout\n"
            "  -u              only download if server file is newer\n"
            "  -q              disable progress bar\n"
            "  -f              force https connection even if it is insecure\n"
            "  -d              dump full response including headers\n"
            "  -i              ignore response status; always output response\n"
            "  -a <user:pass>  add http basic authentication header\n"
            "  -m <method>     set the http request method\n"
            "  -h <header>     add a header to the request (may be repeated)\n"
            "  -b <body>       set the body of the request\n"
            "  -c <path>       use the specified CA certificates file"
            , EUSAGE);
    }

    if (is_stdout(dest) && isatty(1))
        quiet = 1;   // prevent mixing progress bar with output on stdout

    char* arg = argv[optind++];
    char buffer[strlen(arg)];
    URL url = parse_url(arg, buffer);
    char proxybuf[proxyurl ? strlen(proxyurl) : 0];
    URL proxy = proxyurl ? parse_url(proxyurl, proxybuf) : (URL){0};

    if (!auth && url.userinfo[0])
        auth = url.userinfo;  // so auth will apply to redirects

    if (!is_stdout(dest) && isdir(dest) && chdir(dest) != 0)
        fail("error: directory is not accessible", EUSAGE);

    if (timeout)
        signal(SIGALRM, timeout_fail);

    FILE* bar = quiet ? NULL : open_pipe(getenv("PROGRESS"), arg);
    int status_code = get(url, proxy, auth, method, headers, body, dump, ignore,
                          dest, update, cacerts, insecure, timeout, bar, 0);

    if (bar) {
        fclose(bar); // this will cause bar to get EOF and exit soon
        wait(NULL);  // wait for bar to finish drawing
    }

    if (ignore || status_code / 100 == 2 || status_code == 304)
        return OK;

    if (status_code == 404 || status_code == 410)
        return ENOTFOUND;
    if (status_code / 100 == 4)
        return EREQUEST;
    if (status_code / 100 == 5)
        return ESERVER;
    return EFAIL;
}
