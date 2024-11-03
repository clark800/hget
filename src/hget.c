#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>   // PATH_MAX
#include <signal.h>
#include <sys/wait.h>
#include "util.h"
#include "interact.h"

// "There are three common forms of intermediary: proxy, gateway, and tunnel.
// A proxy is a forwarding agent, receiving requests for a URI in its absolute
// form, rewriting all or part of the message, and forwarding the reformatted
// request toward the server identified by the URI."
// "...the method name CONNECT for use with a proxy that can dynamically switch
// to being a tunnel"
// https://datatracker.ietf.org/doc/html/rfc2616 (1999)
const char* USAGE = "Usage: hget [options] <url>\n"
"Options:\n"
"  -o <path>       write output to the specified file or directory\n"
"  -r              resume partial download\n"
"  -n              only download if server file is newer than local file\n"
"  -q              disable progress bar\n"
"  -s              suppress all error messages after usage checks\n"
"  -t <url>        use HTTP/HTTPS tunnel\n"
"  -p <url>        use HTTP/HTTPS proxy (insecure for https)\n"
"  -w <seconds>    wait time for connection timeout\n"
"  -e              output entire response (include response header)\n"
"  -d              output direct response (disable redirects)\n"
"  -l              lax mode (output response regardless of response status)\n"
"  -x              output exact response (equivalent to -e -d -l)\n"
"  -m <method>     set the http request method\n"
"  -h <header>     add a header to the request (may be repeated)\n"
"  -a <user:pass>  add http basic authentication header\n"
"  -b <body>       set the body of the request\n"
"  -u <path>       upload file as request body\n"
"  -f              force https connection even if it is insecure\n"
"  -c <path>       use the specified CA cert file or directory\n"
"  -i <path>       set the client identity certificate\n"
"  -k <path>       set the client private key\n";

// ISO C99 6.7.8/10 static objects are initialized to 0
static int quiet, entire, direct, lax, update, insecure, timeout, tunnel;
static int suppress, resume, nheaders, wget;
static char *dest, *upload, *proxyurl, *auth, *cacerts, *cert, *key, *method;
static char *body, *headers[32];

static void timeout_fail(int signal) {
    (void)signal;
    fail("error: timeout", ETIMEOUT);
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

static void usage(int status, int full) {
    fputs(wget ? "Usage: wget [-q] [-O <path>] <url>\n" :
         (full ? USAGE : "Usage: hget [options] <url>\n"), stderr);
    exit(status);
}

static void parse_args(int argc, char* argv[]) {
    // glibc bug: https://sourceware.org/bugzilla/show_bug.cgi?id=25658
    optind = 1;  // https://stackoverflow.com/a/60484617/2647751
    const char* opts = wget ? "O:q" : "o:u:t:p:w:a:c:m:h:b:i:k:fqsnredlx";
    for (int opt; (opt = getopt(argc, argv, opts)) != -1;) {
        switch (opt) {
            case 'O':
            case 'o': dest = optarg; break;
            case 'r': resume = 1; break;
            case 't': proxyurl = optarg; tunnel = 1; break;
            case 'p': proxyurl = optarg; tunnel = 0; break;
            case 'f': insecure = 1; break;
            case 'w': timeout = atoi(optarg); break;
            case 'a': auth = optarg; break;
            case 'c': cacerts = optarg; break;
            case 'n': update = 1; break;
            case 'e': entire = 1; break;
            case 'd': direct = 1; break;
            case 'l': lax = 1; break;
            case 'x': entire = 1; direct = 1; lax = 1; break;
            case 'b': body = optarg; upload = NULL; break;
            case 'm': method = optarg; break;
            case 'u': upload = optarg; body = NULL; break;
            case 'q': quiet = 1; suppress |= wget; break;
            case 's': suppress = 1; break;
            case 'i': cert = optarg; break;
            case 'k': key = optarg; break;
            case 'h':
                if (nheaders >= (int)(sizeof(headers)/sizeof(char*) - 2))
                    fail("Too many header arguments", EUSAGE);
                headers[nheaders++] = optarg;
                break;
            default:
                if (argc == 2 && optopt == 'h')  // treat this like "help"
                    usage(0, 1);
                exit(EUSAGE);
        }
    }
}

static char* next(char* p, char* delim, char* quotes) {
    // d points to the next character after the end of the current token
    char* d = strchr(quotes, p[0]) ? strchr(p + 1, p[0]) : strpbrk(p, delim);
    return d ? (*d = 0, (d + 1) + strspn(d + 1, delim)) : d;
}

static int tokenize(char* p, char** argv, char* delim, char* quotes) {
    int argc = 1;
    for (p += strspn(p, delim); p && *p; p = next(p, delim, quotes))
        argv[argc++] = strchr(quotes, p[0]) ? p + 1 : p;
    return argc;
}

static void parse_argstring(char* argv0, char* string) {
    char* argv[strlen(string)/2 + 2]; // extra +1 since we start at argv[1]
    int argc = tokenize(string, argv, " \t\r\n", "'\"");
    argv[0] = argv0;
    parse_args(argc, argv);
}

static void parse_argfile(char* argv0, char* path, char* buffer, size_t size) {
    FILE* file = fopen(path, "r");
    if (file == NULL || fread(buffer, 1, size, file) != size)
        fail("error: failed to read argfile", EUSAGE);
    buffer[size] = 0;
    parse_argstring(argv0, buffer);
}

static char* get_config_path(char* buffer, char* relpath) {
    char* config_home = getenv("XDG_CONFIG_HOME");
    if (config_home)
        return strcat(strcat(strcpy(buffer, config_home), "/hget/"), relpath);
    char* home = getenv("HOME");
    if (home)
        return strcat(strcat(strcpy(buffer, home), "/.config/hget/"), relpath);
    return NULL;
}

int main(int argc, char *argv[]) {
    wget = strcmp(get_filename(argv[0]), "wget") == 0;
    dest = wget ? "." : NULL;

    char argfile_path[PATH_MAX];
    get_config_path(argfile_path, "args");
    size_t argfile_size = wget ? 0 : get_file_size(argfile_path);
    char buffer[argfile_size + 1];  // must be in main scope to keep optargs
    if (argfile_size)
        parse_argfile(argv[0], argfile_path, buffer, argfile_size);

    char* envargs = wget ? NULL : getenv("HGET_ARGS");
    // ISO C99 7.20.4.5: The getenv function
    // "The string pointed to shall not be modified by the program"
    char envbuf[(envargs ? strlen(envargs) : 0) + 1];
    parse_argstring(argv[0], strcpy(envbuf, envargs ? envargs : ""));

    parse_args(argc, argv);

    if (optind != argc - 1)
        usage(argc == 1 ? 0 : EUSAGE, argc == 1);

    char* arg = argv[optind++];
    URL url = parse_url(arg);

    if (!proxyurl) {
        if (strcmp(url.scheme, "https") == 0) {
            proxyurl = getenv("HTTPS_PROXY");
            if (!proxyurl)
                proxyurl = getenv("https_proxy");
        } else {
            proxyurl = getenv("HTTP_PROXY");
            if (!proxyurl)
                proxyurl = getenv("http_proxy");
        }
    }

    // modifying getenv strings is undefined behavior (ISO C99 7.20.4.5)
    char proxybuf[proxyurl ? strlen(proxyurl) + 1 : 1];
    strcpy(proxybuf, proxyurl ? proxyurl : "");
    URL proxy = proxyurl ? parse_url(proxybuf) : (URL){0};

    if (!auth && url.userinfo[0])
        auth = url.userinfo;  // so auth will apply to redirects

    if (resume && (is_stdout(dest) || isdir(dest) || access(dest, W_OK) != 0))
        fail("error: partial download file is invalid or inaccessible", EUSAGE);

    if (!is_stdout(dest) && isdir(dest) && chdir(dest) != 0)
        fail("error: output directory is not accessible", EUSAGE);

    if ((cert && !key) || (key && !cert))
        fail("error: -i and -k options must be used together", EUSAGE);

    if (upload && isdir(upload))
        fail("error: upload cannot be a directory", EUSAGE);

    if (timeout)
        signal(SIGALRM, timeout_fail);

    if (is_stdout(dest) && isatty(1))
        quiet = 1;   // prevent mixing progress bar with output on stdout

    FILE* bar = quiet ? NULL : open_pipe(getenv("PROGRESS"), arg);
    if (suppress)  // do this here so that usage errors still print to stderr
        freopen("/dev/null", "w", stderr);
    int status_code = interact(url, proxy, tunnel, auth, method, headers, body,
                          upload, dest, entire, direct, lax, update, resume,
                          cacerts, cert, key, insecure, timeout, bar, 0);

    if (bar) {
        fclose(bar); // this will cause bar to get EOF and exit soon
        wait(NULL);  // wait for bar to finish drawing
    }

    if (lax || status_code/100 == 2 || status_code/100 == 3)
        return OK;
    if (status_code == 404 || status_code == 410)
        return ENOTFOUND;
    if (status_code/100 == 4)
        return EREQUEST;
    return ESERVER;  // 5xx, 1xx, and invalid status codes
}
