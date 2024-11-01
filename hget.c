#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include "util.h"
#include "interact.h"

const char* USAGE = "Usage: hget [options] <url>\n"
"Options:\n"
"  -o <path>       write output to the specified file or directory\n"
"  -n              only download if server file is newer than local file\n"
"  -q              disable progress bar\n"
"  -p <url>        use HTTP/HTTPS tunneling proxy\n"
"  -r <url>        use HTTP/HTTPS relay proxy (insecure for https)\n"
"  -t <seconds>    set connection timeout\n"
"  -x              output explicit response; ignore response status\n"
"  -m <method>     set the http request method\n"
"  -h <header>     add a header to the request (may be repeated)\n"
"  -a <user:pass>  add http basic authentication header\n"
"  -b <body>       set the body of the request\n"
"  -u <path>       upload file as request body\n"
"  -f              force https connection even if it is insecure\n"
"  -c <path>       use the specified CA cert file or directory\n"
"  -i <path>       set the client identity certificate\n"
"  -k <path>       set the client private key\n";

static void timeout_fail(int signal) {
    (void)signal;
    fail("error: timeout", EFAIL);
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

static void usage(int status, int full, int wget) {
    fputs(wget ? "Usage: wget [-q] [-O <path>] <url>\n" :
         (full ? USAGE : "Usage: hget [options] <url>\n"), stderr);
    exit(status);
}

int main(int argc, char *argv[]) {
    int quiet = 0, explicit = 0, update = 0, insecure = 0, timeout = 0;
    int relay = 0, nheaders = 0;
    int wget = strcmp(get_filename(argv[0]), "wget") == 0;
    char *dest = wget ? "." : NULL, *upload = NULL, *proxyurl = NULL,
         *auth = NULL, *cacerts = NULL, *cert = NULL, *key = NULL,
         *method = "GET", *body = NULL;
    char* headers[32] = {0};

    const char* opts = wget ? "O:q" : "o:u:p:r:t:a:c:m:h:b:i:k:fqnx";
    for (int opt; (opt = getopt(argc, argv, opts)) != -1;) {
        switch (opt) {
            case 'p':
                proxyurl = optarg;
                relay = 0;
                break;
            case 'r':
                proxyurl = optarg;
                relay = 1;
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
            case 'n':
                update = 1;
                break;
            case 'x':
                explicit = 1;
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
                break;
            case 'o':
            case 'O':
                dest = optarg;
                break;
            case 'u':
                upload = optarg;
                break;
            case 'q':
                quiet = 1;
                break;
            case 'i':
                cert = optarg;
                break;
            case 'k':
                key = optarg;
                break;
            default:
                if (argc == 2 && optopt == 'h')  // treat this like "help"
                    usage(0, 1, wget);
                exit(EUSAGE);
        }
    }

    if (optind != argc - 1)
        usage(argc == 1 ? 0 : EUSAGE, argc == 1, wget);

    char* arg = argv[optind++];
    URL url = parse_url(arg);

    if (!proxyurl)
        proxyurl = getenv("HGET_PROXY");
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

    if (!cacerts)
        cacerts = getenv("HGET_CA_BUNDLE");
    if (!cacerts)
        cacerts = getenv("CA_BUNDLE");
    if (!cacerts)
        cacerts = CA_BUNDLE;

    if (!auth && url.userinfo[0])
        auth = url.userinfo;  // so auth will apply to redirects

    if (!is_stdout(dest) && isdir(dest) && chdir(dest) != 0)
        fail("error: output directory is not accessible", EUSAGE);

    if (body && upload)
        fail("error: -b and -u options are exclusive", EUSAGE);

    if ((cert && !key) || (key && !cert))
        fail("error: -i and -k options must be used together", EUSAGE);

    if (upload && isdir(upload))
        fail("error: upload cannot be a directory", EUSAGE);

    if (timeout)
        signal(SIGALRM, timeout_fail);

    if (is_stdout(dest) && isatty(1))
        quiet = 1;   // prevent mixing progress bar with output on stdout

    FILE* bar = quiet ? NULL : open_pipe(getenv("PROGRESS"), arg);
    int status_code = interact(url, proxy, relay, auth, method, headers, body,
                          upload, dest, explicit, update, cacerts, cert, key,
                          insecure, timeout, bar, 0);

    if (bar) {
        fclose(bar); // this will cause bar to get EOF and exit soon
        wait(NULL);  // wait for bar to finish drawing
    }

    if (explicit || status_code / 100 == 2 || status_code == 304)
        return OK;
    if (status_code == 404 || status_code == 410)
        return ENOTFOUND;
    if (status_code / 100 == 4)
        return EREQUEST;
    if (status_code / 100 == 5)
        return ESERVER;
    return EFAIL;
}
