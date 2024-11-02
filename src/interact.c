#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include "util.h"
#include "tls.h"
#include "request.h"
#include "response.h"
#include "interact.h"

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
    check_proxy_connect(buffer, proxysock);

    if (strcmp(url.scheme, "https") != 0)
        return proxysock;

    FILE* sock = wrap_tls(proxysock, url.host, cacerts, cert, key, insecure);
    if (sock == NULL)
        fail("error: wrap_tls failed", EFAIL);
    return sock;
}

int interact(URL url, URL proxy, int relay, char* auth, char* method,
        char** headers, char* body, char* upload, char* dest, int explicit,
        int direct, int update, char* cacerts, char* cert, char* key,
        int insecure, int timeout, FILE* bar, int redirects) {
    char buffer[BUFSIZE];
    FILE* proxysock = proxy.host ?
        opensock(proxy, cacerts, cert, key, 0, timeout) : NULL;
    FILE* sock = proxy.host ? (relay ? proxysock : proxy_connect(buffer,
                 proxysock, url, proxy, cacerts, cert, key, insecure)) :
                 opensock(url, cacerts, cert, key, insecure, timeout);

    request(buffer, sock, url, relay ? proxy : (URL){0}, auth, method, headers,
            body, upload, dest, update);
    int status_code = handle_response(buffer, sock, url, dest, method,
                                      explicit, direct, bar);
    fclose(sock);
    if (proxysock && proxysock != sock)
        fclose(proxysock);

    if (!direct && status_code/100 == 3 && status_code != 304) {
        if (redirects >= 20)
            fail("error: too many redirects", EFAIL);
        char* location = get_header(buffer, "Location:");
        if (location == NULL)
            fail("error: redirect missing location", EFAIL);
        return interact(parse_url(location), proxy, relay, auth,
            status_code == 303 ? "GET" : method, headers, body, upload, dest,
            explicit, direct, update, cacerts, cert, key, insecure, timeout,
            bar, redirects + 1);
    }
    return status_code;
}
