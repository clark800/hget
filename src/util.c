#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "util.h"

void* fail(const char* message, int status) {
    fprintf(stderr, "%s\n", message);
    exit(status);
    return NULL;
}

void sfail(const char* message) {
    perror(message);
    exit(EFAIL);
}

char* get_filename(char* path) {
    char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

int is_stdout(char* dest) {
    // "-" is interpreted as stdout for compatibility with wget
    return dest == NULL || strcmp(dest, "-") == 0;
}

void swrite(FILE* sock, const char* buf) {
    size_t size = strlen(buf);
    if (fwrite(buf, 1, size, sock) < size)
        sfail("send failed");
}

int isdir(const char* path) {
    // "If the named file is a symbolic link, the stat() function shall
    // continue pathname resolution using the contents of the symbolic link,
    // and shall return information pertaining to the resulting file if the
    // file exists."
    // (https://pubs.opengroup.org/onlinepubs/000095399/functions/stat.html)
    struct stat sb;
    return path != NULL && stat(path, &sb) == 0 && S_ISDIR(sb.st_mode);
}

URL parse_url(char* str) {
    // truncate at \r or \n in case this is a location header
    str[strcspn(str, "\r\n")] = 0;

    URL url = {.scheme="", .userinfo="", .host="", .port="", .path="",
               .query="", .fragment=""};

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
