# Introduction

hget is a minimalist HTTP GET client written in C with no dependencies. It takes a URL, performs a GET request, and sends the response body to stdout. If the HTTP status code is not a 2xx code, the first line of the response is sent to stderr in addition to the body being sent to stdout.

hget does not support https, compression, authentication, redirection, or other http methods.

hget is about 150 lines of code and compiles to a 46KB static binary with musl-gcc.


# Usage

    hget http://example.com > download.html
    hget example.com > download.html
    hget example.com:8080/path/to/image.jpg > image.jpg


# Return codes

* 0 OK
* 1 socket error
* 2 usage error
* 3 http 3xx response
* 4 http 4xx response
* 5 http 5xx response
* 6 http protocol error


# Building

Run `./make` or `env CC=musl-gcc ./make`.
