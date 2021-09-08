# Introduction

hget is a minimalist HTTP/HTTPS GET client written in C. It takes a URL, performs a GET request, and sends the response body to stdout. If the HTTP status code is not a valid 2xx code, the first line of the response is sent to stderr in addition to the body being sent to stdout.

hget does not support compression, authentication, redirection, or other http methods.

hget is about 300 lines of code and compiles with musl to a 54KB static binary without https support, or a 174KB static binary with https support.


# Usage

    hget http://example.com > download.html
    hget example.com > download.html
    hget example.com:8080/path/to/image.jpg > image.jpg

A script called `dl` is included which shows a progress bar for downloads using [bar](https://github.com/clark800/bar).

    dl example.com/file.ext


# Building

Run `./make` to build without https support.

Run `./make bearssl` or `./make libressl` to build with https support.

Building with `bearssl` requires both [bearssl](https://bearssl.org/)
and [libtls-bearssl](https://github.com/michaelforney/libtls-bearssl).
Building with `libressl` requires [libressl](http://www.libressl.org/).

To set the CA bundle path set the `CA_BUNDLE` environment variable.

To build with the `musl-gcc` wrapper, use e.g. `env CC=musl-gcc ./make`.


# Return codes

* 0 - OK
* 1 - 1xx http response code
* 2 - 203 http response code
* 3 - 3xx http response code
* 4 - 4xx http response code, except 404 or 410
* 5 - 5xx http response code
* 44 - resource not found or gone (404 or 410)
* 254 - usage error
* 255 - failure
