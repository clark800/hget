# Introduction

hget is a minimalist HTTP/HTTPS download utility written in C.
It takes a URL, performs a GET request, and sends the response body to stdout
or a specified file. It automatically follows redirects. If the destination
file exists, it will only be downloaded if the modification time on the server
is newer than the modification time of the file (using If-Modified-Since).
It does not support compression, authentication, proxying, or other http methods.

hget is about 300 lines of code and compiles with musl to a 62KB static binary
without https support, or a 230KB static binary with https support.


# Usage

    hget <url> [<dest>]

A script called `dl` is included which shows a progress bar for downloads using [bar](https://github.com/clark800/bar).

    dl <url>


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
* 1 - failure
* 2 - usage error
* 3 - not found or gone (404 or 410)
* 4 - request error (4xx, except 404 or 410)
* 5 - server error (5xx)
