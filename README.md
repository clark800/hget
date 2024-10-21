# Introduction

hget is a minimalist HTTP/HTTPS client and download utility written in C.

#### Features
* Download progress can be sent to an external progress bar utility.
* Automatically follows HTTP 3xx redirects.
* If the destination file exists, it will only be downloaded if the modification
  time on the server is newer than the modification time of the local file
  (using the If-Modified-Since header).
* Exit status codes are more helpful than curl defaults.

#### Size
* About 400 lines of code
* 66KB static binary without https support
* 234KB static binary with https support


# Usage

    hget [-d] [-q] [-o <dest>] [-c <cacerts>]
         [-m <method>] [-h <header>]... [-b <body>] <url>

The `-d` flag dumps the full response including headers.

To show a progress bar, install a progress bar utility like
[bar](https://github.com/clark800/bar) and set the `PROGRESS` environment
variable to the name of the utility. The `-q` flag disables the progress bar.


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
