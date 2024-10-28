# Introduction

hget is a minimalist HTTP/HTTPS client and download utility written in C.
hget is designed to provide 99% of the value-weighted utility of curl in
<1% as much code.

#### Features
* Download progress can be sent to an external progress bar utility.
* Automatically follows HTTP 3xx redirects.
* If the destination file exists and the `-u` option is specified,
  the file will only be downloaded if the modification time on the server is
  more recent than the modification time of the local file
  (using the If-Modified-Since header).
* Exit status codes are more helpful than curl defaults.

#### Size
* Under 600 lines of code (<0.5% the size of curl at ~134,000 lines)
* 66KB static binary without https support
* 234KB static binary with https support


# Usage

    Usage: hget [options] <url>
    Options:
      -o <dest>       write output to the specified file
      -t <timeout>    abort if connect takes too long (seconds)
      -u              only download if server file is newer
      -q              disable progress bar
      -f              force https connection even if it is insecure
      -d              dump full response including headers
      -i              ignore response status; always output response
      -a <user:pass>  add http basic authentication header
      -m <method>     set the http request method
      -h <header>     add a header to the request (may be repeated)
      -b <body>       set the body of the request
      -c <cacerts>    use the specified CA certificates file

To download a file to the current directory, use `hget -o. <url>`.

To show a progress bar, install a progress bar utility like
[bar](https://github.com/clark800/bar) and set the `PROGRESS` environment
variable to the name of the utility.


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
