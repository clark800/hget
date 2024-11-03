# Introduction

hget is a minimalist HTTP/HTTPS client and download utility written in C.

hget is designed to provide 99% of the value-weighted utility of curl in
<1% as much code.

#### Size
* About 850 lines of code (0.6% the size of curl at ~134,000 lines)

#### Features
* Progress bar
* 3xx redirects by default
* Resuming partial downloads
* Download only if newer
* Compressed responses
* Basic authentication
* HTTP/HTTPS proxy
* HTTP/HTTPS tunnel (including TLS in TLS)
* Upload file
* Set body, method, headers
* Custom CA certificates
* Client certificates

#### Portability
* Should be portable to any POSIX-like system that has either
  fopencookie (Linux) or funopen (BSD).

# Usage

    Usage: hget [options] <url>
    Options:
      -o <path>       write output to the specified file or directory
      -n <path>       only download if server file is newer than local file
      -r              resume partial download
      -q              disable progress bar
      -s              suppress all error messages after usage checks
      -t <url>        use HTTP/HTTPS tunnel
      -p <url>        use HTTP/HTTPS proxy (insecure for https)
      -w <seconds>    wait time for connection timeout
      -e              output entire response (include response header)
      -d              output direct response (disable redirects)
      -l              lax mode (output response regardless of response status)
      -x              output exact response (equivalent to -e -d -l)
      -m <method>     set the http request method
      -h <header>     add a header to the request (may be repeated)
      -j              add content-type header for json
      -a <user:pass>  add http basic authentication header
      -b <body>       set the body of the request
      -u <path>       upload file as request body
      -z              request a gzip compressed response and output gzip file
      -f              force https connection even if it is insecure
      -c <path>       use the specified CA cert file or directory
      -i <path>       set the client identity certificate
      -k <path>       set the client private key
      -v              show verbose output

To download a file to the current directory, use `hget -o. <url>`.

To show a progress bar, install a progress bar utility like
[bar](https://github.com/clark800/bar) and set the `PROGRESS` environment
variable to the name of the utility.

To use a CA certificate directory, make sure each certificate in the directory
is in a separate file (not bundled) and run `c_rehash` on the direcory. Note
that CA directories are not supported in bearssl builds.

# Building

Run `./make` to build without https support.

Run `./make bearssl` or `./make libressl` to build with https support.

Building with `bearssl` requires both [bearssl](https://bearssl.org/)
and [libtls-bearssl](https://github.com/michaelforney/libtls-bearssl).
Building with `libressl` requires [libressl](http://www.libressl.org/).

To build with the `musl-gcc` wrapper, use e.g. `env CC=musl-gcc ./make`.


# Return codes

* 0 - OK (2xx or 3xx)
* 1 - not found or gone (404 or 410)
* 2 - request error (4xx, except 404 or 410)
* 3 - server error or unexpected status (5xx, 1xx)
* 4 - too many redirects
* 5 - proxy error
* 6 - protocol error
* 7 - timeout error
* 8 - system or network error
* 9 - usage error
