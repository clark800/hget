#!/bin/sh

case "$1" in
    '') CPPFLAGS="-DNO_TLS"; SOURCES="hget.c"; LIBS="";;
    bearssl) SOURCES="hget.c tls.c"; LIBS="-ltls -lbearssl";;
    libressl) SOURCES="hget.c tls.c"; LIBS="-ltls";;
    brew) SOURCES="hget.c tls.c"; LIBS="-ltls"
        LDFLAGS="-L/opt/homebrew/opt/libretls/lib"
        CPPFLAGS="-I/opt/homebrew/opt/libretls/include"
        CA_BUNDLE="/opt/homebrew/etc/ca-certificates/cert.pem";;
    sloc) gcc -fpreprocessed -dD -E -P *.c *.h | wc -l; exit 0;;
    clean) rm -f hget; exit 0;;
    *) echo "unrecognized target" >&2; exit 1;;
esac

"${CC:-cc}" $CPPFLAGS ${CFLAGS--O2} $LDFLAGS -std=c99 \
    -Wpedantic -Wall -Wextra -Wfatal-errors -Wshadow -Wcast-qual \
    -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls \
    -D CA_BUNDLE="\"${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}\"" \
    -o hget $SOURCES $LIBS
