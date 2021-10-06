#!/bin/sh

case "$1" in
    '') SOURCES="hget.c stub.c"; LIBS="";;
    bearssl) SOURCES="hget.c tls.c"; LIBS="-ltls -lbearssl";;
    libressl) SOURCES="hget.c tls.c"; LIBS="-ltls";;
    sloc) gcc -fpreprocessed -dD -E -P *.c *.h | wc -l; exit 0;;
    clean) rm -f hget; exit 0;;
    *) echo "unrecognized target" >&2; exit 1;;
esac

"${CC:-cc}" -std=c99 \
    ${CFLAGS--O2 -fno-asynchronous-unwind-tables} \
    ${LDFLAGS--s -static -Wl,--gc-sections} \
    -Wpedantic -Wall -Wextra -Wfatal-errors -Wshadow -Wcast-qual \
    -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls \
    -D CA_BUNDLE="\"${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}\"" \
    -o hget $SOURCES $LIBS
