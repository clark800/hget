#!/bin/sh

# test if a function is available in a library
have() {
    header_name="$1"
    function_name="$2"
    echo "#define _GNU_SOURCE" > .configure.c
    echo "#include <$header_name.h>" >> .configure.c
    echo "int main(void) { (void)$function_name; }" >> .configure.c
    "${CC:-cc}" -o /dev/null .configure.c > /dev/null 2> /dev/null
    result="$?"
    rm .configure.c
    return "$result"
}

case "$1" in
    '') SOURCES="hget.c"; LIBS="";;
    bearssl) TLS=1; SOURCES="hget.c tls.c"; LIBS="-ltls -lbearssl";;
    libressl) TLS=1; SOURCES="hget.c tls.c"; LIBS="-ltls";;
    brew) TLS=1 SOURCES="hget.c tls.c"; LIBS="-ltls"
        LDFLAGS="-L/opt/homebrew/opt/libretls/lib"
        CPPFLAGS="-I/opt/homebrew/opt/libretls/include"
        CA_BUNDLE="/opt/homebrew/etc/ca-certificates/cert.pem";;
    sloc) gcc -fpreprocessed -dD -E -P *.c *.h | wc -l; exit 0;;
    clean) rm -f hget; exit 0;;
    *) echo "unrecognized target" >&2; exit 1;;
esac

if [ "$TLS" = 1 ]; then
    CPPFLAGS="$CPPFLAGS -D TLS"
    if ! have stdio fopencookie; then
        CPPFLAGS="$CPPFLAGS -D NEED_FOPENCOOKIE"
        SOURCES="$SOURCES shim.c"
    fi
fi

"${CC:-cc}" $CPPFLAGS ${CFLAGS--O2} $LDFLAGS -std=c99 \
    -Wpedantic -Wall -Wextra -Wfatal-errors -Wshadow -Wcast-qual \
    -Wmissing-prototypes -Wstrict-prototypes -Wredundant-decls \
    -D CA_BUNDLE="\"${CA_BUNDLE:-/etc/ssl/certs/ca-certificates.crt}\"" \
    -D BUFSIZE="${HGET_BUFSIZE:-8192}" \
    -o hget $SOURCES $LIBS
