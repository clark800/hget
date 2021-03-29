#!/bin/sh

"${CC:-cc}" \
    -std=c99 -pedantic -D_POSIX_C_SOURCE=200112L -Wall -Wextra -Wshadow \
    -O2 -fpie -s -static -o hget hget.c
