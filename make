#!/bin/sh
# note: sockets are not part of the C99 standard so we can't use -std=c99
"${CC:-cc}" -Wall -Wextra -Os -s -static -o hget hget.c
