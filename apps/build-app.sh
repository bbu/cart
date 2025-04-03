#!/bin/bash

clang -shared app-foo.c -o app-foo.so \
    -Wall -Wextra \
    -D_FORTIFY_SOURCE=3 \
    -I../include/ \
    -undefined dynamic_lookup
