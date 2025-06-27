#!/bin/bash

clang -shared app-foo.c -o app-foo.so \
    -Wall -Wextra -Wno-unused \
    -D_FORTIFY_SOURCE=3 \
    -I../include/ \
    -undefined dynamic_lookup
