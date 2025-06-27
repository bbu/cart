#!/bin/bash

clang -std=gnu17 supervisor.c sandbox.c timer.c slab.c hook.c \
    -fno-strict-aliasing \
    -D_ISOC11_SOURCE -D_FORTIFY_SOURCE=3 -D_BSD_SOURCE \
    -Wall -Wextra -pedantic \
    -Wno-gnu-zero-variadic-macro-arguments \
    -Wno-gnu-case-range \
    -Wno-gnu-statement-expression-from-macro-expansion \
    -Wno-language-extension-token \
    -lm
