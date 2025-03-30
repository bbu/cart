#!/bin/bash

clang -shared app-foo.c -o app-foo.so -Wall -Wextra -I../include/ -undefined dynamic_lookup
