#!/bin/bash

clang supervisor.c sandbox.c -fno-strict-aliasing -std=gnu11 -Wall -Wextra -pedantic -Wno-gnu-zero-variadic-macro-arguments -Wno-gnu-case-range
