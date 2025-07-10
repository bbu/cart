#pragma once

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define countof(arr) (sizeof(arr) / sizeof(*(arr)))

#define powerof2(x) ({ \
    const typeof(x) x_once = (x); \
    x_once && !(x_once & (x_once - 1)); \
})

#include <stdio.h> /* printf */
#include <time.h> /* time() */
#include <errno.h> /* errno */
#include <string.h> /* strerror() */

#define log_info(fmt, ...) \
    printf("%lu [INFO] " fmt "\n", time(NULL), ##__VA_ARGS__)

#define log_warn(fmt, ...) \
    printf("%lu [WARN] " fmt "\n", time(NULL), ##__VA_ARGS__)

#define log_errno(msg) \
    printf("%lu [ERRN] (%s:%u) " msg ": [%d] %s\n", time(NULL), __FILE__, __LINE__, errno, strerror(errno))

#define log_error(fmt, ...) \
    printf("%lu [ERR ] (%s:%u) " fmt "\n", time(NULL), __FILE__, __LINE__, ##__VA_ARGS__)

#define log_app(fmt, ...) \
    printf("%lu [APPL] " fmt "\n", time(NULL), ##__VA_ARGS__)
