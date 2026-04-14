#ifndef TRUSTPROBE_TEST_ASSERT_HELPERS_H
#define TRUSTPROBE_TEST_ASSERT_HELPERS_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline void assert_true(const char *name, bool value) {
    if (!value) {
        fprintf(stderr, "test failure: %s\n", name);
        exit(1);
    }
}

static inline void assert_false(const char *name, bool value) {
    if (value) {
        fprintf(stderr, "test failure: %s\n", name);
        exit(1);
    }
}

static inline void assert_eq_sz(const char *name, size_t got, size_t expected) {
    if (got != expected) {
        fprintf(stderr, "test failure: %s (got %zu, expected %zu)\n", name, got, expected);
        exit(1);
    }
}

static inline void assert_eq_int(const char *name, int got, int expected) {
    if (got != expected) {
        fprintf(stderr, "test failure: %s (got %d, expected %d)\n", name, got, expected);
        exit(1);
    }
}

static inline void assert_eq_u16(const char *name, uint16_t got, uint16_t expected) {
    if (got != expected) {
        fprintf(stderr, "test failure: %s (got 0x%04X, expected 0x%04X)\n", name, got, expected);
        exit(1);
    }
}

#endif
