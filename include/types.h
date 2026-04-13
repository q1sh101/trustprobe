#ifndef TRUSTPROBE_TYPES_H
#define TRUSTPROBE_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define TRUSTPROBE_DETAIL_MAX 256

typedef enum {
    CHECK_OK = 0,
    CHECK_WARN = 1,
    CHECK_FAIL = 2,
    CHECK_SKIP = 3
} check_state_t;

typedef struct {
    const char *name;
    check_state_t state;
    char detail[TRUSTPROBE_DETAIL_MAX];
    bool requires_root;
} check_result_t;

typedef struct {
    size_t ok_count;
    size_t warn_count;
    size_t fail_count;
    size_t skip_count;
} posture_summary_t;

static inline check_result_t make_result(const char *name, check_state_t state, const char *detail) {
    check_result_t result = {
        .name = name,
        .state = state,
        .detail = {0},
        .requires_root = false,
    };
    if (detail != NULL) {
        snprintf(result.detail, sizeof(result.detail), "%s", detail);
    }
    return result;
}

static inline check_result_t make_root_result(const char *name, check_state_t state, const char *detail) {
    check_result_t result = make_result(name, state, detail);
    result.requires_root = true;
    return result;
}

#endif

