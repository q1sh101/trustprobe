#ifndef BYTHOS_TYPES_H
#define BYTHOS_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define BYTHOS_DETAIL_MAX 256

typedef enum {
    CHECK_OK = 0,
    CHECK_WARN = 1,
    CHECK_FAIL = 2,
    CHECK_SKIP = 3
} check_state_t;

typedef struct {
    const char *name;
    check_state_t state;
    char detail[BYTHOS_DETAIL_MAX];
    bool requires_root;
    bool actionable;
} check_result_t;

typedef struct {
    size_t ok_count;
    size_t warn_count;
    size_t fail_count;
    size_t skip_count;
} posture_summary_t;

#define BYTHOS_MAX_SUBGROUP_RESULTS 32

typedef struct {
    const char *name;
    check_result_t results[BYTHOS_MAX_SUBGROUP_RESULTS];
    size_t result_count;
    posture_summary_t summary;
} check_subgroup_t;

static inline check_result_t make_result(const char *name, check_state_t state, const char *detail) {
    check_result_t result = {
        .name = name,
        .state = state,
        .detail = {0},
        .requires_root = false,
        .actionable = false,
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

static inline check_result_t make_install_result(const char *name, const char *detail) {
    check_result_t result = make_result(name, CHECK_SKIP, detail);
    result.actionable = true;
    return result;
}

static inline const char *bythos_pl(size_t n, const char *singular, const char *plural) {
    return n == 1 ? singular : plural;
}

#define EMIT(name_, state_, detail_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_result((name_), (state_), (detail_)); \
        } \
    } while (0)

#define EMIT_ROOT(name_, state_, detail_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_root_result((name_), (state_), (detail_)); \
        } \
    } while (0)

#define EMIT_INSTALL(name_, detail_) \
    do { \
        if (used < max_results) { \
            results[used++] = make_install_result((name_), (detail_)); \
        } \
    } while (0)

#endif

