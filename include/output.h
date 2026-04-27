#ifndef BYTHOS_OUTPUT_H
#define BYTHOS_OUTPUT_H

#include <stddef.h>

#include "types.h"

typedef struct {
    const char *name;
    const check_subgroup_t *subgroups;
    size_t subgroup_count;
    const posture_summary_t *summary;
} bythos_group_view_t;

static inline void bythos_summary_merge(posture_summary_t *dst,
                                        const posture_summary_t *src) {
    dst->ok_count += src->ok_count;
    dst->warn_count += src->warn_count;
    dst->fail_count += src->fail_count;
    dst->skip_count += src->skip_count;
}

typedef enum {
    BYTHOS_RENDER_PLAIN = 0,
    BYTHOS_RENDER_JSON = 1,
} bythos_render_mode_t;

void bythos_summary_add(posture_summary_t *summary, const check_result_t *result);
check_state_t bythos_summary_state(const posture_summary_t *summary);
const char *bythos_state_name(check_state_t state);

void bythos_render(
    bythos_render_mode_t mode,
    const char *mode_str,
    const char *banner,
    const bythos_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
);

#endif
