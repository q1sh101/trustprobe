#ifndef TRUSTPROBE_OUTPUT_H
#define TRUSTPROBE_OUTPUT_H

#include <stddef.h>

#include "types.h"

typedef struct {
    const char *name;
    const check_subgroup_t *subgroups;
    size_t subgroup_count;
    const posture_summary_t *summary;
} trustprobe_group_view_t;

static inline void trustprobe_summary_merge(posture_summary_t *dst,
                                        const posture_summary_t *src) {
    dst->ok_count += src->ok_count;
    dst->warn_count += src->warn_count;
    dst->fail_count += src->fail_count;
    dst->skip_count += src->skip_count;
}

typedef enum {
    TRUSTPROBE_RENDER_PLAIN = 0,
    TRUSTPROBE_RENDER_JSON = 1,
} trustprobe_render_mode_t;

void trustprobe_summary_add(posture_summary_t *summary, const check_result_t *result);
check_state_t trustprobe_summary_state(const posture_summary_t *summary);
const char *trustprobe_state_name(check_state_t state);

void trustprobe_render(
    trustprobe_render_mode_t mode,
    const char *mode_str,
    const char *banner,
    const trustprobe_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
);

#endif
