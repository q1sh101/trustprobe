#ifndef TRUSTPROBE_OUTPUT_H
#define TRUSTPROBE_OUTPUT_H

#include <stddef.h>

#include "types.h"

typedef struct {
    const char *name;
    const check_result_t *results;
    size_t result_count;
    const posture_summary_t *summary;
} trustprobe_group_view_t;

void trustprobe_log(const char *fmt, ...);

void trustprobe_print_result(const check_result_t *result);
void trustprobe_summary_add(posture_summary_t *summary, const check_result_t *result);
check_state_t trustprobe_summary_state(const posture_summary_t *summary);
const char *trustprobe_state_name(check_state_t state);
void trustprobe_print_summary(const char *name, const posture_summary_t *summary);
void trustprobe_print_json(
    const char *mode,
    const char *banner,
    const trustprobe_group_view_t *groups,
    size_t group_count,
    const posture_summary_t *overall,
    int exit_code
);

#endif
