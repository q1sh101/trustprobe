#ifndef TRUSTPROBE_OUTPUT_H
#define TRUSTPROBE_OUTPUT_H

#include <stddef.h>

#include "types.h"

void trustprobe_log(const char *fmt, ...);

void trustprobe_print_result(const check_result_t *result);
void trustprobe_summary_add(posture_summary_t *summary, const check_result_t *result);
check_state_t trustprobe_summary_state(const posture_summary_t *summary);
const char *trustprobe_state_name(check_state_t state);
void trustprobe_print_summary(const char *name, const posture_summary_t *summary);

#endif
