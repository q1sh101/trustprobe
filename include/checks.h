#ifndef TRUSTPROBE_CHECKS_H
#define TRUSTPROBE_CHECKS_H

#include <stddef.h>

#include "types.h"

#define TRUSTPROBE_MAX_GROUP_RESULTS 128

size_t trustprobe_check_physical(check_result_t *results, size_t max_results);
size_t trustprobe_check_firmware(check_result_t *results, size_t max_results);

#endif
