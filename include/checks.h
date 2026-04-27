#ifndef TRUSTPROBE_CHECKS_H
#define TRUSTPROBE_CHECKS_H

#include <stddef.h>

#include "types.h"

#define TRUSTPROBE_MAX_GROUP_SUBGROUPS 16

size_t trustprobe_check_physical(check_subgroup_t *subgroups, size_t max_subgroups);
size_t trustprobe_check_firmware(check_subgroup_t *subgroups, size_t max_subgroups);

#endif
