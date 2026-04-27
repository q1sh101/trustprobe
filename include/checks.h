#ifndef BYTHOS_CHECKS_H
#define BYTHOS_CHECKS_H

#include <stddef.h>

#include "types.h"

#define BYTHOS_MAX_GROUP_SUBGROUPS 16

size_t bythos_check_physical(check_subgroup_t *subgroups, size_t max_subgroups);
size_t bythos_check_firmware(check_subgroup_t *subgroups, size_t max_subgroups);

#endif
