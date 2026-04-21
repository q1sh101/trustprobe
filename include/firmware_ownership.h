#ifndef TRUSTPROBE_FIRMWARE_OWNERSHIP_H
#define TRUSTPROBE_FIRMWARE_OWNERSHIP_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool available;
    bool owner_readable;
    bool owner_parsed;
    char owner[128];
    bool enrollments_readable;
    size_t enrollment_count;
} trustprobe_mok_ownership_t;

bool trustprobe_probe_mok_ownership(trustprobe_mok_ownership_t *ownership);

#endif
