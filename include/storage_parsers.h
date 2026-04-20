#ifndef TRUSTPROBE_STORAGE_PARSERS_H
#define TRUSTPROBE_STORAGE_PARSERS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    size_t luks_count;
    size_t crypt_count;
    size_t crypt_swap_count;
} trustprobe_lsblk_posture_t;

void trustprobe_parse_lsblk_posture(const char *text, trustprobe_lsblk_posture_t *posture);

#endif
