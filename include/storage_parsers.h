#ifndef TRUSTPROBE_STORAGE_PARSERS_H
#define TRUSTPROBE_STORAGE_PARSERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    size_t luks_count;
    size_t crypt_count;
    size_t crypt_swap_count;
} trustprobe_lsblk_posture_t;

void trustprobe_parse_lsblk_posture(const char *text, trustprobe_lsblk_posture_t *posture);

/*
 * Parses PCR indices from a cryptsetup luksDump systemd-tpm2 token section.
 * Handles both "pcrs: 0 7 9" and "tpm2-pcrs: [0, 7, 9]" formats.
 * Returns false if no systemd-tpm2 token or no pcrs field found.
 */
bool trustprobe_parse_luks_pcr_mask(const char *text, uint32_t *mask_out);

#endif
