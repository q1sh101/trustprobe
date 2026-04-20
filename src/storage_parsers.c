#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "storage_parsers.h"

void trustprobe_parse_lsblk_posture(const char *text, trustprobe_lsblk_posture_t *posture) {
    if (posture == NULL) {
        return;
    }

    *posture = (trustprobe_lsblk_posture_t){0};

    if (text == NULL || *text == '\0') {
        return;
    }

    const char *cursor = text;
    while (*cursor != '\0') {
        size_t raw_len = strcspn(cursor, "\r\n");
        char line[512];
        bool is_luks = false;
        bool is_crypt = false;
        bool is_swap = false;

        if (raw_len > 0) {
            size_t copy_len = raw_len;
            if (copy_len >= sizeof(line)) {
                copy_len = sizeof(line) - 1;
            }

            memcpy(line, cursor, copy_len);
            line[copy_len] = '\0';

            if (strstr(line, "FSTYPE=\"crypto_LUKS\"") != NULL) {
                is_luks = true;
            }
            if (strstr(line, "TYPE=\"crypt\"") != NULL) {
                is_crypt = true;
            }
            if (strstr(line, "FSTYPE=\"swap\"") != NULL) {
                is_swap = true;
            }
        }

        if (is_luks) {
            posture->luks_count++;
        }
        if (is_crypt) {
            posture->crypt_count++;
            if (is_swap) {
                posture->crypt_swap_count++;
            }
        }

        cursor += raw_len;
        while (*cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
    }
}
