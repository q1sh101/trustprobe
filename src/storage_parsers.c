#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
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

bool trustprobe_parse_luks_pcr_mask(const char *text, uint32_t *mask_out) {
    if (text == NULL || mask_out == NULL) return false;
    *mask_out = 0;

    const char *pos = strstr(text, "systemd-tpm2");
    if (pos == NULL) return false;

    /* bound search to this token section */
    size_t window = strlen(pos);
    if (window > 512) window = 512;
    const char *end = pos + window;

    const char *line = pos;
    while (line < end) {
        const char *eol = line;
        while (eol < end && *eol != '\n' && *eol != '\r') eol++;

        /* look for "pcrs" on this line, but not "pcrs-mask" or "pcr-mask" */
        const char *p = line;
        while (p + 4 <= eol) {
            if (strncmp(p, "pcrs", 4) == 0 && p[4] != '-') {
                const char *colon = p + 4;
                while (colon < eol && *colon != ':') colon++;
                if (colon >= eol) break;

                const char *q = colon + 1;
                bool found = false;
                while (q < eol) {
                    if (*q >= '0' && *q <= '9') {
                        unsigned int n = 0;
                        while (q < eol && *q >= '0' && *q <= '9') {
                            n = n * 10 + (unsigned int)(*q - '0');
                            q++;
                        }
                        if (n < 32) {
                            *mask_out |= (1u << n);
                            found = true;
                        }
                    } else {
                        q++;
                    }
                }
                if (found) return true;
                break;
            }
            p++;
        }

        line = (eol < end) ? eol + 1 : end;
    }

    return false;
}
