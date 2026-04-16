#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "runtime.h"
#include "silicon_parsers.h"

static bool token_present(const char *text, const char *needle) {
    size_t needle_len = strlen(needle);
    const char *cursor = text;

    while (*cursor != '\0') {
        while (*cursor != '\0' && isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (*cursor == '\0') {
            break;
        }

        size_t token_len = strcspn(cursor, " \t\r\n");
        if (token_len == needle_len && strncmp(cursor, needle, needle_len) == 0) {
            return true;
        }

        cursor += token_len;
    }

    return false;
}

void trustprobe_parse_iommu_cmdline(const char *text, trustprobe_iommu_cmdline_t *cmdline) {
    if (cmdline == NULL) {
        return;
    }

    *cmdline = (trustprobe_iommu_cmdline_t){0};

    if (text == NULL || *text == '\0') {
        return;
    }

    cmdline->iommu_disabled =
        token_present(text, "iommu=off") ||
        token_present(text, "intel_iommu=off") ||
        token_present(text, "amd_iommu=off");

    cmdline->vendor_iommu_on =
        token_present(text, "intel_iommu=on") ||
        token_present(text, "amd_iommu=on");

    cmdline->passthrough_on =
        token_present(text, "iommu=pt") ||
        token_present(text, "iommu.passthrough=1");

    cmdline->passthrough_off = token_present(text, "iommu.passthrough=0");
    cmdline->strict_on = token_present(text, "iommu.strict=1");
    cmdline->strict_off = token_present(text, "iommu.strict=0");
}

bool trustprobe_extract_microcode_revision(const char *text, char *buffer, size_t size) {
    if (text == NULL || buffer == NULL || size == 0) {
        return false;
    }

    buffer[0] = '\0';

    char line[512];
    const char *cursor = text;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len >= sizeof(line)) {
            line_len = sizeof(line) - 1;
        }

        memcpy(line, cursor, line_len);
        line[line_len] = '\0';

        char *lhs = trustprobe_trim(line);
        if (strncmp(lhs, "microcode", 9) == 0) {
            char *sep = strchr(lhs, ':');
            if (sep != NULL) {
                char *rhs = trustprobe_trim(sep + 1);
                if (*rhs != '\0') {
                    snprintf(buffer, size, "%s", rhs);
                    return true;
                }
            }
        }

        cursor += strcspn(cursor, "\r\n");
        while (*cursor == '\r' || *cursor == '\n') {
            cursor++;
        }
    }

    return false;
}
