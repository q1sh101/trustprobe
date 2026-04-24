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

int trustprobe_pcr_zero_check(const char *buf, unsigned int pcr_num) {
    if (buf == NULL) return -1;

    char prefix[8];
    snprintf(prefix, sizeof(prefix), "%u", pcr_num);
    size_t plen = strlen(prefix);

    const char *line = buf;
    while (*line != '\0') {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;

        if (strncmp(p, prefix, plen) == 0 &&
            (p[plen] == ' ' || p[plen] == ':' || p[plen] == '\t')) {
            const char *eol = p;
            while (*eol && *eol != '\n') eol++;
            const char *ox = p;
            while (ox + 1 < eol) {
                if (ox[0] == '0' && ox[1] == 'x') {
                    const char *hex = ox + 2;
                    bool zeros = true;
                    size_t n = 0;
                    while (hex[n] && hex[n] != '\n' && hex[n] != '\r' && hex[n] != ' ') {
                        if (hex[n] != '0') zeros = false;
                        n++;
                    }
                    return n == 0 ? -1 : (zeros ? 1 : 0);
                }
                ox++;
            }
            return -1;
        }

        while (*line && *line != '\n') line++;
        if (*line == '\n') line++;
    }
    return -1;
}

trustprobe_cpu_vendor_t trustprobe_cpu_vendor(void) {
    char buf[4096] = {0};
    if (!trustprobe_read_file_text("/proc/cpuinfo", buf, sizeof(buf))) {
        return TRUSTPROBE_CPU_VENDOR_UNKNOWN;
    }

    const char *cursor = buf;
    while (*cursor != '\0') {
        size_t line_len = strcspn(cursor, "\r\n");
        if (line_len > 10 && strncmp(cursor, "vendor_id", 9) == 0) {
            const char *colon = memchr(cursor, ':', line_len);
            if (colon != NULL) {
                colon++;
                while (*colon == ' ' || *colon == '\t') colon++;
                if (strncmp(colon, "AuthenticAMD", 12) == 0) return TRUSTPROBE_CPU_VENDOR_AMD;
                if (strncmp(colon, "GenuineIntel", 12) == 0) return TRUSTPROBE_CPU_VENDOR_INTEL;
            }
            break;
        }
        cursor += line_len;
        while (*cursor == '\r' || *cursor == '\n') cursor++;
    }

    return TRUSTPROBE_CPU_VENDOR_UNKNOWN;
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
