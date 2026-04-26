#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"
#include "silicon_parsers.h"

#define ME_FW_VERSION_PATH "/sys/class/mei/mei0/fw_version"

size_t trustprobe_check_me_version(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) return used;

    if (trustprobe_cpu_vendor() != TRUSTPROBE_CPU_VENDOR_INTEL) {
        return used;
    }

    if (!trustprobe_file_exists(ME_FW_VERSION_PATH)) {
        results[used++] = make_result("Intel ME version", CHECK_SKIP,
            "Intel ME not present");
        return used;
    }

    char buf[64] = {0};
    if (!trustprobe_read_file_text(ME_FW_VERSION_PATH, buf, sizeof(buf))) {
        results[used++] = make_result("Intel ME version", CHECK_SKIP,
            "ME version unreadable");
        return used;
    }

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
                       buf[len - 1] == ' ')) {
        buf[--len] = '\0';
    }

    unsigned int a = 0, b = 0, c = 0, d = 0;
    if (sscanf(buf, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        results[used++] = make_result("Intel ME version", CHECK_SKIP,
            "ME version format unrecognized");
        return used;
    }

    char detail[TRUSTPROBE_DETAIL_MAX];
    snprintf(detail, sizeof(detail), "ME version %s", buf);
    results[used++] = make_result("Intel ME version", CHECK_OK, detail);

    return used;
}
