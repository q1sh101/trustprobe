#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"

size_t trustprobe_check_kernel_lockdown(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *path = "/sys/kernel/security/lockdown";

    if (used >= max_results) {
        return used;
    }

    char buf[128] = {0};
    if (!trustprobe_read_file_text(path, buf, sizeof(buf))) {
        results[used++] = make_result("kernel lockdown", CHECK_SKIP,
            "lockdown interface not visible");
        return used;
    }

    trustprobe_trim(buf);

    /*
     * The kernel exposes lockdown state like:
     *   "none [integrity] confidentiality"
     * The active mode is enclosed in brackets.
     */
    if (strstr(buf, "[confidentiality]") != NULL) {
        results[used++] = make_result("kernel lockdown", CHECK_OK,
            "confidentiality mode active");
    } else if (strstr(buf, "[integrity]") != NULL) {
        results[used++] = make_result("kernel lockdown", CHECK_OK,
            "integrity mode active");
    } else if (strstr(buf, "[none]") != NULL) {
        results[used++] = make_result("kernel lockdown", CHECK_WARN,
            "lockdown disabled");
    } else {
        results[used++] = make_result("kernel lockdown", CHECK_WARN,
            "unexpected lockdown state");
    }

    return used;
}
