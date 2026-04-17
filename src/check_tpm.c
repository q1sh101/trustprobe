#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"

size_t trustprobe_check_tpm(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *tpm_class_path = "/sys/class/tpm/tpm0";
    const char *tpm_major_path = "/sys/class/tpm/tpm0/tpm_version_major";

    if (used < max_results) {
        char major[64] = {0};

        if (!trustprobe_file_exists(tpm_class_path)) {
            results[used++] = make_result("TPM presence", CHECK_WARN, "no TPM device visible");
        } else if (!trustprobe_read_file_text(tpm_major_path, major, sizeof(major))) {
            results[used++] = make_result("TPM presence", CHECK_WARN, "TPM device visible but version unreadable");
        } else {
            char *trimmed = trustprobe_trim(major);

            if (strcmp(trimmed, "2") == 0) {
                results[used++] = make_result("TPM presence", CHECK_OK, "TPM 2.0 device visible");
            } else if (trimmed[0] != '\0') {
                char detail[128];
                snprintf(detail, sizeof(detail), "TPM major version %s visible", trimmed);
                results[used++] = make_result("TPM presence", CHECK_WARN, detail);
            } else {
                results[used++] = make_result("TPM presence", CHECK_WARN, "TPM version not visible");
            }
        }
    }

    return used;
}
