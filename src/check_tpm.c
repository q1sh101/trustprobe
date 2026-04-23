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

    if (used < max_results) {
        static const char *const pcr_argv[] = {"tpm2_pcrread", "sha256:7", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!trustprobe_command_exists("tpm2_pcrread")) {
            results[used++] = make_result("TPM PCR 7", CHECK_SKIP,
                "tpm2_pcrread not available");
        } else if (!trustprobe_capture_argv_status(pcr_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            results[used++] = make_result("TPM PCR 7", CHECK_SKIP,
                "PCR read failed");
        } else {
            /* Accept both "7: 0x..." and "7 : 0x..." PCR output forms. */
            const char *line = buf;
            const char *hex_start = NULL;

            while (*line != '\0' && hex_start == NULL) {
                const char *p = line;
                while (*p == ' ' || *p == '\t') {
                    p++;
                }
                if (p[0] == '7' && (p[1] == ' ' || p[1] == ':' || p[1] == '\t')) {
                    const char *eol = p;
                    while (*eol != '\0' && *eol != '\n') {
                        eol++;
                    }
                    const char *ox = p;
                    while (ox + 1 < eol) {
                        if (ox[0] == '0' && ox[1] == 'x') {
                            hex_start = ox + 2;
                            break;
                        }
                        ox++;
                    }
                }
                while (*line != '\0' && *line != '\n') {
                    line++;
                }
                if (*line == '\n') {
                    line++;
                }
            }

            if (hex_start == NULL) {
                results[used++] = make_result("TPM PCR 7", CHECK_SKIP,
                    "PCR 7 not found in output");
            } else {
                bool all_zeros = true;
                size_t count = 0;
                while (hex_start[count] != '\0' && hex_start[count] != '\n' &&
                       hex_start[count] != '\r' && hex_start[count] != ' ') {
                    if (hex_start[count] != '0') {
                        all_zeros = false;
                    }
                    count++;
                }
                if (count == 0) {
                    results[used++] = make_result("TPM PCR 7", CHECK_SKIP,
                        "PCR 7 value unreadable");
                } else if (all_zeros) {
                    results[used++] = make_result("TPM PCR 7", CHECK_WARN,
                        "PCR 7 empty; Secure Boot state not measured into TPM");
                } else {
                    results[used++] = make_result("TPM PCR 7", CHECK_OK,
                        "PCR 7 non-zero; Secure Boot state measured");
                }
            }
        }
    }

    return used;
}
