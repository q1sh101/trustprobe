#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"
#include "silicon_parsers.h"

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
        static const char *const pcr7_argv[] = {"tpm2_pcrread", "sha256:7", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!trustprobe_command_exists("tpm2_pcrread")) {
            results[used++] = make_result("TPM PCR 7", CHECK_SKIP, "tpm2_pcrread not available");
        } else if (!trustprobe_capture_argv_status(pcr7_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            results[used++] = make_result("TPM PCR 7", CHECK_SKIP, "PCR read failed");
        } else {
            int z = trustprobe_pcr_zero_check(buf, 7);
            if (z < 0) {
                results[used++] = make_result("TPM PCR 7", CHECK_SKIP, "PCR 7 not found in output");
            } else if (z == 1) {
                results[used++] = make_result("TPM PCR 7", CHECK_WARN,
                    "PCR 7 empty; Secure Boot state not measured into TPM");
            } else {
                results[used++] = make_result("TPM PCR 7", CHECK_OK,
                    "PCR 7 non-zero; Secure Boot state measured");
            }
        }
    }

    if (used < max_results) {
        static const char *const pcr0_argv[] = {"tpm2_pcrread", "sha256:0", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!trustprobe_command_exists("tpm2_pcrread")) {
            results[used++] = make_result("TPM PCR 0", CHECK_SKIP, "tpm2_pcrread not available");
        } else if (!trustprobe_capture_argv_status(pcr0_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            results[used++] = make_result("TPM PCR 0", CHECK_SKIP, "PCR read failed");
        } else {
            int z = trustprobe_pcr_zero_check(buf, 0);
            if (z < 0) {
                results[used++] = make_result("TPM PCR 0", CHECK_SKIP, "PCR 0 not found in output");
            } else if (z == 1) {
                results[used++] = make_result("TPM PCR 0", CHECK_WARN,
                    "PCR 0 zero; firmware not measured at boot");
            } else {
                results[used++] = make_result("TPM PCR 0", CHECK_OK,
                    "PCR 0 non-zero; firmware measured at boot");
            }
        }
    }

    if (used < max_results) {
        const char *evlog = "/sys/kernel/security/tpm0/ascii_bios_measurements";
        FILE *f = fopen(evlog, "r");

        if (f == NULL) {
            results[used++] = make_result("TPM event log", CHECK_SKIP, "event log not available");
        } else {
            char line[512];
            bool found = false;
            while (fgets(line, sizeof(line), f) != NULL) {
                if (strstr(line, "EV_S_CRTM_VERSION") != NULL) {
                    found = true;
                    break;
                }
            }
            fclose(f);
            if (found) {
                results[used++] = make_result("TPM event log", CHECK_OK, "CRTM version event present");
            } else {
                results[used++] = make_result("TPM event log", CHECK_WARN,
                    "EV_S_CRTM_VERSION absent from event log");
            }
        }
    }

    return used;
}
