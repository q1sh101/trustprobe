#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_tpm(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *tpm_class_path = "/sys/class/tpm/tpm0";
    const char *tpm_major_path = "/sys/class/tpm/tpm0/tpm_version_major";

    {
        char major[64] = {0};

        if (!bythos_file_exists(tpm_class_path)) {
            EMIT("TPM presence", CHECK_WARN, "no TPM device visible");
        } else if (!bythos_read_file_text(tpm_major_path, major, sizeof(major))) {
            EMIT("TPM presence", CHECK_WARN, "TPM device visible but version unreadable");
        } else {
            char *trimmed = bythos_trim(major);

            if (strcmp(trimmed, "2") == 0) {
                EMIT("TPM presence", CHECK_OK, "TPM 2.0 device visible");
            } else if (trimmed[0] != '\0') {
                char detail[128];
                snprintf(detail, sizeof(detail), "TPM %s.x device visible; expected TPM 2.0", trimmed);
                EMIT("TPM presence", CHECK_WARN, detail);
            } else {
                EMIT("TPM presence", CHECK_WARN, "TPM device visible but version not visible");
            }
        }
    }

    {
        static const char *const pcr7_argv[] = {"tpm2_pcrread", "sha256:7", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!bythos_command_exists("tpm2_pcrread")) {
            EMIT_INSTALL("TPM PCR 7", "tpm2_pcrread not available");
        } else if (!bythos_capture_argv_status(pcr7_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            EMIT("TPM PCR 7", CHECK_SKIP, "PCR read failed");
        } else {
            int z = bythos_pcr_zero_check(buf, 7);
            if (z < 0) {
                EMIT("TPM PCR 7", CHECK_SKIP, "not found in output");
            } else if (z == 1) {
                EMIT("TPM PCR 7", CHECK_WARN, "empty; Secure Boot state not measured into TPM");
            } else {
                EMIT("TPM PCR 7", CHECK_OK, "non-zero; Secure Boot state measured");
            }
        }
    }

    {
        static const char *const pcr0_argv[] = {"tpm2_pcrread", "sha256:0", NULL};
        char buf[512] = {0};
        int exit_status = -1;

        if (!bythos_command_exists("tpm2_pcrread")) {
            EMIT_INSTALL("TPM PCR 0", "tpm2_pcrread not available");
        } else if (!bythos_capture_argv_status(pcr0_argv, buf, sizeof(buf), &exit_status) ||
                   exit_status != 0) {
            EMIT("TPM PCR 0", CHECK_SKIP, "PCR read failed");
        } else {
            int z = bythos_pcr_zero_check(buf, 0);
            if (z < 0) {
                EMIT("TPM PCR 0", CHECK_SKIP, "not found in output");
            } else if (z == 1) {
                EMIT("TPM PCR 0", CHECK_WARN, "zero; firmware not measured at boot");
            } else {
                EMIT("TPM PCR 0", CHECK_OK, "non-zero; firmware measured at boot");
            }
        }
    }

    {
        const char *evlog = "/sys/kernel/security/tpm0/ascii_bios_measurements";
        FILE *f = fopen(evlog, "r");

        if (f == NULL) {
            EMIT("TPM event log", CHECK_SKIP, "not available");
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
                EMIT("TPM event log", CHECK_OK, "CRTM version event present");
            } else {
                EMIT("TPM event log", CHECK_WARN, "EV_S_CRTM_VERSION absent");
            }
        }
    }

    return used;
}
