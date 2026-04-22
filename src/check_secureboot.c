#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "efi_boot_parsers.h"
#include "firmware_ownership.h"
#include "firmware_parsers.h"
#include "runtime.h"

#define EFI_SIGDB_GUID "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
#define EFI_DB_PATH  "/sys/firmware/efi/efivars/db-" EFI_SIGDB_GUID
#define EFI_DBX_PATH "/sys/firmware/efi/efivars/dbx-" EFI_SIGDB_GUID

static void check_sigdb_variable(const char *path, const char *name,
                                 bool efi_visible,
                                 check_result_t *results, size_t *used,
                                 size_t max_results) {
    if (*used >= max_results) {
        return;
    }

    if (!efi_visible) {
        results[(*used)++] = make_result(name, CHECK_SKIP,
            "EFI runtime interface not visible");
        return;
    }

    if (!trustprobe_file_exists(path)) {
        results[(*used)++] = make_result(name, CHECK_WARN,
            "UEFI visible but variable missing");
        return;
    }

    /* db/dbx presence matters; sample only enough to classify empty vs non-empty. */
    unsigned char buf[32];
    size_t len = 0;
    if (!trustprobe_read_file_binary(path, buf, sizeof(buf), &len)) {
        results[(*used)++] = make_result(name, CHECK_WARN,
            "variable visible but unreadable");
        return;
    }

    trustprobe_efi_sigdb_status_t status = trustprobe_classify_efi_sigdb(buf, len);
    if (status == TRUSTPROBE_EFI_SIGDB_NONEMPTY) {
        results[(*used)++] = make_result(name, CHECK_OK,
            "visible and non-empty");
    } else {
        results[(*used)++] = make_result(name, CHECK_WARN,
            "visible but empty");
    }
}

size_t trustprobe_check_secureboot(check_result_t *results, size_t max_results) {
    size_t used = 0;
    bool has_mokutil = false;
    static const char *mokutil_state_argv[] = {"mokutil", "--sb-state", NULL};
    char state_buffer[512] = {0};
    bool have_state_output = false;
    trustprobe_mok_ownership_t ownership = {0};
    trustprobe_secure_boot_status_t state = TRUSTPROBE_SECURE_BOOT_UNKNOWN;

    has_mokutil = trustprobe_command_exists("mokutil");

    if (has_mokutil) {
        trustprobe_probe_mok_ownership(&ownership);
    }

    int sb_exit = -1;
    if (used < max_results) {
        if (!has_mokutil) {
            results[used++] = make_result("secure boot state", CHECK_SKIP, "mokutil not installed");
        } else if (!trustprobe_capture_argv_status(mokutil_state_argv, state_buffer, sizeof(state_buffer), &sb_exit) || sb_exit != 0) {
            results[used++] = make_result("secure boot state", CHECK_WARN, "unable to read Secure Boot state");
        /* Disabled Secure Boot is a direct posture regression for this layer, so keep it as FAIL. */
        } else if ((state = trustprobe_parse_secure_boot_state(state_buffer)) == TRUSTPROBE_SECURE_BOOT_ENABLED) {
            have_state_output = true;
            results[used++] = make_result("secure boot state", CHECK_OK, "Secure Boot enabled");
        } else if (state == TRUSTPROBE_SECURE_BOOT_DISABLED) {
            have_state_output = true;
            results[used++] = make_result("secure boot state", CHECK_FAIL, "Secure Boot disabled");
        } else {
            have_state_output = true;
            results[used++] = make_result("secure boot state", CHECK_WARN, "unexpected mokutil output");
        }
    }

    if (used < max_results) {
        if (!has_mokutil) {
            results[used++] = make_result("secure boot setup mode", CHECK_SKIP, "mokutil not installed");
        } else if (!have_state_output) {
            results[used++] = make_result("secure boot setup mode", CHECK_SKIP, "setup mode unavailable");
        } else if (trustprobe_secure_boot_setup_mode(state_buffer)) {
            results[used++] = make_result("secure boot setup mode", CHECK_WARN, "Setup Mode enabled");
        } else {
            results[used++] = make_result("secure boot setup mode", CHECK_OK, "Setup Mode disabled");
        }
    }

    if (used < max_results) {
        if (!has_mokutil) {
            results[used++] = make_result("platform key owner", CHECK_SKIP, "mokutil not installed");
        } else if (!ownership.owner_readable) {
            results[used++] = make_result("platform key owner", CHECK_SKIP, "platform key owner unreadable");
        } else if (ownership.owner_parsed) {
            results[used++] = make_result("platform key owner", CHECK_OK, ownership.owner);
        } else {
            results[used++] = make_result("platform key owner", CHECK_SKIP, "platform key owner not parsed");
        }
    }

    if (used < max_results) {
        if (!has_mokutil) {
            results[used++] = make_result("MOK enrollments", CHECK_SKIP, "mokutil not installed");
        } else if (!ownership.enrollments_readable) {
            results[used++] = make_result("MOK enrollments", CHECK_SKIP, "MOK list unreadable");
        } else {
            char detail[128];
            if (ownership.enrollment_count == 0) {
                results[used++] = make_result("MOK enrollments", CHECK_OK, "no local MOK enrollments visible");
            } else {
                snprintf(detail, sizeof(detail), "%zu local MOK enrollment(s) visible", ownership.enrollment_count);
                results[used++] = make_result("MOK enrollments", CHECK_OK, detail);
            }
        }
    }

    /* Secure Boot signature databases - raw efivars visibility */
    bool efi_visible = trustprobe_file_exists("/sys/firmware/efi");

    check_sigdb_variable(EFI_DB_PATH, "secure boot allowlist",
                         efi_visible, results, &used, max_results);

    check_sigdb_variable(EFI_DBX_PATH, "secure boot revocations",
                         efi_visible, results, &used, max_results);

    return used;
}
