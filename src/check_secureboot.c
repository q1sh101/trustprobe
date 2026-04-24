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
#define EFI_DB_PATH    "/sys/firmware/efi/efivars/db-"  EFI_SIGDB_GUID
#define EFI_DBX_PATH   "/sys/firmware/efi/efivars/dbx-" EFI_SIGDB_GUID
#define EFI_SBAT_PATH  "/sys/firmware/efi/efivars/SbatLevel-605dab50-e046-4300-abb6-3dd810dd8b23"

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

    bool efi_visible = trustprobe_file_exists("/sys/firmware/efi");

    check_sigdb_variable(EFI_DB_PATH, "secure boot allowlist",
                         efi_visible, results, &used, max_results);

    check_sigdb_variable(EFI_DBX_PATH, "secure boot revocations",
                         efi_visible, results, &used, max_results);

    if (used < max_results) {
        if (!efi_visible) {
            results[used++] = make_result("Secure Boot dbx size", CHECK_SKIP,
                "EFI runtime interface not visible");
        } else {
            unsigned char dbx_buf[8192];
            size_t dbx_len = 0;
            if (!trustprobe_read_file_binary(EFI_DBX_PATH, dbx_buf, sizeof(dbx_buf), &dbx_len) ||
                dbx_len <= 4u) {
                results[used++] = make_result("Secure Boot dbx size", CHECK_SKIP,
                    "dbx not readable");
            } else {
                size_t payload = dbx_len - 4u;
                char detail[TRUSTPROBE_DETAIL_MAX];
                if (payload < 100) {
                    snprintf(detail, sizeof(detail),
                        "dbx minimal (%zu bytes); may be factory default", payload);
                    results[used++] = make_result("Secure Boot dbx size", CHECK_WARN, detail);
                } else {
                    snprintf(detail, sizeof(detail),
                        "dbx non-minimal (%zu bytes); currency unverified", payload);
                    results[used++] = make_result("Secure Boot dbx size", CHECK_OK, detail);
                }
            }
        }
    }

    if (used < max_results) {
        if (!efi_visible) {
            results[used++] = make_result("Secure Boot db keys", CHECK_SKIP,
                "EFI runtime interface not visible");
        } else {
            unsigned char db_buf[8192];
            size_t db_len = 0;
            if (!trustprobe_read_file_binary(EFI_DB_PATH, db_buf, sizeof(db_buf), &db_len)) {
                results[used++] = make_result("Secure Boot db keys", CHECK_SKIP,
                    "db not readable");
            } else {
                size_t lists = trustprobe_count_efi_sigdb_lists(db_buf, db_len);
                if (lists == 0) {
                    results[used++] = make_result("Secure Boot db keys", CHECK_WARN,
                        "db empty; Secure Boot allowlist missing");
                } else {
                    char detail[TRUSTPROBE_DETAIL_MAX];
                    snprintf(detail, sizeof(detail),
                        "%zu key list(s) in Secure Boot allowlist", lists);
                    results[used++] = make_result("Secure Boot db keys", CHECK_OK, detail);
                }
            }
        }
    }

    if (used < max_results) {
        if (!efi_visible) {
            results[used++] = make_result("SBAT policy level", CHECK_SKIP,
                "EFI runtime interface not visible");
        } else if (!trustprobe_file_exists(EFI_SBAT_PATH)) {
            results[used++] = make_result("SBAT policy level", CHECK_SKIP,
                "SbatLevel variable absent; pre-SBAT firmware");
        } else {
            unsigned char sbat_buf[256];
            size_t sbat_len = 0;
            if (!trustprobe_read_file_binary(EFI_SBAT_PATH, sbat_buf, sizeof(sbat_buf), &sbat_len) ||
                sbat_len <= 4u) {
                results[used++] = make_result("SBAT policy level", CHECK_WARN,
                    "SbatLevel variable unreadable");
            } else {
                char sbat_line[64] = {0};
                if (!trustprobe_parse_sbat_level(sbat_buf, sbat_len, sbat_line, sizeof(sbat_line))) {
                    results[used++] = make_result("SBAT policy level", CHECK_WARN,
                        "SbatLevel variable unreadable");
                } else {
                    char detail[TRUSTPROBE_DETAIL_MAX];
                    snprintf(detail, sizeof(detail), "SbatLevel: %s", sbat_line);
                    results[used++] = make_result("SBAT policy level", CHECK_OK, detail);
                }
            }
        }
    }

    if (used < max_results) {
        if (!has_mokutil) {
            results[used++] = make_result("Secure Boot trust breadth", CHECK_SKIP,
                "mokutil not installed");
        } else {
            static const char *const db_argv[] = {"mokutil", "--db", NULL};
            char db_buf[32768] = {0};
            int db_exit = -1;
            if (!trustprobe_capture_argv_status(db_argv, db_buf, sizeof(db_buf), &db_exit) ||
                db_exit != 0) {
                results[used++] = make_result("Secure Boot trust breadth", CHECK_SKIP,
                    "unable to read Secure Boot db");
            } else if (trustprobe_sb_has_ms_ca(db_buf)) {
                results[used++] = make_result("Secure Boot trust breadth", CHECK_WARN,
                    "Microsoft 3rd Party UEFI CA in db; widens trusted signer set");
            } else {
                results[used++] = make_result("Secure Boot trust breadth", CHECK_OK,
                    "Microsoft 3rd Party UEFI CA not found in db");
            }
        }
    }

    if (used < max_results) {
        char mounts_buf[4096] = {0};
        if (!trustprobe_read_file_text("/proc/mounts", mounts_buf, sizeof(mounts_buf))) {
            results[used++] = make_result("efivarfs mount mode", CHECK_SKIP,
                "unable to read /proc/mounts");
        } else {
            const char *marker = strstr(mounts_buf, " efivarfs ");
            if (marker == NULL) {
                results[used++] = make_result("efivarfs mount mode", CHECK_SKIP,
                    "efivarfs not mounted");
            } else {
                const char *opts = marker + 10; /* skip " efivarfs " */
                if (strncmp(opts, "ro,", 3) == 0 || strncmp(opts, "ro\n", 3) == 0 ||
                    strncmp(opts, "ro ", 3) == 0 || strncmp(opts, "ro\0", 3) == 0) {
                    results[used++] = make_result("efivarfs mount mode", CHECK_OK,
                        "efivarfs mounted read-only");
                } else {
                    results[used++] = make_result("efivarfs mount mode", CHECK_WARN,
                        "efivarfs mounted read-write; Secure Boot variables writable");
                }
            }
        }
    }

    return used;
}
