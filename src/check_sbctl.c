#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "firmware_parsers.h"
#include "runtime.h"

size_t trustprobe_check_sbctl(check_result_t *results, size_t max_results) {
    size_t used = 0;
    static const char *const sbctl_status_argv[] = {"sbctl", "status", NULL};

    if (used < max_results) {
        char buffer[2048] = {0};
        int status = -1;
        trustprobe_sbctl_status_t sbctl_status = {0};

        if (!trustprobe_command_exists("sbctl")) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "not installed");
        } else if (!trustprobe_capture_argv_status(sbctl_status_argv, buffer, sizeof(buffer), &status)) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "status unavailable");
        } else if (status != 0) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "not initialized");
        } else if (!trustprobe_parse_sbctl_status(buffer, &sbctl_status)) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "status unavailable");
        } else if (!sbctl_status.installed_known) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "status unavailable");
        } else if (!sbctl_status.installed) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "not initialized");
        } else if (!sbctl_status.owner_guid_present) {
            results[used++] = make_result("sbctl (optional)", CHECK_SKIP, "owner GUID not visible");
        } else {
            char detail[192];
            if (sbctl_status.vendor_keys_present) {
                snprintf(
                    detail,
                    sizeof(detail),
                    "initialized; owner GUID present; vendor keys %.64s",
                    sbctl_status.vendor_keys
                );
            } else {
                snprintf(detail, sizeof(detail), "%s", "initialized; owner GUID present");
            }
            results[used++] = make_result("sbctl (optional)", CHECK_OK, detail);
        }
    }

    return used;
}
