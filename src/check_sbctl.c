#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "firmware_parsers.h"
#include "runtime.h"

size_t bythos_check_sbctl(check_result_t *results, size_t max_results) {
    size_t used = 0;
    static const char *const sbctl_status_argv[] = {"sbctl", "status", NULL};

    {
        char buffer[2048] = {0};
        int status = -1;
        bythos_sbctl_status_t sbctl_status = {0};

        if (!bythos_command_exists("sbctl")) {
            EMIT_INSTALL("sbctl (optional)", "not installed");
        } else if (!bythos_capture_argv_status(sbctl_status_argv, buffer, sizeof(buffer), &status)) {
            EMIT("sbctl (optional)", CHECK_SKIP, "status unavailable");
        } else if (status != 0) {
            EMIT_INSTALL("sbctl (optional)", "not initialized");
        } else if (!bythos_parse_sbctl_status(buffer, &sbctl_status)) {
            EMIT("sbctl (optional)", CHECK_SKIP, "status unavailable");
        } else if (!sbctl_status.installed_known) {
            EMIT("sbctl (optional)", CHECK_SKIP, "status unavailable");
        } else if (!sbctl_status.installed) {
            EMIT_INSTALL("sbctl (optional)", "not initialized");
        } else if (!sbctl_status.owner_guid_present) {
            EMIT("sbctl (optional)", CHECK_SKIP, "owner GUID not visible");
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
            EMIT("sbctl (optional)", CHECK_OK, detail);
        }
    }

    return used;
}
