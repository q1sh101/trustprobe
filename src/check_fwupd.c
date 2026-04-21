#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "firmware_parsers.h"
#include "runtime.h"

size_t trustprobe_check_fwupd(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *lvfs_conf = "/etc/fwupd/remotes.d/lvfs.conf";
    bool has_fwupdmgr = false;
    static const char *fwupd_devices_argv[] = {"fwupdmgr", "get-devices", NULL};
    static const char *fwupd_updates_argv[] = {"fwupdmgr", "get-updates", NULL};

    has_fwupdmgr = trustprobe_command_exists("fwupdmgr");

    if (used < max_results) {
        switch (trustprobe_probe_systemd_service("fwupd.service")) {
        case TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
            results[used++] = make_result("fwupd service", CHECK_SKIP, "systemctl not available");
            break;
        case TRUSTPROBE_SERVICE_STATE_ACTIVE:
            results[used++] = make_result("fwupd service", CHECK_OK, "service is running");
            break;
        case TRUSTPROBE_SERVICE_STATE_INACTIVE:
            results[used++] = make_result("fwupd service", CHECK_WARN, "service is installed but inactive");
            break;
        case TRUSTPROBE_SERVICE_STATE_MISSING:
            results[used++] = make_result("fwupd service", CHECK_WARN, "service not installed");
            break;
        default:
            results[used++] = make_result("fwupd service", CHECK_SKIP, "state unavailable");
            break;
        }
    }

    if (used < max_results) {
        char enabled[32] = {0};
        if (!has_fwupdmgr) {
            results[used++] = make_result("LVFS remote", CHECK_SKIP, "fwupdmgr not installed");
        } else if (!trustprobe_file_exists(lvfs_conf)) {
            results[used++] = make_result("LVFS remote", CHECK_WARN, "lvfs.conf not found");
        } else if (!trustprobe_read_key_value(lvfs_conf, "Enabled", enabled, sizeof(enabled))) {
            results[used++] = make_result("LVFS remote", CHECK_WARN, "Enabled key not found");
        } else if (strcmp(enabled, "true") == 0) {
            results[used++] = make_result("LVFS remote", CHECK_OK, "LVFS remote enabled");
        } else {
            results[used++] = make_result("LVFS remote", CHECK_WARN, "LVFS remote not enabled");
        }
    }

    if (used < max_results) {
        int devices = -1;
        if (!has_fwupdmgr) {
            results[used++] = make_result("firmware inventory", CHECK_SKIP, "fwupdmgr not installed");
        } else if ((devices = trustprobe_run_argv_quiet(fwupd_devices_argv)) == 0) {
            results[used++] = make_result("firmware inventory", CHECK_OK, "device list available");
        } else {
            results[used++] = make_result("firmware inventory", CHECK_SKIP, "unable to list firmware devices");
        }
    }

    if (used < max_results) {
        char buffer[2048] = {0};
        int status = -1;
        trustprobe_fwupd_updates_status_t updates = TRUSTPROBE_FWUPD_UPDATES_UNKNOWN;

        if (!has_fwupdmgr) {
            results[used++] = make_result("firmware update status", CHECK_SKIP, "fwupdmgr not installed");
        } else if (!trustprobe_capture_argv_status(fwupd_updates_argv, buffer, sizeof(buffer), &status)) {
            results[used++] = make_result("firmware update status", CHECK_SKIP, "unable to query firmware updates");
        } else if ((updates = trustprobe_parse_fwupd_updates(buffer, status)) == TRUSTPROBE_FWUPD_UPDATES_NONE) {
            results[used++] = make_result("firmware update status", CHECK_OK, "no updates available");
        } else if (updates == TRUSTPROBE_FWUPD_UPDATES_AVAILABLE) {
            results[used++] = make_result("firmware update status", CHECK_WARN, "firmware updates available");
        } else {
            results[used++] = make_result("firmware update status", CHECK_SKIP, "update status unavailable");
        }
    }

    /* Firmware update history - informational signal, not a hard posture gate. */
    if (used < max_results) {
        static const char *fwupd_history_argv[] = {"fwupdmgr", "get-history", NULL};
        char hist_buffer[2048] = {0};
        int hist_status = -1;

        if (!has_fwupdmgr) {
            results[used++] = make_result("firmware update history", CHECK_SKIP, "fwupdmgr not installed");
        } else if (!trustprobe_capture_argv_status(fwupd_history_argv, hist_buffer, sizeof(hist_buffer), &hist_status)) {
            results[used++] = make_result("firmware update history", CHECK_SKIP, "history unavailable");
        } else if (hist_status != 0) {
            results[used++] = make_result("firmware update history", CHECK_SKIP, "history unavailable");
        } else if (hist_buffer[0] != '\0') {
            results[used++] = make_result("firmware update history", CHECK_OK, "firmware update history available");
        } else {
            results[used++] = make_result("firmware update history", CHECK_OK, "no update history visible");
        }
    }

    return used;
}
