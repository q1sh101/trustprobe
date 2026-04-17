#include <dirent.h>
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"

static const char *const BOLT_SYSFS_BASE = "/sys/bus/thunderbolt/devices";

static bool read_thunderbolt_security_level(char *buffer, size_t size,
                                            bool *controller_visible) {
    if (controller_visible != NULL) {
        *controller_visible = false;
    }

    DIR *dir = opendir(BOLT_SYSFS_BASE);
    if (dir == NULL) {
        return false;
    }

    bool saw_domain = false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "domain", 6) != 0) {
            continue;
        }

        saw_domain = true;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s/security",
                     BOLT_SYSFS_BASE, entry->d_name) >= (int)sizeof(path)) {
            continue;
        }

        if (!trustprobe_file_exists(path)) {
            continue;
        }

        if (controller_visible != NULL) {
            *controller_visible = true;
        }

        if (trustprobe_read_file_text(path, buffer, size)) {
            closedir(dir);
            return true;
        }
    }

    closedir(dir);

    if (controller_visible != NULL) {
        *controller_visible = saw_domain;
    }

    return false;
}

size_t trustprobe_check_bolt(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used < max_results) {
        switch (trustprobe_probe_systemd_service("bolt.service")) {
        case TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
            results[used++] = make_result("Thunderbolt policy service", CHECK_SKIP, "systemctl not available");
            break;
        case TRUSTPROBE_SERVICE_STATE_ACTIVE:
            results[used++] = make_result("Thunderbolt policy service", CHECK_OK, "service is running");
            break;
        case TRUSTPROBE_SERVICE_STATE_INACTIVE:
            results[used++] = make_result("Thunderbolt policy service", CHECK_WARN, "service is installed but inactive");
            break;
        case TRUSTPROBE_SERVICE_STATE_MISSING:
            results[used++] = make_result("Thunderbolt policy service", CHECK_SKIP, "service not installed");
            break;
        default:
            results[used++] = make_result("Thunderbolt policy service", CHECK_SKIP, "state unavailable");
            break;
        }
    }

    /* Security level comes from sysfs; boltctl presence is not required. */
    if (used < max_results) {
        char level[64] = {0};
        bool controller_visible = false;

        if (!read_thunderbolt_security_level(level, sizeof(level),
                                             &controller_visible)) {
            if (!controller_visible) {
                results[used++] = make_result("Thunderbolt security level", CHECK_SKIP,
                    "no Thunderbolt controller visible");
            } else {
                results[used++] = make_result("Thunderbolt security level", CHECK_WARN,
                    "Thunderbolt controller visible but security level unreadable");
            }
        } else {
            char *trimmed = trustprobe_trim(level);

            if (strcmp(trimmed, "secure") == 0 || strcmp(trimmed, "dponly") == 0) {
                char detail[TRUSTPROBE_DETAIL_MAX];
                snprintf(detail, sizeof(detail), "Thunderbolt security level: %s", trimmed);
                results[used++] = make_result("Thunderbolt security level", CHECK_OK, detail);
            } else if (strcmp(trimmed, "user") == 0) {
                results[used++] = make_result("Thunderbolt security level", CHECK_OK,
                    "Thunderbolt security level: user (authorize on connect)");
            } else if (strcmp(trimmed, "none") == 0) {
                results[used++] = make_result("Thunderbolt security level", CHECK_WARN,
                    "Thunderbolt security level: none (all devices trusted)");
            } else {
                char detail[TRUSTPROBE_DETAIL_MAX];
                snprintf(detail, sizeof(detail), "Thunderbolt security level: %s", trimmed);
                results[used++] = make_result("Thunderbolt security level", CHECK_WARN, detail);
            }
        }
    }

    /* boltctl inventory is informational; do not over-parse human output. */
    if (used < max_results) {
        static const char *const boltctl_list_argv[] = {"boltctl", "list", NULL};
        char buffer[4096] = {0};
        int exit_status = -1;

        if (!trustprobe_command_exists("boltctl")) {
            results[used++] = make_result("Thunderbolt devices (optional)", CHECK_SKIP,
                "boltctl not installed");
        } else if (!trustprobe_capture_argv_status(boltctl_list_argv, buffer, sizeof(buffer), &exit_status) ||
            exit_status != 0) {
            results[used++] = make_result("Thunderbolt devices (optional)", CHECK_SKIP,
                "unable to list Thunderbolt devices");
        } else {
            char *trimmed = trustprobe_trim(buffer);
            if (*trimmed == '\0') {
                results[used++] = make_result("Thunderbolt devices (optional)", CHECK_OK,
                    "no visible Thunderbolt devices");
            } else {
                results[used++] = make_result("Thunderbolt devices (optional)", CHECK_OK,
                    "device list available");
            }
        }
    }

    return used;
}
