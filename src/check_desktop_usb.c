#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"

static const char *const TRUSTPROBE_DCONF_POLICY_PATH = "/etc/dconf/db/local.d/00-usb-hardening";
static const char *const TRUSTPROBE_DCONF_PROFILE_PATH = "/etc/dconf/profile/user";
static const char *const TRUSTPROBE_DCONF_USB_PROTECTION_KEY = "usb-protection";
static const char *const TRUSTPROBE_DCONF_AUTOMOUNT_KEY = "automount";
static const char *const TRUSTPROBE_DCONF_AUTOMOUNT_OPEN_KEY = "automount-open";
static const char *const TRUSTPROBE_DCONF_AUTORUN_KEY = "autorun-never";
static const char *const TRUSTPROBE_DCONF_READ_ONLY_MEDIA_KEY = "mount-removable-storage-devices-as-read-only";

static bool dconf_value_matches(const char *path, const char *key, const char *expected) {
    char value[64] = {0};

    if (!trustprobe_read_key_value(path, key, value, sizeof(value))) {
        return false;
    }

    return strcmp(value, expected) == 0;
}

size_t trustprobe_check_desktop_usb(check_result_t *results, size_t max_results) {
    const char *dconf_policy = TRUSTPROBE_DCONF_POLICY_PATH;
    const char *dconf_profile = TRUSTPROBE_DCONF_PROFILE_PATH;
    size_t used = 0;
    bool has_systemctl = false;
    bool policy_readable = false;
    static const char *usbguard_dbus_enabled_argv[] = {"systemctl", "is-enabled", "usbguard-dbus.service", NULL};

    has_systemctl = trustprobe_command_exists("systemctl");

    if (used < max_results) {
        char buffer[128] = {0};
        int exit_status = 0;
        if (!has_systemctl) {
            results[used++] = make_result("usbguard-dbus masked", CHECK_WARN, "systemctl not available");
        } else if (trustprobe_capture_argv_status(usbguard_dbus_enabled_argv, buffer, sizeof(buffer), &exit_status)) {
            if (strstr(buffer, "masked") != NULL) {
                results[used++] = make_result("usbguard-dbus masked", CHECK_OK, "desktop D-Bus bridge masked");
            } else if (strstr(buffer, "disabled") != NULL) {
                results[used++] = make_result("usbguard-dbus masked", CHECK_FAIL, "disabled but not masked");
            } else if (exit_status == 0) {
                results[used++] = make_result("usbguard-dbus masked", CHECK_FAIL, "service is enabled");
            } else {
                results[used++] = make_result("usbguard-dbus masked", CHECK_WARN, "unexpected unit state");
            }
        } else {
            results[used++] = make_result("usbguard-dbus masked", CHECK_WARN, "unable to read unit state");
        }
    }

    if (used < max_results) {
        FILE *probe = fopen(dconf_policy, "r");
        if (probe != NULL) {
            fclose(probe);
            policy_readable = true;
            results[used++] = make_result("GNOME USB policy file", CHECK_OK, "dconf policy file found");
        } else if (errno == ENOENT) {
            results[used++] = make_result("GNOME USB policy file", CHECK_WARN, "dconf policy file not found");
        } else {
            results[used++] = make_root_result("GNOME USB policy file", CHECK_SKIP, "dconf policy file not readable");
        }
    }

    if (policy_readable && used < max_results) {
        /*
         * These dconf keys are desktop-side guardrails around removable media behavior.
         * Missing them weakens the boundary, but does not override USBGuard's primary deny path by itself.
         */
        if (dconf_value_matches(dconf_policy, TRUSTPROBE_DCONF_USB_PROTECTION_KEY, "false")) {
            results[used++] = make_result("GNOME USB protection", CHECK_OK, "usb-protection disabled");
        } else {
            results[used++] = make_result("GNOME USB protection", CHECK_WARN, "usb-protection=false not found");
        }
    }

    if (policy_readable && used < max_results) {
        if (dconf_value_matches(dconf_policy, TRUSTPROBE_DCONF_AUTOMOUNT_KEY, "false") &&
            dconf_value_matches(dconf_policy, TRUSTPROBE_DCONF_AUTOMOUNT_OPEN_KEY, "false")) {
            results[used++] = make_result("automount disabled", CHECK_OK, "automount and automount-open disabled");
        } else {
            results[used++] = make_result("automount disabled", CHECK_WARN, "missing automount hardening keys");
        }
    }

    if (policy_readable && used < max_results) {
        if (dconf_value_matches(dconf_policy, TRUSTPROBE_DCONF_AUTORUN_KEY, "true")) {
            results[used++] = make_result("autorun disabled", CHECK_OK, "autorun-never set");
        } else {
            results[used++] = make_result("autorun disabled", CHECK_WARN, "autorun-never not found");
        }
    }

    if (policy_readable && used < max_results) {
        if (dconf_value_matches(dconf_policy, TRUSTPROBE_DCONF_READ_ONLY_MEDIA_KEY, "true")) {
            results[used++] = make_result("removable media lockdown", CHECK_OK, "read-only removable media enforced");
        } else {
            results[used++] = make_result("removable media lockdown", CHECK_WARN, "read-only removable media lockdown not found");
        }
    }

    if (used < max_results) {
        if (trustprobe_file_exists(dconf_profile)) {
            results[used++] = make_result("dconf system profile", CHECK_OK, "system dconf profile present");
        } else {
            results[used++] = make_result("dconf system profile", CHECK_WARN, "system dconf profile missing");
        }
    }

    return used;
}
