#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"

static const char *const BYTHOS_DCONF_POLICY_PATH = "/etc/dconf/db/local.d/00-usb-hardening";
static const char *const BYTHOS_DCONF_PROFILE_PATH = "/etc/dconf/profile/user";
static const char *const BYTHOS_DCONF_USB_PROTECTION_KEY = "usb-protection";
static const char *const BYTHOS_DCONF_AUTOMOUNT_KEY = "automount";
static const char *const BYTHOS_DCONF_AUTOMOUNT_OPEN_KEY = "automount-open";
static const char *const BYTHOS_DCONF_AUTORUN_KEY = "autorun-never";
static const char *const BYTHOS_DCONF_READ_ONLY_MEDIA_KEY = "mount-removable-storage-devices-as-read-only";

static bool dconf_value_matches(const char *path, const char *key, const char *expected) {
    char value[64] = {0};

    if (!bythos_read_key_value(path, key, value, sizeof(value))) {
        return false;
    }

    return strcmp(value, expected) == 0;
}

size_t bythos_check_desktop_usb(check_result_t *results, size_t max_results) {
    const char *dconf_policy = BYTHOS_DCONF_POLICY_PATH;
    const char *dconf_profile = BYTHOS_DCONF_PROFILE_PATH;
    size_t used = 0;
    bool has_systemctl = false;
    bool policy_readable = false;
    static const char *usbguard_dbus_enabled_argv[] = {"systemctl", "is-enabled", "usbguard-dbus.service", NULL};

    has_systemctl = bythos_command_exists("systemctl");

    {
        char buffer[128] = {0};
        int exit_status = 0;
        if (!has_systemctl) {
            EMIT("usbguard-dbus masked", CHECK_WARN, "systemctl not available");
        } else if (bythos_capture_argv_status(usbguard_dbus_enabled_argv, buffer, sizeof(buffer), &exit_status)) {
            if (strstr(buffer, "masked") != NULL) {
                EMIT("usbguard-dbus masked", CHECK_OK, "D-Bus bridge disabled at socket level");
            } else if (strstr(buffer, "disabled") != NULL) {
                EMIT("usbguard-dbus masked", CHECK_FAIL, "disabled but not masked");
            } else if (exit_status == 0) {
                EMIT("usbguard-dbus masked", CHECK_FAIL, "service is enabled");
            } else {
                EMIT("usbguard-dbus masked", CHECK_WARN, "unexpected unit state");
            }
        } else {
            EMIT("usbguard-dbus masked", CHECK_WARN, "unable to read unit state");
        }
    }

    {
        FILE *probe = fopen(dconf_policy, "r");
        if (probe != NULL) {
            fclose(probe);
            policy_readable = true;
            EMIT("GNOME USB policy file", CHECK_OK, "dconf policy file found");
        } else if (errno == ENOENT) {
            EMIT("GNOME USB policy file", CHECK_WARN, "dconf policy file not found");
        } else {
            EMIT_ROOT("GNOME USB policy file", CHECK_SKIP, "dconf policy file not readable");
        }
    }

    if (policy_readable) {
        /*
         * These dconf keys are desktop-side guardrails around removable media behavior.
         * Missing them weakens the boundary, but does not override USBGuard's primary deny path by itself.
         */
        if (dconf_value_matches(dconf_policy, BYTHOS_DCONF_USB_PROTECTION_KEY, "false")) {
            EMIT("GNOME USB protection", CHECK_OK, "usb-protection deferred to USBGuard");
        } else {
            EMIT("GNOME USB protection", CHECK_WARN, "usb-protection=false not found");
        }
    }

    if (policy_readable) {
        if (dconf_value_matches(dconf_policy, BYTHOS_DCONF_AUTOMOUNT_KEY, "false") &&
            dconf_value_matches(dconf_policy, BYTHOS_DCONF_AUTOMOUNT_OPEN_KEY, "false")) {
            EMIT("automount disabled", CHECK_OK, "automount-open also disabled");
        } else {
            EMIT("automount disabled", CHECK_WARN, "missing automount hardening keys");
        }
    }

    if (policy_readable) {
        if (dconf_value_matches(dconf_policy, BYTHOS_DCONF_AUTORUN_KEY, "true")) {
            EMIT("autorun disabled", CHECK_OK, "autorun-never set");
        } else {
            EMIT("autorun disabled", CHECK_WARN, "autorun-never not found");
        }
    }

    if (policy_readable) {
        if (dconf_value_matches(dconf_policy, BYTHOS_DCONF_READ_ONLY_MEDIA_KEY, "true")) {
            EMIT("removable media lockdown", CHECK_OK, "read-only enforced");
        } else {
            EMIT("removable media lockdown", CHECK_WARN, "read-only enforcement not found");
        }
    }

    if (bythos_file_exists(dconf_profile)) {
        EMIT("dconf system profile", CHECK_OK, "system dconf profile present");
    } else {
        EMIT("dconf system profile", CHECK_WARN, "system dconf profile missing");
    }

    return used;
}
