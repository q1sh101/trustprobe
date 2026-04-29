#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"

static bool bluetooth_hardware_visible(void) {
    DIR *dir = opendir("/sys/class/bluetooth");
    if (dir == NULL) {
        return false;
    }
    struct dirent *entry;
    bool found = false;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        found = true;
        break;
    }
    closedir(dir);
    return found;
}

size_t bythos_check_bluetooth(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (!bluetooth_hardware_visible()) {
        EMIT("Bluetooth hardware", CHECK_SKIP, "adapter not detected");
        return used;
    }
    EMIT("Bluetooth hardware", CHECK_OK, "adapter detected");

    bool service_active = false;
    switch (bythos_probe_systemd_service("bluetooth.service")) {
    case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
        EMIT_INSTALL("Bluetooth service", "systemctl not available");
        break;
    case BYTHOS_SERVICE_STATE_ACTIVE:
        service_active = true;
        EMIT("Bluetooth service", CHECK_OK, "running");
        break;
    case BYTHOS_SERVICE_STATE_INACTIVE:
        EMIT("Bluetooth service", CHECK_OK, "installed but inactive");
        break;
    case BYTHOS_SERVICE_STATE_MISSING:
        EMIT_INSTALL("Bluetooth service", "not installed");
        break;
    default:
        EMIT("Bluetooth service", CHECK_SKIP, "state unavailable");
        break;
    }

    if (!service_active) {
        return used;
    }

    static const char *const btctl_argv[] = {"bluetoothctl", "show", NULL};
    char output[4096] = {0};
    int exit_status = -1;
    bool btctl_ok = bythos_command_exists("bluetoothctl") &&
                    bythos_capture_argv_status(btctl_argv, output, sizeof(output), &exit_status) &&
                    exit_status == 0;

    if (!btctl_ok) {
        EMIT_INSTALL("Bluetooth discoverable", "bluetoothctl not available");
    } else if (strstr(output, "Discoverable: yes") != NULL) {
        EMIT("Bluetooth discoverable", CHECK_FAIL, "adapter advertising presence");
    } else {
        EMIT("Bluetooth discoverable", CHECK_OK, "not advertising presence");
    }

    if (!btctl_ok) {
        EMIT_INSTALL("Bluetooth pairable", "bluetoothctl not available");
    } else if (strstr(output, "Pairable: yes") != NULL) {
        EMIT("Bluetooth pairable", CHECK_WARN, "accepting new pairings");
    } else {
        EMIT("Bluetooth pairable", CHECK_OK, "not accepting new pairings");
    }

    return used;
}
