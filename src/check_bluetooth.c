#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "checks.h"
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

size_t trustprobe_check_bluetooth(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used < max_results) {
        if (!bluetooth_hardware_visible()) {
            results[used++] = make_result("Bluetooth hardware", CHECK_SKIP, "no Bluetooth hardware visible");
            return used;
        }
        results[used++] = make_result("Bluetooth hardware", CHECK_OK, "Bluetooth hardware present");
    }

    bool service_active = false;
    if (used < max_results) {
        switch (trustprobe_probe_systemd_service("bluetooth.service")) {
        case TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
            results[used++] = make_result("Bluetooth service", CHECK_SKIP, "systemctl not available");
            break;
        case TRUSTPROBE_SERVICE_STATE_ACTIVE:
            service_active = true;
            results[used++] = make_result("Bluetooth service", CHECK_OK, "service is running");
            break;
        case TRUSTPROBE_SERVICE_STATE_INACTIVE:
            results[used++] = make_result("Bluetooth service", CHECK_OK, "service is inactive");
            break;
        case TRUSTPROBE_SERVICE_STATE_MISSING:
            results[used++] = make_result("Bluetooth service", CHECK_SKIP, "service not installed");
            break;
        default:
            results[used++] = make_result("Bluetooth service", CHECK_SKIP, "state unavailable");
            break;
        }
    }

    if (!service_active) {
        return used;
    }

    static const char *const btctl_argv[] = {"bluetoothctl", "show", NULL};
    char output[4096] = {0};
    int exit_status = -1;
    bool btctl_ok = trustprobe_command_exists("bluetoothctl") &&
                    trustprobe_capture_argv_status(btctl_argv, output, sizeof(output), &exit_status) &&
                    exit_status == 0;

    if (used < max_results) {
        if (!btctl_ok) {
            results[used++] = make_result("Bluetooth discoverable", CHECK_SKIP, "bluetoothctl not available");
        } else if (strstr(output, "Discoverable: yes") != NULL) {
            results[used++] = make_result("Bluetooth discoverable", CHECK_FAIL, "adapter is discoverable");
        } else {
            results[used++] = make_result("Bluetooth discoverable", CHECK_OK, "not discoverable");
        }
    }

    if (used < max_results) {
        if (!btctl_ok) {
            results[used++] = make_result("Bluetooth pairable", CHECK_SKIP, "bluetoothctl not available");
        } else if (strstr(output, "Pairable: yes") != NULL) {
            results[used++] = make_result("Bluetooth pairable", CHECK_WARN, "adapter is pairable");
        } else {
            results[used++] = make_result("Bluetooth pairable", CHECK_OK, "not pairable");
        }
    }

    return used;
}
