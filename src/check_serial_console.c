#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"

static const char *const SERIAL_GETTY_UNITS[] = {
    "serial-getty@ttyS0.service",
    "serial-getty@ttyAMA0.service",
    "serial-getty@ttyUSB0.service",
    NULL,
};

static bool cmdline_has_serial_console(void) {
    char buf[4096] = {0};
    if (!trustprobe_read_file_text("/proc/cmdline", buf, sizeof(buf))) {
        return false;
    }
    return strstr(buf, "console=ttyS")   != NULL ||
           strstr(buf, "console=ttyAMA") != NULL ||
           strstr(buf, "console=ttyUSB") != NULL;
}

size_t trustprobe_check_serial_console(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used < max_results) {
        if (cmdline_has_serial_console()) {
            results[used++] = make_result("Serial kernel console", CHECK_WARN, "serial console active in kernel cmdline");
        } else {
            results[used++] = make_result("Serial kernel console", CHECK_OK, "no serial console in kernel cmdline");
        }
    }

    if (used < max_results) {
        const char *active_unit = NULL;
        bool any_present = false;
        bool systemctl_unavailable = false;

        for (size_t i = 0; SERIAL_GETTY_UNITS[i] != NULL; i++) {
            switch (trustprobe_probe_systemd_service(SERIAL_GETTY_UNITS[i])) {
            case TRUSTPROBE_SERVICE_STATE_ACTIVE:
                active_unit = SERIAL_GETTY_UNITS[i];
                break;
            case TRUSTPROBE_SERVICE_STATE_INACTIVE:
                any_present = true;
                break;
            case TRUSTPROBE_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
                systemctl_unavailable = true;
                break;
            default:
                break;
            }
            if (active_unit != NULL) {
                break;
            }
        }

        if (systemctl_unavailable && !any_present && active_unit == NULL) {
            results[used++] = make_result("Serial getty service", CHECK_SKIP, "systemctl not available");
        } else if (active_unit != NULL) {
            char detail[TRUSTPROBE_DETAIL_MAX];
            snprintf(detail, sizeof(detail), "%s is active", active_unit);
            results[used++] = make_result("Serial getty service", CHECK_WARN, detail);
        } else if (any_present) {
            results[used++] = make_result("Serial getty service", CHECK_OK, "no serial getty service active");
        } else {
            results[used++] = make_result("Serial getty service", CHECK_SKIP, "no serial getty service present");
        }
    }

    return used;
}
