#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"

static const char *const SERIAL_GETTY_UNITS[] = {
    "serial-getty@ttyS0.service",
    "serial-getty@ttyAMA0.service",
    "serial-getty@ttyUSB0.service",
    NULL,
};

static bool cmdline_has_serial_console(void) {
    char buf[4096] = {0};
    if (!bythos_read_file_text("/proc/cmdline", buf, sizeof(buf))) {
        return false;
    }
    return strstr(buf, "console=ttyS")   != NULL ||
           strstr(buf, "console=ttyAMA") != NULL ||
           strstr(buf, "console=ttyUSB") != NULL;
}

size_t bythos_check_serial_console(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (cmdline_has_serial_console()) {
        EMIT("serial kernel console", CHECK_WARN, "active in kernel cmdline");
    } else {
        EMIT("serial kernel console", CHECK_OK, "absent from kernel cmdline");
    }

    {
        const char *active_unit = NULL;
        bool any_present = false;
        bool systemctl_unavailable = false;

        for (size_t i = 0; SERIAL_GETTY_UNITS[i] != NULL; i++) {
            switch (bythos_probe_systemd_service(SERIAL_GETTY_UNITS[i])) {
            case BYTHOS_SERVICE_STATE_ACTIVE:
                active_unit = SERIAL_GETTY_UNITS[i];
                break;
            case BYTHOS_SERVICE_STATE_INACTIVE:
                any_present = true;
                break;
            case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
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
            EMIT_INSTALL("serial getty service", "systemctl not available");
        } else if (active_unit != NULL) {
            char detail[BYTHOS_DETAIL_MAX];
            snprintf(detail, sizeof(detail), "%s is active", active_unit);
            EMIT("serial getty service", CHECK_WARN, detail);
        } else if (any_present) {
            EMIT("serial getty service", CHECK_OK, "none active");
        } else {
            EMIT("serial getty service", CHECK_SKIP, "none present");
        }
    }

    return used;
}
