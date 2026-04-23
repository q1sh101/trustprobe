#include <stddef.h>

#include "checks.h"
#include "checks_internal.h"

#define REMAINING(used, max) ((used) < (max) ? (max) - (used) : 0)

size_t trustprobe_check_physical(check_result_t *results, size_t max_results) {
    if (results == NULL || max_results == 0) {
        return 0;
    }

    size_t used = 0;

    used += trustprobe_check_usbguard(results + used, REMAINING(used, max_results));
    used += trustprobe_check_usbguard_policy(results + used, REMAINING(used, max_results));
    used += trustprobe_check_desktop_usb(results + used, REMAINING(used, max_results));
    used += trustprobe_check_iommu(results + used, REMAINING(used, max_results));
    used += trustprobe_check_bluetooth(results + used, REMAINING(used, max_results));
    used += trustprobe_check_serial_console(results + used, REMAINING(used, max_results));
    used += trustprobe_check_bolt(results + used, REMAINING(used, max_results));

    return used;
}

size_t trustprobe_check_firmware(check_result_t *results, size_t max_results) {
    if (results == NULL || max_results == 0) {
        return 0;
    }

    size_t used = 0;

    used += trustprobe_check_efi(results + used, REMAINING(used, max_results));
    used += trustprobe_check_tpm(results + used, REMAINING(used, max_results));
    used += trustprobe_check_microcode(results + used, REMAINING(used, max_results));
    used += trustprobe_check_luks(results + used, REMAINING(used, max_results));
    used += trustprobe_check_fwupd(results + used, REMAINING(used, max_results));
    used += trustprobe_check_sbctl(results + used, REMAINING(used, max_results));
    used += trustprobe_check_secureboot(results + used, REMAINING(used, max_results));
    used += trustprobe_check_bios_boot(results + used, REMAINING(used, max_results));

    return used;
}

size_t trustprobe_check_kernel(check_result_t *results, size_t max_results) {
    if (results == NULL || max_results == 0) {
        return 0;
    }

    size_t used = 0;

    used += trustprobe_check_kernel_lockdown(results + used, REMAINING(used, max_results));
    used += trustprobe_check_kernel_sysctl(results + used, REMAINING(used, max_results));
    used += trustprobe_check_kernel_tools(results + used, REMAINING(used, max_results));

    return used;
}
