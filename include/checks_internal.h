#ifndef TRUSTPROBE_CHECKS_INTERNAL_H
#define TRUSTPROBE_CHECKS_INTERNAL_H

#include <stddef.h>

#include "types.h"

size_t trustprobe_check_usbguard(check_result_t *results, size_t max_results);
size_t trustprobe_check_usbguard_policy(check_result_t *results, size_t max_results);
size_t trustprobe_check_desktop_usb(check_result_t *results, size_t max_results);
size_t trustprobe_check_iommu(check_result_t *results, size_t max_results);
size_t trustprobe_check_bluetooth(check_result_t *results, size_t max_results);
size_t trustprobe_check_dci(check_result_t *results, size_t max_results);
size_t trustprobe_check_serial_console(check_result_t *results, size_t max_results);
size_t trustprobe_check_bolt(check_result_t *results, size_t max_results);
size_t trustprobe_check_efi(check_result_t *results, size_t max_results);
size_t trustprobe_check_tpm(check_result_t *results, size_t max_results);
size_t trustprobe_check_microcode(check_result_t *results, size_t max_results);
size_t trustprobe_check_luks(check_result_t *results, size_t max_results);
size_t trustprobe_check_fwupd(check_result_t *results, size_t max_results);
size_t trustprobe_check_sbctl(check_result_t *results, size_t max_results);
size_t trustprobe_check_secureboot(check_result_t *results, size_t max_results);
size_t trustprobe_check_bios_boot(check_result_t *results, size_t max_results);
size_t trustprobe_check_boot_chain(check_result_t *results, size_t max_results);
size_t trustprobe_check_kernel_lockdown(check_result_t *results, size_t max_results);
size_t trustprobe_check_kernel_sysctl(check_result_t *results, size_t max_results);
size_t trustprobe_check_kernel_tools(check_result_t *results, size_t max_results);

#endif
