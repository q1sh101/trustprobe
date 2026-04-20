#ifndef TRUSTPROBE_CHECKS_INTERNAL_H
#define TRUSTPROBE_CHECKS_INTERNAL_H

#include <stddef.h>

#include "types.h"

size_t trustprobe_check_usbguard(check_result_t *results, size_t max_results);
size_t trustprobe_check_usbguard_policy(check_result_t *results, size_t max_results);
size_t trustprobe_check_desktop_usb(check_result_t *results, size_t max_results);
size_t trustprobe_check_iommu(check_result_t *results, size_t max_results);
size_t trustprobe_check_bolt(check_result_t *results, size_t max_results);
size_t trustprobe_check_efi(check_result_t *results, size_t max_results);
size_t trustprobe_check_tpm(check_result_t *results, size_t max_results);
size_t trustprobe_check_microcode(check_result_t *results, size_t max_results);
size_t trustprobe_check_luks(check_result_t *results, size_t max_results);

#endif
