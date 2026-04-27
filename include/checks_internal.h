#ifndef BYTHOS_CHECKS_INTERNAL_H
#define BYTHOS_CHECKS_INTERNAL_H

#include <stddef.h>

#include "types.h"

size_t bythos_check_usbguard(check_result_t *results, size_t max_results);
size_t bythos_check_usbguard_policy(check_result_t *results, size_t max_results);
size_t bythos_check_desktop_usb(check_result_t *results, size_t max_results);
size_t bythos_check_iommu(check_result_t *results, size_t max_results);
size_t bythos_check_bluetooth(check_result_t *results, size_t max_results);
size_t bythos_check_dci(check_result_t *results, size_t max_results);
size_t bythos_check_serial_console(check_result_t *results, size_t max_results);
size_t bythos_check_bolt(check_result_t *results, size_t max_results);
size_t bythos_check_efi(check_result_t *results, size_t max_results);
size_t bythos_check_tpm(check_result_t *results, size_t max_results);
size_t bythos_check_microcode(check_result_t *results, size_t max_results);
size_t bythos_check_luks(check_result_t *results, size_t max_results);
size_t bythos_check_fwupd(check_result_t *results, size_t max_results);
size_t bythos_check_sbctl(check_result_t *results, size_t max_results);
size_t bythos_check_secureboot(check_result_t *results, size_t max_results);
size_t bythos_check_bios_boot(check_result_t *results, size_t max_results);
size_t bythos_check_boot_chain(check_result_t *results, size_t max_results);
size_t bythos_check_esp_posture(check_result_t *results, size_t max_results);
size_t bythos_check_bios_cntl(check_result_t *results, size_t max_results);
size_t bythos_check_me_version(check_result_t *results, size_t max_results);

#endif
