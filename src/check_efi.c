#include <stddef.h>
#include <stdio.h>

#include "checks.h"
#include "runtime.h"

size_t trustprobe_check_efi(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *efi_path = "/sys/firmware/efi";

    if (used < max_results) {
        /*
         * Legacy BIOS blocks Secure Boot entirely, so EFI visibility is a real
         * boot-trust signal even before we inspect higher-level firmware state.
         */
        if (trustprobe_file_exists(efi_path)) {
            results[used++] = make_result("EFI boot mode", CHECK_OK, "UEFI firmware interface visible");
        } else {
            results[used++] = make_result("EFI boot mode", CHECK_WARN, "EFI runtime interface not visible; legacy BIOS mode likely");
        }
    }

    return used;
}
