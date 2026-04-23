#include <stddef.h>
#include <stdio.h>

#include "checks.h"
#include "runtime.h"

size_t trustprobe_check_efi(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *efi_path = "/sys/firmware/efi";

    bool efi_visible = trustprobe_file_exists(efi_path);

    if (used < max_results) {
        if (efi_visible) {
            results[used++] = make_result("EFI boot mode", CHECK_OK, "UEFI firmware interface visible");
        } else {
            results[used++] = make_result("EFI boot mode", CHECK_WARN, "EFI runtime interface not visible; legacy BIOS mode likely");
        }
    }

    if (used < max_results) {
        if (!efi_visible) {
            results[used++] = make_result("ESRT entries", CHECK_SKIP,
                "EFI runtime not visible");
        } else {
            size_t count = 0;
            bool readable = trustprobe_count_child_dirs(
                "/sys/firmware/efi/esrt/entries", &count);
            if (!readable || count == 0) {
                results[used++] = make_result("ESRT entries", CHECK_WARN,
                    "no ESRT entries; fwupd cannot update firmware");
            } else {
                char detail[TRUSTPROBE_DETAIL_MAX];
                snprintf(detail, sizeof(detail), "%zu ESRT firmware entry(ies)", count);
                results[used++] = make_result("ESRT entries", CHECK_OK, detail);
            }
        }
    }

    return used;
}
