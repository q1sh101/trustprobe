#include <stddef.h>
#include <stdio.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"

size_t bythos_check_efi(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *efi_path = "/sys/firmware/efi";

    bool efi_visible = bythos_file_exists(efi_path);

    if (efi_visible) {
        EMIT("EFI boot mode", CHECK_OK, "UEFI firmware interface visible");
    } else {
        EMIT("EFI boot mode", CHECK_WARN, "EFI runtime interface not visible; legacy BIOS mode likely");
    }

    if (!efi_visible) {
        EMIT("ESRT entries", CHECK_SKIP, "EFI runtime not visible");
    } else {
        size_t count = 0;
        bool readable = bythos_count_child_dirs(
            "/sys/firmware/efi/esrt/entries", &count);
        if (!readable || count == 0) {
            EMIT("ESRT entries", CHECK_WARN,
                "no ESRT entries; fwupd cannot update firmware");
        } else {
            char detail[BYTHOS_DETAIL_MAX];
            snprintf(detail, sizeof(detail), "%zu firmware %s",
                count, bythos_pl(count, "entry", "entries"));
            EMIT("ESRT entries", CHECK_OK, detail);
        }
    }

    return used;
}
