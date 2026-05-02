#include <dirent.h>
#include <stdbool.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"

static const char *const BOLT_SYSFS_BASE = "/sys/bus/thunderbolt/devices";

static bool read_tb_domain_attr(const char *attr, char *buffer, size_t size) {
    DIR *dir = opendir(BOLT_SYSFS_BASE);
    if (dir == NULL) return false;

    struct dirent *entry;
    while ((entry = bythos_readdir_safe(dir, NULL)) != NULL) {
        if (strncmp(entry->d_name, "domain", 6) != 0) continue;

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s/%s",
                     BOLT_SYSFS_BASE, entry->d_name, attr) >= (int)sizeof(path)) continue;

        if (bythos_read_file_text(path, buffer, size)) {
            closedir(dir);
            return true;
        }
    }

    closedir(dir);
    return false;
}

static bool tb_controller_present(void) {
    DIR *dir = opendir(BOLT_SYSFS_BASE);
    if (dir == NULL) return false;

    bool found = false;
    struct dirent *entry;
    while ((entry = bythos_readdir_safe(dir, NULL)) != NULL) {
        if (strncmp(entry->d_name, "domain", 6) == 0) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

size_t bythos_check_bolt_dma(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (!tb_controller_present()) {
        EMIT_SKIP_HW("Thunderbolt DMA protection", "Thunderbolt");
        return used;
    }

    char val[8] = {0};
    if (!read_tb_domain_attr("iommu_dma_protection", val, sizeof(val))) {
        EMIT_SKIP_FEATURE("Thunderbolt DMA protection", "iommu_dma_protection");
    } else {
        char *v = bythos_trim(val);
        if (strcmp(v, "1") == 0) {
            EMIT("Thunderbolt DMA protection", CHECK_OK, "pre-boot DMA active");
        } else {
            EMIT("Thunderbolt DMA protection", CHECK_WARN, "pre-boot DMA inactive");
        }
    }

    return used;
}
