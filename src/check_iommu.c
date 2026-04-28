#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_iommu(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *cmdline_path = "/proc/cmdline";
    const char *groups_path = "/sys/kernel/iommu_groups";
    size_t group_count = 0;
    bool groups_visible = false;

    if (bythos_count_child_dirs(groups_path, &group_count) && group_count > 0) {
        char detail[128];
        snprintf(detail, sizeof(detail), "%zu %s active",
            group_count, bythos_pl(group_count, "group", "groups"));
        groups_visible = true;
        EMIT("IOMMU groups", CHECK_OK, detail);
    } else {
        EMIT("IOMMU groups", CHECK_WARN, "none visible");
    }

    {
        char cmdline[4096] = {0};
        bythos_iommu_cmdline_t parsed = {0};

        if (!bythos_read_file_text(cmdline_path, cmdline, sizeof(cmdline))) {
            if (groups_visible) {
                EMIT("IOMMU DMA posture", CHECK_OK, "runtime groups visible; kernel cmdline unavailable");
            } else {
                EMIT("IOMMU DMA posture", CHECK_WARN, "unable to inspect kernel cmdline");
            }
            return used;
        }

        bythos_parse_iommu_cmdline(cmdline, &parsed);

        if (parsed.iommu_disabled) {
            EMIT("IOMMU DMA posture", CHECK_FAIL, "IOMMU disabled in kernel cmdline");
        } else if (parsed.passthrough_on) {
            EMIT("IOMMU DMA posture", CHECK_FAIL, "passthrough override enabled in kernel cmdline");
        } else if (parsed.strict_off) {
            EMIT("IOMMU DMA posture", CHECK_WARN,
                groups_visible ? "runtime groups visible; strict mode explicitly disabled"
                               : "strict mode explicitly disabled in kernel cmdline");
        } else if (groups_visible) {
            char detail[192];

            if (parsed.passthrough_off && parsed.strict_on) {
                snprintf(detail, sizeof(detail), "runtime groups visible; passthrough disabled; strict mode enabled");
            } else if (parsed.passthrough_off) {
                snprintf(detail, sizeof(detail), "runtime groups visible; passthrough disabled");
            } else if (parsed.strict_on) {
                snprintf(detail, sizeof(detail), "runtime groups visible; strict mode enabled");
            } else if (parsed.vendor_iommu_on) {
                snprintf(detail, sizeof(detail), "runtime groups visible; vendor IOMMU enable flag present");
            } else {
                snprintf(detail, sizeof(detail), "runtime groups visible; no passthrough override seen");
            }

            EMIT("IOMMU DMA posture", CHECK_OK, detail);
        } else if (parsed.passthrough_off || parsed.strict_on || parsed.vendor_iommu_on) {
            EMIT("IOMMU DMA posture", CHECK_WARN, "cmdline looks hardened but runtime groups are not visible");
        } else {
            EMIT("IOMMU DMA posture", CHECK_WARN, "unable to confirm DMA remapping posture");
        }
    }

    return used;
}
