#ifndef TRUSTPROBE_SILICON_PARSERS_H
#define TRUSTPROBE_SILICON_PARSERS_H

#include <stdbool.h>
#include <stddef.h>

typedef struct {
    bool iommu_disabled;
    bool vendor_iommu_on;
    bool passthrough_on;
    bool passthrough_off;
    bool strict_on;
    bool strict_off;
} trustprobe_iommu_cmdline_t;

typedef enum {
    TRUSTPROBE_CPU_VENDOR_UNKNOWN = 0,
    TRUSTPROBE_CPU_VENDOR_AMD,
    TRUSTPROBE_CPU_VENDOR_INTEL,
} trustprobe_cpu_vendor_t;

void trustprobe_parse_iommu_cmdline(const char *text, trustprobe_iommu_cmdline_t *cmdline);
bool trustprobe_extract_microcode_revision(const char *text, char *buffer, size_t size);
trustprobe_cpu_vendor_t trustprobe_cpu_vendor(void);

#endif
