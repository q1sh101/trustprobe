#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "checks.h"
#include "runtime.h"
#include "silicon_parsers.h"

#define INTEL_PCH_CONFIG "/sys/bus/pci/devices/0000:00:1f.0/config"
#define BIOS_CNTL_OFFSET ((off_t)0xDC)

size_t trustprobe_check_bios_cntl(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) return used;

    if (trustprobe_cpu_vendor() != TRUSTPROBE_CPU_VENDOR_INTEL) {
        return used;
    }

    if (!trustprobe_file_exists(INTEL_PCH_CONFIG)) {
        results[used++] = make_result("BIOS_CNTL", CHECK_SKIP, "Intel PCH not found");
        return used;
    }

    int fd = open(INTEL_PCH_CONFIG, O_RDONLY);
    if (fd < 0) {
        results[used++] = make_result("BIOS_CNTL", CHECK_SKIP, "PCI config not readable");
        return used;
    }

    uint8_t byte = 0;
    ssize_t n = pread(fd, &byte, 1, BIOS_CNTL_OFFSET);
    close(fd);

    if (n != 1) {
        results[used++] = make_result("BIOS_CNTL", CHECK_SKIP, "BIOS_CNTL register unreadable");
        return used;
    }

    unsigned int bioswe  = (unsigned int)(byte & 0x01u);
    unsigned int ble     = (unsigned int)((byte >> 1) & 0x01u);
    unsigned int smm_bwp = (unsigned int)((byte >> 5) & 0x01u);

    if (bioswe) {
        results[used++] = make_result("BIOS_CNTL", CHECK_WARN,
            "BIOSWE set: BIOS region write enabled");
    } else if (!ble) {
        results[used++] = make_result("BIOS_CNTL", CHECK_WARN,
            "BLE not set: BIOS lock enable missing");
    } else if (!smm_bwp) {
        results[used++] = make_result("BIOS_CNTL", CHECK_WARN,
            "SMM_BWP not set: SMM-only write not enforced");
    } else {
        results[used++] = make_result("BIOS_CNTL", CHECK_OK,
            "BLE and SMM_BWP set; BIOS region protected");
    }

    return used;
}
