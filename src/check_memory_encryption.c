#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_memory_encryption(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    bythos_cpu_vendor_t vendor = bythos_cpu_vendor();

    if (vendor == BYTHOS_CPU_VENDOR_UNKNOWN) {
        EMIT_SKIP_VENDOR("memory encryption", "CPU vendor undetermined");
        return used;
    }
    if (vendor != BYTHOS_CPU_VENDOR_AMD && vendor != BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_SKIP_VENDOR("memory encryption", "vendor not supported (non-Intel/AMD)");
        return used;
    }

    static char cpuinfo[65536];
    memset(cpuinfo, 0, sizeof(cpuinfo));

    if (!bythos_read_file_text("/proc/cpuinfo", cpuinfo, sizeof(cpuinfo))) {
        EMIT_SKIP_EXEC("memory encryption", "cpuinfo");
        return used;
    }

    bythos_mem_enc_flags_t flags;
    bythos_parse_memory_encryption_flags(cpuinfo, &flags);

    if (vendor == BYTHOS_CPU_VENDOR_AMD) {
        if (!flags.amd_sme) {
            EMIT_SKIP("memory encryption", SKIP_FEATURE_ABSENT,
                "CPU encryption flags not detected");
        } else if (flags.amd_sme_active) {
            EMIT("memory encryption", CHECK_OK, "AMD SME active");
        } else {
            EMIT("memory encryption", CHECK_WARN, "AMD SME supported but inactive");
        }
    } else {
        if (!flags.intel_tme) {
            EMIT_SKIP("memory encryption", SKIP_FEATURE_ABSENT,
                "CPU encryption flags not detected");
        } else {
            EMIT("memory encryption", CHECK_OK,
                "Intel TME capability present; activation not verified");
        }
    }

    return used;
}
