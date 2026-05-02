#include <stddef.h>
#include <stdio.h>

#include "checks.h"
#include "checks_internal.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_microcode(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *cpuinfo_path = "/proc/cpuinfo";

    {
        char microcode_line[256] = {0};
        char revision[128] = {0};

        if (!bythos_first_line_with_prefix(cpuinfo_path, "microcode", microcode_line, sizeof(microcode_line))) {
            EMIT("CPU microcode", CHECK_WARN, "revision not visible");
        } else if (bythos_extract_microcode_revision(microcode_line, revision, sizeof(revision))) {
            char detail[160];
            snprintf(detail, sizeof(detail), "loaded revision %s", revision);
            EMIT("CPU microcode", CHECK_OK, detail);
        } else {
            EMIT("CPU microcode", CHECK_WARN, "revision not visible");
        }
    }

    if (bythos_command_exists("spectre-meltdown-checker")) {
        EMIT("CPU vulnerability scan", CHECK_OK, "available: spectre-meltdown-checker");
    } else {
        EMIT_SKIP_TOOL_INSTALL("CPU vulnerability scan", "spectre-meltdown-checker");
    }

    return used;
}
