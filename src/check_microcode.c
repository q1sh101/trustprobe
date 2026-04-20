#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t trustprobe_check_microcode(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *cpuinfo_path = "/proc/cpuinfo";

    if (used < max_results) {
        static char cpuinfo[65536];
        char revision[128] = {0};

        memset(cpuinfo, 0, sizeof(cpuinfo));

        if (!trustprobe_read_file_text(cpuinfo_path, cpuinfo, sizeof(cpuinfo))) {
            results[used++] = make_result("CPU microcode", CHECK_WARN, "unable to read /proc/cpuinfo");
        } else if (trustprobe_extract_microcode_revision(cpuinfo, revision, sizeof(revision))) {
            char detail[160];
            snprintf(detail, sizeof(detail), "loaded revision %s", revision);
            results[used++] = make_result("CPU microcode", CHECK_OK, detail);
        } else {
            results[used++] = make_result("CPU microcode", CHECK_WARN, "microcode revision not visible");
        }
    }

    if (used < max_results) {
        if (trustprobe_command_exists("spectre-meltdown-checker")) {
            results[used++] = make_result("spectre-meltdown-checker (optional)", CHECK_OK,
                "installed");
        } else {
            results[used++] = make_result("spectre-meltdown-checker (optional)", CHECK_SKIP,
                "not installed");
        }
    }

    return used;
}
