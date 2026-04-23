#include <stddef.h>

#include "checks.h"
#include "runtime.h"

size_t trustprobe_check_kernel_tools(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used < max_results) {
        if (trustprobe_command_exists("kernel-hardening-checker")) {
            results[used++] = make_result("kernel-hardening-checker (optional)", CHECK_OK,
                "installed");
        } else {
            results[used++] = make_result("kernel-hardening-checker (optional)", CHECK_SKIP,
                "not installed");
        }
    }

    if (used < max_results) {
        if (trustprobe_file_exists("/sys/module/lkrg")) {
            results[used++] = make_result("LKRG module (optional)", CHECK_OK,
                "loaded");
        } else {
            results[used++] = make_result("LKRG module (optional)", CHECK_SKIP,
                "not loaded");
        }
    }

    return used;
}
