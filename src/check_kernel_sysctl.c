#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include "checks.h"
#include "runtime.h"

static bool read_sysctl_int(const char *proc_path, int *value) {
    char buf[32] = {0};
    if (!trustprobe_read_file_text(proc_path, buf, sizeof(buf))) {
        return false;
    }
    trustprobe_trim(buf);
    char *end = NULL;
    long v = strtol(buf, &end, 10);
    if (end == buf || *end != '\0') {
        return false;
    }
    *value = (int)v;
    return true;
}

static void check_sysctl_ge(const char *proc_path, const char *label,
                            int threshold,
                            check_result_t *results, size_t *used,
                            size_t max_results) {
    if (*used >= max_results) {
        return;
    }

    int value = 0;
    if (!read_sysctl_int(proc_path, &value)) {
        results[(*used)++] = make_result(label, CHECK_SKIP, "not readable");
        return;
    }

    char detail[128];
    if (value >= threshold) {
        snprintf(detail, sizeof(detail), "value %d (>= %d)", value, threshold);
        results[(*used)++] = make_result(label, CHECK_OK, detail);
    } else {
        snprintf(detail, sizeof(detail), "value %d (expected >= %d)", value, threshold);
        results[(*used)++] = make_result(label, CHECK_WARN, detail);
    }
}

size_t trustprobe_check_kernel_sysctl(check_result_t *results, size_t max_results) {
    size_t used = 0;

    check_sysctl_ge("/proc/sys/kernel/kptr_restrict",
                    "sysctl kptr_restrict", 1,
                    results, &used, max_results);

    check_sysctl_ge("/proc/sys/kernel/dmesg_restrict",
                    "sysctl dmesg_restrict", 1,
                    results, &used, max_results);

    check_sysctl_ge("/proc/sys/kernel/yama/ptrace_scope",
                    "sysctl yama.ptrace_scope", 1,
                    results, &used, max_results);

    check_sysctl_ge("/proc/sys/kernel/unprivileged_bpf_disabled",
                    "sysctl unprivileged_bpf_disabled", 1,
                    results, &used, max_results);

    check_sysctl_ge("/proc/sys/kernel/kexec_load_disabled",
                    "sysctl kexec_load_disabled", 1,
                    results, &used, max_results);

    return used;
}
