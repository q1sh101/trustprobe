#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "checks.h"
#include "runtime.h"

#define MSR_IA32_DEBUG_INTERFACE 0xC80ULL
#define DCI_ENABLE_BIT  (UINT64_C(1) << 0)
#define DCI_LOCK_BIT    (UINT64_C(1) << 30)

static bool cpu_is_intel(void) {
    char buf[4096] = {0};
    if (!trustprobe_read_file_text("/proc/cpuinfo", buf, sizeof(buf))) {
        return false;
    }
    return strstr(buf, "GenuineIntel") != NULL;
}

static bool cpu_is_amd(void) {
    char buf[4096] = {0};
    if (!trustprobe_read_file_text("/proc/cpuinfo", buf, sizeof(buf))) {
        return false;
    }
    return strstr(buf, "AuthenticAMD") != NULL;
}

size_t trustprobe_check_dci(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) {
        return used;
    }

    if (cpu_is_amd()) {
        if (trustprobe_file_exists("/sys/module/ccp")) {
            results[used++] = make_result("AMD PSP visibility", CHECK_OK,
                "AMD PSP driver visible; deep audit requires CHIPSEC");
        } else {
            results[used++] = make_result("AMD PSP visibility", CHECK_WARN,
                "AMD PSP driver not loaded");
        }
        return used;
    }

    if (!cpu_is_intel()) {
        results[used++] = make_result("Intel DCI", CHECK_SKIP, "unknown CPU vendor");
        return used;
    }

    static const char *const MSR_PATH = "/dev/cpu/0/msr";

    if (!trustprobe_file_exists(MSR_PATH)) {
        results[used++] = make_result("Intel DCI", CHECK_SKIP, "msr device not available");
        return used;
    }

    int fd = open(MSR_PATH, O_RDONLY);
    if (fd < 0) {
        if (errno == EACCES) {
            results[used++] = make_root_result("Intel DCI", CHECK_SKIP, "requires root to read MSR");
        } else {
            results[used++] = make_result("Intel DCI", CHECK_SKIP, "MSR 0xC80 unreadable");
        }
        return used;
    }

    uint64_t val = 0;
    ssize_t n = pread(fd, &val, sizeof(val), (off_t)MSR_IA32_DEBUG_INTERFACE);
    close(fd);

    if (n != (ssize_t)sizeof(val)) {
        results[used++] = make_result("Intel DCI", CHECK_SKIP, "MSR 0xC80 unreadable");
        return used;
    }

    bool enabled = (val & DCI_ENABLE_BIT) != 0;
    bool locked  = (val & DCI_LOCK_BIT)  != 0;

    if (enabled) {
        results[used++] = make_result("Intel DCI", CHECK_FAIL,
            locked ? "DCI enabled and locked (cannot be disabled without reboot)"
                   : "DCI enabled - USB-C debug access possible");
    } else if (locked) {
        results[used++] = make_result("Intel DCI", CHECK_OK, "DCI disabled and locked");
    } else {
        results[used++] = make_result("Intel DCI", CHECK_WARN, "DCI disabled but not locked");
    }

    return used;
}
