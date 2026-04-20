#include <stddef.h>
#include <stdio.h>

#include "checks.h"
#include "runtime.h"
#include "storage_parsers.h"

size_t trustprobe_check_luks(check_result_t *results, size_t max_results) {
    size_t used = 0;
    static const char *const lsblk_argv[] = {"lsblk", "-P", "-o", "NAME,TYPE,FSTYPE", NULL};

    if (used < max_results) {
        char buffer[8192] = {0};
        int status = -1;
        trustprobe_lsblk_posture_t posture = {0};

        if (!trustprobe_command_exists("lsblk")) {
            results[used++] = make_result("LUKS block devices", CHECK_SKIP, "lsblk not available");
        } else if (!trustprobe_capture_argv_status(lsblk_argv, buffer, sizeof(buffer), &status)) {
            results[used++] = make_result("LUKS block devices", CHECK_WARN, "unable to inspect block devices");
        } else if (status != 0) {
            results[used++] = make_result("LUKS block devices", CHECK_WARN, "lsblk inspection failed");
        } else {
            trustprobe_parse_lsblk_posture(buffer, &posture);
            if (posture.luks_count > 0) {
                char detail[224];
                snprintf(
                    detail,
                    sizeof(detail),
                    "%zu LUKS-encrypted volume(s) visible",
                    posture.luks_count
                );
                results[used++] = make_result("LUKS block devices", CHECK_OK, detail);
            } else if (posture.crypt_count > 0 && posture.crypt_count == posture.crypt_swap_count) {
                char detail[224];
                snprintf(
                    detail,
                    sizeof(detail),
                    "%zu encrypted swap device(s) visible; %s",
                    posture.crypt_swap_count,
                    "no LUKS-encrypted persistent volumes detected"
                );
                results[used++] = make_result("LUKS block devices", CHECK_WARN, detail);
            } else if (posture.crypt_count > 0) {
                char detail[224];
                snprintf(
                    detail,
                    sizeof(detail),
                    "%zu encrypted mapper device(s) visible; %s",
                    posture.crypt_count,
                    "no LUKS signature detected"
                );
                results[used++] = make_result("LUKS block devices", CHECK_WARN, detail);
            } else {
                results[used++] = make_result(
                    "LUKS block devices",
                    CHECK_WARN,
                    "no LUKS-encrypted volumes detected"
                );
            }
        }
    }

    return used;
}
