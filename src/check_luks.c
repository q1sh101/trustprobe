#include <stddef.h>
#include <stdio.h>
#include <string.h>

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

    if (used < max_results) {
        static const char *const lsblk_fstype_argv[] = {
            "lsblk", "-r", "-n", "-o", "NAME,FSTYPE", NULL
        };
        char lsblk_buf[4096] = {0};
        int lsblk_status = -1;

        if (!trustprobe_command_exists("lsblk")) {
            results[used++] = make_result("LUKS TPM binding", CHECK_SKIP,
                "lsblk not available");
        } else if (!trustprobe_command_exists("cryptsetup")) {
            results[used++] = make_result("LUKS TPM binding", CHECK_SKIP,
                "cryptsetup not available");
        } else if (!trustprobe_capture_argv_status(lsblk_fstype_argv, lsblk_buf,
                                                    sizeof(lsblk_buf), &lsblk_status) ||
                   lsblk_status != 0) {
            results[used++] = make_result("LUKS TPM binding", CHECK_SKIP,
                "unable to inspect block devices");
        } else {
            size_t luks_found = 0;
            size_t luks_with_token = 0;
            char *line = lsblk_buf;

            while (*line != '\0') {
                char *eol = strchr(line, '\n');
                size_t line_len = eol != NULL ? (size_t)(eol - line) : strlen(line);
                char *space = memchr(line, ' ', line_len);

                if (space != NULL) {
                    size_t namelen = (size_t)(space - line);
                    const char *fstype = space + 1;
                    size_t fstypelen = (size_t)(line + line_len - fstype);

                    while (fstypelen > 0 &&
                           (fstype[fstypelen - 1] == ' ' || fstype[fstypelen - 1] == '\r')) {
                        fstypelen--;
                    }

                    if (fstypelen == 11 && strncmp(fstype, "crypto_LUKS", 11) == 0 &&
                        namelen > 0 && namelen < 64) {
                        char device_path[80] = {0};
                        if (snprintf(device_path, sizeof(device_path),
                                     "/dev/%.*s", (int)namelen, line) < (int)sizeof(device_path)) {
                            const char *dump_argv[] = {
                                "cryptsetup", "luksDump", device_path, NULL
                            };
                            char dump_buf[8192] = {0};
                            int dump_status = -1;
                            luks_found++;
                            if (trustprobe_capture_argv_status(
                                    (const char *const *)dump_argv,
                                    dump_buf, sizeof(dump_buf), &dump_status) &&
                                dump_status == 0 &&
                                strstr(dump_buf, "tpm2") != NULL) {
                                luks_with_token++;
                            }
                        }
                    }
                }

                line = eol != NULL ? eol + 1 : line + line_len;
            }

            if (luks_found == 0) {
                results[used++] = make_result("LUKS TPM binding", CHECK_SKIP,
                    "no LUKS devices found");
            } else if (luks_with_token == luks_found) {
                char detail[TRUSTPROBE_DETAIL_MAX];
                snprintf(detail, sizeof(detail),
                    "LUKS has TPM2 token on %zu device(s)", luks_found);
                results[used++] = make_result("LUKS TPM binding", CHECK_OK, detail);
            } else {
                results[used++] = make_result("LUKS TPM binding", CHECK_WARN,
                    "LUKS device without TPM2 token");
            }
        }
    }

    return used;
}
