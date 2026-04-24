#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "checks.h"
#include "runtime.h"
#include "storage_parsers.h"

#define PCR_BIT(n) (1u << (unsigned int)(n))

static void pcr_mask_to_str(uint32_t mask, char *out, size_t size) {
    size_t pos = 0;
    bool first = true;
    for (unsigned int i = 0; i < 32u && pos + 6 < size; i++) {
        if (mask & PCR_BIT(i)) {
            if (!first) out[pos++] = ' ';
            pos += (size_t)snprintf(out + pos, size - pos, "%u", i);
            first = false;
        }
    }
    if (pos == 0 && size > 0) out[0] = '\0';
}

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
            size_t luks_no_token = 0;
            size_t luks_token_noparsed = 0;
            uint32_t weakest_mask = 0xFFFFFFFFu;
            unsigned int weakest_popcount = 32u;
            bool any_token = false;
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
                                dump_status == 0) {
                                if (strstr(dump_buf, "tpm2") != NULL) {
                                    any_token = true;
                                    uint32_t mask = 0;
                                    if (trustprobe_parse_luks_pcr_mask(dump_buf, &mask)) {
                                        uint32_t tmp = mask;
                                        unsigned int pc = 0;
                                        while (tmp) { pc += tmp & 1u; tmp >>= 1; }
                                        if (pc < weakest_popcount) {
                                            weakest_popcount = pc;
                                            weakest_mask = mask;
                                        }
                                    } else {
                                        luks_token_noparsed++;
                                    }
                                } else {
                                    luks_no_token++;
                                }
                            }
                        }
                    }
                }

                line = eol != NULL ? eol + 1 : line + line_len;
            }

            if (luks_found == 0) {
                results[used++] = make_result("LUKS TPM binding", CHECK_SKIP,
                    "no LUKS devices found");
            } else if (!any_token) {
                results[used++] = make_result("LUKS TPM binding", CHECK_WARN,
                    "LUKS device without TPM2 token");
            } else if (luks_no_token > 0) {
                results[used++] = make_result("LUKS TPM binding", CHECK_WARN,
                    "at least one LUKS device without TPM2 token");
            } else if (weakest_mask == 0xFFFFFFFFu || weakest_mask == 0) {
                /* token present but PCR field not parsed */
                char detail[TRUSTPROBE_DETAIL_MAX];
                snprintf(detail, sizeof(detail),
                    "TPM2 token on %zu device(s); PCR binding unreadable", luks_found);
                results[used++] = make_result("LUKS TPM binding", CHECK_WARN, detail);
            } else {
                bool has7 = (weakest_mask & PCR_BIT(7)) != 0;
                bool has4 = (weakest_mask & PCR_BIT(4)) != 0;
                bool has9 = (weakest_mask & PCR_BIT(9)) != 0;
                bool has0 = (weakest_mask & PCR_BIT(0)) != 0;
                char pcr_str[64] = {0};
                pcr_mask_to_str(weakest_mask, pcr_str, sizeof(pcr_str));
                char detail[TRUSTPROBE_DETAIL_MAX];

                if (!has7) {
                    snprintf(detail, sizeof(detail),
                        "PCRs: %s; PCR 7 absent, Secure Boot state unmeasured", pcr_str);
                    results[used++] = make_result("LUKS TPM binding", CHECK_WARN, detail);
                } else if (!has4 && !has9) {
                    snprintf(detail, sizeof(detail),
                        "PCRs: %s only; bootloader and initramfs unprotected", pcr_str);
                    results[used++] = make_result("LUKS TPM binding", CHECK_WARN, detail);
                } else if (!has9) {
                    snprintf(detail, sizeof(detail),
                        "PCRs: %s; initramfs unprotected", pcr_str);
                    results[used++] = make_result("LUKS TPM binding", CHECK_WARN, detail);
                } else if (has0) {
                    if (luks_token_noparsed > 0) {
                        snprintf(detail, sizeof(detail),
                            "PCRs: %s; %zu device(s) PCR binding unreadable",
                            pcr_str, luks_token_noparsed);
                        results[used++] = make_result("LUKS TPM binding", CHECK_WARN, detail);
                    } else {
                        snprintf(detail, sizeof(detail),
                            "PCRs: %s; firmware and full boot chain measured", pcr_str);
                        results[used++] = make_result("LUKS TPM binding", CHECK_OK, detail);
                    }
                } else {
                    if (luks_token_noparsed > 0) {
                        snprintf(detail, sizeof(detail),
                            "PCRs: %s; %zu device(s) PCR binding unreadable",
                            pcr_str, luks_token_noparsed);
                        results[used++] = make_result("LUKS TPM binding", CHECK_WARN, detail);
                    } else {
                        snprintf(detail, sizeof(detail),
                            "PCRs: %s; boot chain measured", pcr_str);
                        results[used++] = make_result("LUKS TPM binding", CHECK_OK, detail);
                    }
                }
            }
        }
    }

    return used;
}
