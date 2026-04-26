#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "checks.h"
#include "efi_boot_parsers.h"
#include "runtime.h"

#define EFI_BOOT_ORDER_PATH "/sys/firmware/efi/efivars/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_BOOT_ENTRY_FMT  "/sys/firmware/efi/efivars/Boot%04X-8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_BOOT_NEXT_PATH  "/sys/firmware/efi/efivars/BootNext-8be4df61-93ca-11d2-aa0d-00e098032b8c"

static bool read_boot_entry(uint16_t number, trustprobe_efi_boot_entry_t *entry) {
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), EFI_BOOT_ENTRY_FMT, number) >= (int)sizeof(path)) {
        return false;
    }

    unsigned char buf[4096];
    size_t len = 0;
    if (!trustprobe_read_file_binary(path, buf, sizeof(buf), &len)) {
        return false;
    }

    return trustprobe_parse_efi_boot_entry(buf, len, number, entry);
}

static size_t check_efivars_boot(check_result_t *results, size_t max_results) {
    size_t used = 0;

    unsigned char order_buf[256];
    size_t order_len = 0;

    if (!trustprobe_read_file_binary(EFI_BOOT_ORDER_PATH, order_buf,
                                     sizeof(order_buf), &order_len)) {
        return 0;
    }

    trustprobe_efi_boot_order_t order = {0};
    if (!trustprobe_parse_efi_boot_order(order_buf, order_len, &order)) {
        return 0;
    }

    /* Only active risky entries are a real posture signal. */
    bool usb_in_order = false;
    bool net_in_order = false;
    bool cd_in_order = false;

    for (size_t i = 0; i < order.order_count; i++) {
        trustprobe_efi_boot_entry_t entry = {0};
        if (!read_boot_entry(order.order[i], &entry)) {
            continue;
        }

        if (!entry.active) {
            continue;
        }

        switch (entry.type) {
            case TRUSTPROBE_EFI_BOOT_TYPE_USB:
                usb_in_order = true;
                break;
            case TRUSTPROBE_EFI_BOOT_TYPE_NETWORK:
                net_in_order = true;
                break;
            case TRUSTPROBE_EFI_BOOT_TYPE_CD:
                cd_in_order = true;
                break;
            default:
                break;
        }
    }

    if (used < max_results) {
        if (usb_in_order) {
            results[used++] = make_result("EFI USB boot",
                CHECK_WARN, "active USB boot entry in EFI boot order");
        } else {
            results[used++] = make_result("EFI USB boot",
                CHECK_OK, "no active USB boot entry in EFI boot order");
        }
    }

    if (used < max_results) {
        if (net_in_order) {
            results[used++] = make_result("EFI network boot",
                CHECK_WARN, "active network boot entry in EFI boot order");
        } else {
            results[used++] = make_result("EFI network boot",
                CHECK_OK, "no active network boot entry in EFI boot order");
        }
    }

    if (used < max_results) {
        if (cd_in_order) {
            results[used++] = make_result("EFI CD/DVD boot",
                CHECK_WARN, "active CD/DVD boot entry in EFI boot order");
        } else {
            results[used++] = make_result("EFI CD/DVD boot",
                CHECK_OK, "no active CD/DVD boot entry in EFI boot order");
        }
    }

    /* BootNext: one-shot override for the next reboot */
    if (used < max_results) {
        unsigned char next_buf[16];
        size_t next_len = 0;
        uint16_t next_number = 0;

        if (!trustprobe_file_exists(EFI_BOOT_NEXT_PATH)) {
            results[used++] = make_result("EFI one-shot boot",
                CHECK_OK, "no one-shot EFI boot override");
        } else if (!trustprobe_read_file_binary(EFI_BOOT_NEXT_PATH, next_buf,
                                                 sizeof(next_buf), &next_len) ||
                   !trustprobe_parse_efi_boot_next(next_buf, next_len, &next_number)) {
            results[used++] = make_result("EFI one-shot boot",
                CHECK_WARN, "BootNext variable present but unreadable");
        } else {
            trustprobe_efi_boot_entry_t next_entry = {0};
            if (!read_boot_entry(next_number, &next_entry)) {
                results[used++] = make_result("EFI one-shot boot",
                    CHECK_WARN, "BootNext points to unreadable entry");
            } else if (next_entry.type == TRUSTPROBE_EFI_BOOT_TYPE_USB) {
                results[used++] = make_result("EFI one-shot boot",
                    CHECK_WARN, "BootNext overrides to USB boot");
            } else if (next_entry.type == TRUSTPROBE_EFI_BOOT_TYPE_NETWORK) {
                results[used++] = make_result("EFI one-shot boot",
                    CHECK_WARN, "BootNext overrides to network boot");
            } else if (next_entry.type == TRUSTPROBE_EFI_BOOT_TYPE_CD) {
                results[used++] = make_result("EFI one-shot boot",
                    CHECK_WARN, "BootNext overrides to CD/DVD boot");
            } else {
                results[used++] = make_result("EFI one-shot boot",
                    CHECK_OK, "BootNext points to non-risky entry");
            }
        }
    }

    return used;
}

static bool name_matches_usb_boot(const char *name) {
    char lower[256];
    size_t len = strlen(name);
    if (len >= sizeof(lower)) {
        len = sizeof(lower) - 1;
    }

    for (size_t i = 0; i < len; i++) {
        lower[i] = (char)tolower((unsigned char)name[i]);
    }
    lower[len] = '\0';

    return strstr(lower, "usb") != NULL && strstr(lower, "boot") != NULL;
}

static size_t check_firmware_attrs_boot(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *base = "/sys/class/firmware-attributes";

    if (used >= max_results) {
        return used;
    }

    DIR *vendors = opendir(base);
    if (vendors == NULL) {
        results[used++] = make_result("BIOS USB boot", CHECK_SKIP,
            "firmware-attributes not available; check BIOS manually");
        return used;
    }

    bool found = false;
    char value[64] = {0};
    struct dirent *vendor;

    while ((vendor = readdir(vendors)) != NULL) {
        if (vendor->d_name[0] == '.') {
            continue;
        }

        char attrs_path[PATH_MAX];
        if (snprintf(attrs_path, sizeof(attrs_path), "%s/%s/attributes", base, vendor->d_name) >= (int)sizeof(attrs_path)) {
            continue;
        }

        DIR *attrs = opendir(attrs_path);
        if (attrs == NULL) {
            continue;
        }

        struct dirent *attr;
        while ((attr = readdir(attrs)) != NULL) {
            if (attr->d_name[0] == '.') {
                continue;
            }

            if (!name_matches_usb_boot(attr->d_name)) {
                continue;
            }

            char val_path[PATH_MAX];
            if (snprintf(val_path, sizeof(val_path), "%s/%s/current_value", attrs_path, attr->d_name) >= (int)sizeof(val_path)) {
                continue;
            }

            if (trustprobe_read_file_text(val_path, value, sizeof(value))) {
                size_t vlen = strlen(value);
                while (vlen > 0 && isspace((unsigned char)value[vlen - 1])) {
                    value[--vlen] = '\0';
                }
                found = true;
                break;
            }
        }

        closedir(attrs);
        if (found) {
            break;
        }
    }

    closedir(vendors);

    if (!found) {
        results[used++] = make_result("BIOS USB boot", CHECK_SKIP,
            "USB boot attribute not exposed; check BIOS manually");
        return used;
    }

    char lower_value[64];
    size_t vlen = strlen(value);
    if (vlen >= sizeof(lower_value)) {
        vlen = sizeof(lower_value) - 1;
    }
    for (size_t i = 0; i < vlen; i++) {
        lower_value[i] = (char)tolower((unsigned char)value[i]);
    }
    lower_value[vlen] = '\0';

    if (strstr(lower_value, "disable") != NULL) {
        results[used++] = make_result("BIOS USB boot", CHECK_OK, "USB boot disabled via firmware-attributes");
    } else if (strstr(lower_value, "enable") != NULL) {
        results[used++] = make_result("BIOS USB boot", CHECK_WARN, "USB boot enabled; consider disabling in BIOS");
    } else {
        char detail[TRUSTPROBE_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "USB boot setting: %s", value);
        results[used++] = make_result("BIOS USB boot", CHECK_WARN, detail);
    }

    return used;
}

static size_t check_firmware_password(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (used >= max_results) {
        return used;
    }

    if (!trustprobe_command_exists("dmidecode")) {
        results[used++] = make_result("Firmware password", CHECK_SKIP,
            "dmidecode not available");
        return used;
    }

    static const char *const dmidecode_argv[] = {"dmidecode", "-t", "24", NULL};
    char buf[2048] = {0};
    int exit_status = -1;

    bool captured = trustprobe_capture_argv_status(dmidecode_argv, buf, sizeof(buf), &exit_status);
    if (!captured || exit_status != 0) {
        if (!captured ||
            strstr(buf, "Permission denied") != NULL ||
            strstr(buf, "must be root") != NULL ||
            strstr(buf, "requires root") != NULL) {
            results[used++] = make_root_result("Firmware password", CHECK_SKIP,
                "requires root to read DMI hardware security");
        } else {
            results[used++] = make_result("Firmware password", CHECK_SKIP,
                "firmware password state not readable");
        }
        return used;
    }

    const char *field = "Administrator Password Status:";
    const char *pos = strstr(buf, field);
    if (pos == NULL) {
        results[used++] = make_result("Firmware password", CHECK_SKIP,
            "firmware password state not readable");
        return used;
    }

    pos += strlen(field);
    while (*pos == ' ' || *pos == '\t') {
        pos++;
    }

    if (strncmp(pos, "Enabled", 7) == 0) {
        results[used++] = make_result("Firmware password", CHECK_OK,
            "firmware administrator password is set");
    } else if (strncmp(pos, "Disabled", 8) == 0) {
        results[used++] = make_result("Firmware password", CHECK_WARN,
            "no firmware administrator password set");
    } else {
        results[used++] = make_result("Firmware password", CHECK_SKIP,
            "firmware password state not readable");
    }

    return used;
}

static size_t check_efivars_immutable(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    if (!trustprobe_file_exists(EFI_BOOT_ORDER_PATH)) {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_SKIP,
            "BootOrder variable not found");
        return used;
    }

    int fd = open(EFI_BOOT_ORDER_PATH, O_RDONLY);
    if (fd < 0) {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_SKIP,
            "BootOrder variable not readable");
        return used;
    }

    unsigned int flags = 0;
    int ret = ioctl(fd, FS_IOC_GETFLAGS, &flags);
    close(fd);

    if (ret < 0) {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_SKIP,
            "immutable flag unreadable");
        return used;
    }

    if (flags & (unsigned int)FS_IMMUTABLE_FL) {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_OK,
            "BootOrder immutable flag set");
    } else {
        results[used++] = make_result("EFI BootOrder immutable", CHECK_WARN,
            "BootOrder immutable flag not set");
    }
    return used;
}

size_t trustprobe_check_bios_boot(check_result_t *results, size_t max_results) {
    size_t used = 0;

    used += check_efivars_boot(results + used, used < max_results ? max_results - used : 0);
    used += check_efivars_immutable(results + used, used < max_results ? max_results - used : 0);
    used += check_firmware_attrs_boot(results + used, used < max_results ? max_results - used : 0);
    used += check_firmware_password(results + used, used < max_results ? max_results - used : 0);

    return used;
}
