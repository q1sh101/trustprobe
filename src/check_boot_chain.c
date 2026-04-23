#include <ctype.h>
#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "checks.h"
#include "runtime.h"

static size_t check_bootloader_version(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    static const char *const grub_argv[]    = {"grub-install",  "--version", NULL};
    static const char *const grub2_argv[]   = {"grub2-install", "--version", NULL};
    static const char *const bootctl_argv[] = {"bootctl",       "--version", NULL};

    const char *const *argv = NULL;

    if (trustprobe_command_exists("grub-install")) {
        argv = grub_argv;
    } else if (trustprobe_command_exists("grub2-install")) {
        argv = grub2_argv;
    } else if (trustprobe_command_exists("bootctl")) {
        argv = bootctl_argv;
    }

    if (argv == NULL) {
        results[used++] = make_result("bootloader version", CHECK_SKIP,
            "bootloader tool not found");
        return used;
    }

    char buf[256] = {0};
    int exit_status = -1;
    if (!trustprobe_capture_argv_status(argv, buf, sizeof(buf), &exit_status) ||
        exit_status != 0 || buf[0] == '\0') {
        results[used++] = make_result("bootloader version", CHECK_SKIP,
            "bootloader version unreadable");
        return used;
    }

    char *trimmed = trustprobe_trim(buf);
    char detail[TRUSTPROBE_DETAIL_MAX];
    snprintf(detail, sizeof(detail), "%.160s; verify against CVE database", trimmed);
    results[used++] = make_result("bootloader version", CHECK_WARN, detail);
    return used;
}

static bool find_shim(char *path_out, size_t path_out_size) {
    const char *base = "/boot/efi/EFI";
    DIR *efi_dir = opendir(base);
    if (efi_dir == NULL) {
        return false;
    }

    bool found = false;
    struct dirent *vendor;

    while (!found && (vendor = readdir(efi_dir)) != NULL) {
        if (vendor->d_name[0] == '.') {
            continue;
        }

        char vendor_path[PATH_MAX];
        if (snprintf(vendor_path, sizeof(vendor_path), "%s/%s",
                     base, vendor->d_name) >= (int)sizeof(vendor_path)) {
            continue;
        }

        DIR *vendor_dir = opendir(vendor_path);
        if (vendor_dir == NULL) {
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(vendor_dir)) != NULL) {
            size_t nlen = strlen(entry->d_name);
            if (nlen >= 64) {
                continue;
            }

            char lower[64] = {0};
            for (size_t i = 0; i < nlen; i++) {
                lower[i] = (char)tolower((unsigned char)entry->d_name[i]);
            }
            lower[nlen] = '\0';

            if (strcmp(lower, "shimx64.efi") != 0) {
                continue;
            }

            if (snprintf(path_out, path_out_size, "%s/%s",
                         vendor_path, entry->d_name) >= (int)path_out_size) {
                continue;
            }

            found = true;
            break;
        }

        closedir(vendor_dir);
    }

    closedir(efi_dir);
    return found;
}

static size_t check_shim_signature(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    char shim_path[PATH_MAX] = {0};
    if (!find_shim(shim_path, sizeof(shim_path))) {
        results[used++] = make_result("shim signature", CHECK_SKIP,
            "shim binary not found at /boot/efi/EFI/");
        return used;
    }

    if (!trustprobe_command_exists("pesign")) {
        results[used++] = make_result("shim signature", CHECK_SKIP,
            "pesign not available");
        return used;
    }

    const char *pesign_argv[] = {"pesign", "--list", "--in", shim_path, NULL};
    char buf[2048] = {0};
    int exit_status = -1;

    if (!trustprobe_capture_argv_status(
            (const char *const *)pesign_argv, buf, sizeof(buf), &exit_status) ||
        exit_status != 0) {
        results[used++] = make_result("shim signature", CHECK_WARN,
            "shim signature unverifiable");
        return used;
    }

    char lower[2048] = {0};
    for (size_t i = 0; i < sizeof(buf) - 1 && buf[i] != '\0'; i++) {
        lower[i] = (char)tolower((unsigned char)buf[i]);
    }

    if (buf[0] == '\0' || strstr(lower, "no signature") != NULL) {
        results[used++] = make_result("shim signature", CHECK_FAIL,
            "shim binary not signed");
    } else {
        results[used++] = make_result("shim signature", CHECK_OK,
            "shim signature present");
    }
    return used;
}

static size_t check_initramfs_permissions(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) {
        return used;
    }

    DIR *boot = opendir("/boot");
    if (boot == NULL) {
        results[used++] = make_result("initramfs permissions", CHECK_SKIP,
            "unable to read /boot");
        return used;
    }

    size_t count = 0;
    bool any_warn = false;
    char warn_detail[TRUSTPROBE_DETAIL_MAX] = {0};

    struct dirent *entry;
    while ((entry = readdir(boot)) != NULL) {
        const char *name = entry->d_name;
        if (strncmp(name, "initrd", 6) != 0 && strncmp(name, "initramfs", 9) != 0) {
            continue;
        }

        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "/boot/%s", name) >= (int)sizeof(path)) {
            continue;
        }

        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }

        count++;

        if (!any_warn) {
            if (st.st_uid != 0) {
                any_warn = true;
                snprintf(warn_detail, sizeof(warn_detail),
                    "initramfs not root-owned: %.200s", name);
            } else if ((st.st_mode & (mode_t)0022) != 0) {
                any_warn = true;
                snprintf(warn_detail, sizeof(warn_detail),
                    "initramfs world/group writable: %.200s", name);
            }
        }
    }

    closedir(boot);

    if (used >= max_results) {
        return used;
    }

    if (count == 0) {
        results[used++] = make_result("initramfs permissions", CHECK_SKIP,
            "no initramfs found in /boot");
        return used;
    }

    if (any_warn) {
        results[used++] = make_result("initramfs permissions", CHECK_WARN, warn_detail);
    } else {
        char detail[TRUSTPROBE_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
            "%zu initramfs file(s) root-owned and not writable", count);
        results[used++] = make_result("initramfs permissions", CHECK_OK, detail);
    }
    return used;
}

size_t trustprobe_check_boot_chain(check_result_t *results, size_t max_results) {
    size_t used = 0;

    if (results == NULL || max_results == 0) {
        return 0;
    }

    size_t remaining;

    remaining = used < max_results ? max_results - used : 0;
    used += check_bootloader_version(results + used, remaining);

    remaining = used < max_results ? max_results - used : 0;
    used += check_shim_signature(results + used, remaining);

    remaining = used < max_results ? max_results - used : 0;
    used += check_initramfs_permissions(results + used, remaining);

    return used;
}
