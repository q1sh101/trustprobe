#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>

#include "checks.h"
#include "esp_parsers.h"
#include "runtime.h"

static const char *const ESP_EFI_BASE = "/boot/efi/EFI";

static size_t check_esp_permissions(check_result_t *results, size_t max_results) {
    size_t used = 0;
    struct stat st;

    if (used < max_results && stat("/boot", &st) == 0) {
        if (st.st_uid != 0) {
            results[used++] = make_result("/boot ownership", CHECK_WARN,
                "/boot not owned by root");
        } else if ((st.st_mode & (mode_t)0022) != 0) {
            results[used++] = make_result("/boot ownership", CHECK_WARN,
                "/boot world/group-writable");
        } else {
            results[used++] = make_result("/boot ownership", CHECK_OK,
                "root-owned and not world-writable");
        }
    }

    if (used >= max_results) return used;

    if (stat("/boot/efi", &st) != 0) {
        results[used++] = make_result("ESP mount", CHECK_SKIP,
            "ESP not mounted at /boot/efi");
        return used;
    }
    if (st.st_uid != 0) {
        results[used++] = make_result("ESP ownership", CHECK_WARN,
            "ESP not owned by root");
    } else if ((st.st_mode & (mode_t)0022) != 0) {
        results[used++] = make_result("ESP ownership", CHECK_WARN,
            "ESP world/group-writable");
    } else {
        results[used++] = make_result("ESP ownership", CHECK_OK,
            "ESP root-owned and not world-writable");
    }
    return used;
}

static size_t check_efi_vendor_dirs(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    DIR *dir = opendir(ESP_EFI_BASE);
    if (dir == NULL) {
        results[used++] = make_result("EFI vendor directories", CHECK_SKIP,
            "EFI directory not accessible");
        return used;
    }

    size_t total = 0;
    char unexpected[64] = {0};
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char path[PATH_MAX];
        if (snprintf(path, sizeof(path), "%s/%s", ESP_EFI_BASE, entry->d_name) >=
            (int)sizeof(path)) continue;
        struct stat st;
        /* FAT32 d_type is often DT_UNKNOWN; use stat to confirm directory */
        if (stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) continue;
        total++;
        if (!trustprobe_esp_is_known_vendor(entry->d_name) && unexpected[0] == '\0') {
            snprintf(unexpected, sizeof(unexpected), "%.60s", entry->d_name);
        }
    }
    closedir(dir);

    if (total == 0) {
        results[used++] = make_result("EFI vendor directories", CHECK_WARN,
            "EFI directory contains no vendor dirs");
    } else if (unexpected[0] != '\0') {
        char detail[TRUSTPROBE_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "unrecognized EFI vendor dir: %s", unexpected);
        results[used++] = make_result("EFI vendor directories", CHECK_WARN, detail);
    } else {
        char detail[TRUSTPROBE_DETAIL_MAX];
        snprintf(detail, sizeof(detail), "%zu vendor dir(s); all recognized", total);
        results[used++] = make_result("EFI vendor directories", CHECK_OK, detail);
    }
    return used;
}

static bool find_shim(char *path_out, size_t size) {
    DIR *efi_dir = opendir(ESP_EFI_BASE);
    if (efi_dir == NULL) return false;
    bool found = false;
    struct dirent *vendor;
    while (!found && (vendor = readdir(efi_dir)) != NULL) {
        if (vendor->d_name[0] == '.') continue;
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s/shimx64.efi",
                     ESP_EFI_BASE, vendor->d_name) >= (int)sizeof(candidate)) continue;
        if (trustprobe_file_exists(candidate)) {
            snprintf(path_out, size, "%s", candidate);
            found = true;
        }
    }
    closedir(efi_dir);
    return found;
}

static size_t check_bootx64(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    /* UEFI fallback path used by attackers to persist across BootOrder resets */
    const char *upper = "/boot/efi/EFI/BOOT/BOOTX64.EFI";
    const char *lower = "/boot/efi/EFI/BOOT/bootx64.efi";
    const char *bootx64 = trustprobe_file_exists(upper) ? upper :
                          trustprobe_file_exists(lower) ? lower : NULL;

    if (bootx64 == NULL) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_SKIP,
            "UEFI fallback loader not found");
        return used;
    }

    char shim[PATH_MAX] = {0};
    if (!find_shim(shim, sizeof(shim))) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_SKIP,
            "present; shim not found for comparison");
        return used;
    }

    struct stat st_boot, st_shim;
    if (stat(bootx64, &st_boot) == 0 && stat(shim, &st_shim) == 0 &&
        st_boot.st_ino == st_shim.st_ino && st_boot.st_dev == st_shim.st_dev) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_OK,
            "matches installed shim (inode)");
        return used;
    }

    if (!trustprobe_command_exists("sha256sum")) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_SKIP,
            "present; sha256sum unavailable for identity check");
        return used;
    }

    const char *boot_argv[] = {"sha256sum", bootx64, NULL};
    const char *shim_argv[] = {"sha256sum", shim,    NULL};
    char boot_out[256] = {0}, shim_out[256] = {0};
    int exit_a = -1, exit_b = -1;

    if (!trustprobe_capture_argv_status((const char *const *)boot_argv,
                                        boot_out, sizeof(boot_out), &exit_a) || exit_a != 0 ||
        !trustprobe_capture_argv_status((const char *const *)shim_argv,
                                        shim_out, sizeof(shim_out), &exit_b) || exit_b != 0) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_SKIP,
            "present; hash unavailable");
        return used;
    }

    char boot_hash[128] = {0}, shim_hash[128] = {0};
    if (!trustprobe_parse_sha256sum_line(boot_out, boot_hash, sizeof(boot_hash)) ||
        !trustprobe_parse_sha256sum_line(shim_out, shim_hash, sizeof(shim_hash))) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_SKIP,
            "present; hash parse failed");
        return used;
    }

    if (strcmp(boot_hash, shim_hash) == 0) {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_OK,
            "matches installed shim (sha256)");
    } else {
        results[used++] = make_result("BOOTX64.EFI (fallback)", CHECK_WARN,
            "BOOTX64.EFI does not match installed shim");
    }
    return used;
}

static size_t check_update_capsule(check_result_t *results, size_t max_results) {
    size_t used = 0;
    if (used >= max_results) return used;

    DIR *dir = opendir("/boot/efi/EFI/UpdateCapsule");
    if (dir == NULL) {
        results[used++] = make_result("ESP UpdateCapsule", CHECK_SKIP,
            "UpdateCapsule directory absent");
        return used;
    }

    size_t count = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] != '.') count++;
    }
    closedir(dir);

    if (count == 0) {
        results[used++] = make_result("ESP UpdateCapsule", CHECK_OK,
            "UpdateCapsule directory empty");
    } else {
        char detail[TRUSTPROBE_DETAIL_MAX];
        snprintf(detail, sizeof(detail),
            "%zu file(s) in UpdateCapsule; firmware will apply on next reboot", count);
        results[used++] = make_result("ESP UpdateCapsule", CHECK_WARN, detail);
    }
    return used;
}

size_t trustprobe_check_esp_posture(check_result_t *results, size_t max_results) {
    size_t used = 0;
    size_t remaining;

    if (results == NULL || max_results == 0) return 0;

    remaining = max_results - used;
    used += check_esp_permissions(results + used, remaining);

    /* ESP not mounted — remaining checks have nothing to read */
    if (used > 0 && results[used - 1].state == CHECK_SKIP) return used;

    remaining = max_results - used;
    used += check_efi_vendor_dirs(results + used, remaining);

    remaining = max_results - used;
    used += check_bootx64(results + used, remaining);

    remaining = max_results - used;
    used += check_update_capsule(results + used, remaining);

    return used;
}
