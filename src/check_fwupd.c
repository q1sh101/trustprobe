#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "checks.h"
#include "checks_internal.h"
#include "firmware_parsers.h"
#include "runtime.h"
#include "silicon_parsers.h"

size_t bythos_check_fwupd(check_result_t *results, size_t max_results) {
    size_t used = 0;
    const char *lvfs_conf = "/etc/fwupd/remotes.d/lvfs.conf";
    bool has_fwupdmgr = false;
    static const char *fwupd_devices_argv[] = {"fwupdmgr", "get-devices", NULL};
    static const char *fwupd_updates_argv[] = {"fwupdmgr", "get-updates", NULL};

    has_fwupdmgr = bythos_command_exists("fwupdmgr");

    switch (bythos_probe_systemd_service("fwupd.service")) {
    case BYTHOS_SERVICE_STATE_SYSTEMCTL_UNAVAILABLE:
        EMIT_INSTALL("fwupd service", "systemctl not available");
        break;
    case BYTHOS_SERVICE_STATE_ACTIVE:
        EMIT("fwupd service", CHECK_OK, "running");
        break;
    case BYTHOS_SERVICE_STATE_INACTIVE:
        EMIT("fwupd service", CHECK_WARN, "installed but inactive");
        break;
    case BYTHOS_SERVICE_STATE_MISSING:
        EMIT("fwupd service", CHECK_WARN, "not installed");
        break;
    default:
        EMIT("fwupd service", CHECK_SKIP, "state unavailable");
        break;
    }

    {
        char enabled[32] = {0};
        if (!has_fwupdmgr) {
            EMIT_INSTALL("LVFS remote", "fwupdmgr not installed");
        } else if (!bythos_file_exists(lvfs_conf)) {
            EMIT("LVFS remote", CHECK_WARN, "lvfs.conf not found");
        } else if (!bythos_read_key_value(lvfs_conf, "Enabled", enabled, sizeof(enabled))) {
            EMIT("LVFS remote", CHECK_WARN, "Enabled key not found");
        } else if (strcmp(enabled, "true") == 0) {
            EMIT("LVFS remote", CHECK_OK, "enabled");
        } else {
            EMIT("LVFS remote", CHECK_WARN, "not enabled");
        }
    }

    {
        int devices = -1;
        if (!has_fwupdmgr) {
            EMIT_INSTALL("firmware inventory", "fwupdmgr not installed");
        } else if ((devices = bythos_run_argv_quiet(fwupd_devices_argv)) == 0) {
            EMIT("firmware inventory", CHECK_OK, "device list available");
        } else {
            EMIT("firmware inventory", CHECK_SKIP, "unable to list devices");
        }
    }

    {
        char buffer[2048] = {0};
        int status = -1;
        bythos_fwupd_updates_status_t updates = BYTHOS_FWUPD_UPDATES_UNKNOWN;

        if (!has_fwupdmgr) {
            EMIT_INSTALL("firmware update status", "fwupdmgr not installed");
        } else if (!bythos_capture_argv_status(fwupd_updates_argv, buffer, sizeof(buffer), &status)) {
            EMIT("firmware update status", CHECK_SKIP, "unable to query");
        } else if ((updates = bythos_parse_fwupd_updates(buffer, status)) == BYTHOS_FWUPD_UPDATES_NONE) {
            EMIT("firmware update status", CHECK_OK, "no updates available");
        } else if (updates == BYTHOS_FWUPD_UPDATES_AVAILABLE) {
            EMIT("firmware update status", CHECK_WARN, "updates available");
        } else {
            EMIT("firmware update status", CHECK_SKIP, "unavailable");
        }
    }

    /* Firmware update history - informational signal, not a hard posture gate. */
    {
        static const char *fwupd_history_argv[] = {"fwupdmgr", "get-history", NULL};
        char hist_buffer[2048] = {0};
        int hist_status = -1;

        if (!has_fwupdmgr) {
            EMIT_INSTALL("firmware update history", "fwupdmgr not installed");
        } else if (!bythos_capture_argv_status(fwupd_history_argv, hist_buffer, sizeof(hist_buffer), &hist_status)) {
            EMIT("firmware update history", CHECK_SKIP, "history unavailable");
        } else if (hist_status != 0) {
            EMIT("firmware update history", CHECK_SKIP, "history unavailable");
        } else if (hist_buffer[0] != '\0') {
            EMIT("firmware update history", CHECK_OK, "available");
        } else {
            EMIT("firmware update history", CHECK_SKIP, "no history visible");
        }
    }

    static const char *const hsi_argv[] = {"fwupdmgr", "security", "--json", NULL};
    char hsi_json[32768] = {0};
    int hsi_status = -1;
    bool hsi_ok = false;

    if (has_fwupdmgr &&
        bythos_capture_argv_status(hsi_argv, hsi_json, sizeof(hsi_json), &hsi_status) &&
        hsi_status == 0 &&
        hsi_json[0] != '\0') {
        hsi_ok = true;
    }

    bythos_cpu_vendor_t vendor = bythos_cpu_vendor();

    if (!hsi_ok) {
        EMIT("HSI query", CHECK_SKIP,
            has_fwupdmgr ? "security query failed" : "fwupdmgr not installed");
        return used;
    }

#define EMIT_HSI(name_, id_, positive_, ok_msg_, warn_msg_) \
    do { \
        if (used < max_results) { \
            char _v[64] = {0}; \
            if (!bythos_hsi_find_result(hsi_json, (id_), _v, sizeof(_v))) { \
                results[used++] = make_result((name_), CHECK_SKIP, "not reported"); \
            } else if (strcmp(_v, "not-supported") == 0) { \
                results[used++] = make_result((name_), CHECK_SKIP, "not supported"); \
            } else if (strcmp(_v, (positive_)) == 0) { \
                results[used++] = make_result((name_), CHECK_OK, (ok_msg_)); \
            } else { \
                results[used++] = make_result((name_), CHECK_WARN, (warn_msg_)); \
            } \
        } \
    } while (0)

    /* universal */
    EMIT_HSI("HSI: platform fused",
             "org.fwupd.hsi.PlatformFused",           "locked",
             "security fuses set",                    "security fuses not set");
    EMIT_HSI("HSI: debug locked",
             "org.fwupd.hsi.PlatformDebugLocked",     "locked",
             "locked",                                "not locked");
    EMIT_HSI("HSI: Secure Boot",
             "org.fwupd.hsi.Uefi.SecureBoot",         "enabled",
             "enabled",                               "not enabled");
    EMIT_HSI("HSI: UEFI PK",
             "org.fwupd.hsi.Uefi.Pk",                 "valid",
             "enrolled",                              "not enrolled");
    EMIT_HSI("HSI: UEFI db",
             "org.fwupd.hsi.Uefi.Db",                 "valid",
             "valid",                                 "not valid");
    EMIT_HSI("HSI: DBX currency",
             "org.fwupd.hsi.UefiDbxUpdates",          "valid",
             "revocation list current",               "revocation list outdated");
    EMIT_HSI("HSI: UEFI boot variables",
             "org.fwupd.hsi.Uefi.BootserviceVars",    "locked",
             "locked",                                "not locked");
    EMIT_HSI("HSI: capsule updates",
             "org.fwupd.hsi.Bios.CapsuleUpdates",     "enabled",
             "authentication enabled",               "authentication not enabled");
    EMIT_HSI("HSI: TPM 2.0",
             "org.fwupd.hsi.Tpm.Version20",           "found",
             "present",                               "not found");
    EMIT_HSI("HSI: TPM empty PCR",
             "org.fwupd.hsi.Tpm.EmptyPcr",           "valid",
             "no unexpected empty PCRs",              "unexpected empty PCR found");
    EMIT_HSI("HSI: TPM PCR0 reconstruction",
             "org.fwupd.hsi.Tpm.ReconstructionPcr0", "valid",
             "valid",                                 "failed");
    EMIT_HSI("HSI: IOMMU",
             "org.fwupd.hsi.Iommu",                   "enabled",
             "enabled",                               "not enabled");
    EMIT_HSI("HSI: pre-boot DMA protection",
             "org.fwupd.hsi.PrebootDma",              "enabled",
             "active",                                "not active");
    EMIT_HSI("HSI: encrypted RAM",
             "org.fwupd.hsi.EncryptedRam",            "enabled",
             "memory encryption active",              "memory encryption not active");

    /* AMD-only */
    if (vendor == BYTHOS_CPU_VENDOR_AMD) {
        EMIT_HSI("HSI: SMM locked",
                 "org.fwupd.hsi.Amd.SmmLocked",          "locked",
                 "locked",                                "not locked");
        EMIT_HSI("HSI: SPI replay protection",
                 "org.fwupd.hsi.Amd.SpiReplayProtection", "enabled",
                 "enabled",                               "not enabled");
        EMIT_HSI("HSI: firmware rollback protection",
                 "org.fwupd.hsi.Amd.RollbackProtection",  "enabled",
                 "enabled",                               "not enabled");
        EMIT_HSI("HSI: SPI write protection",
                 "org.fwupd.hsi.Amd.SpiWriteProtection",  "enabled",
                 "enabled",                               "not enabled");
    }

    /* Intel-only */
    if (vendor == BYTHOS_CPU_VENDOR_INTEL) {
        EMIT_HSI("HSI: BIOS write protection",
                 "org.fwupd.hsi.BiosWriteProtection",     "enabled",
                 "enabled",                               "not enabled");
        EMIT_HSI("HSI: ME manufacturing mode",
                 "org.fwupd.hsi.IntelMeMfgMode",          "locked",
                 "not in manufacturing mode",             "in manufacturing mode");
        EMIT_HSI("HSI: Boot Guard ACM",
                 "org.fwupd.hsi.IntelBootguard.Acm",     "valid",
                 "valid",                                 "not valid");
        EMIT_HSI("HSI: Boot Guard policy",
                 "org.fwupd.hsi.IntelBootguard.Policy",  "valid",
                 "valid",                                 "not valid");

        {
            char en_val[64]  = {0};
            char ver_val[64] = {0};
            bool has_en  = bythos_hsi_find_result(hsi_json,
                               "org.fwupd.hsi.IntelBootguard.Enabled", en_val, sizeof(en_val));
            bool has_ver = bythos_hsi_find_result(hsi_json,
                               "org.fwupd.hsi.IntelBootguard.Verified", ver_val, sizeof(ver_val));

            if (!has_en) {
                EMIT("HSI: Boot Guard", CHECK_SKIP, "not reported");
            } else if (strcmp(en_val, "not-supported") == 0) {
                EMIT("HSI: Boot Guard", CHECK_SKIP, "not supported");
            } else if (strcmp(en_val, "enabled") != 0) {
                EMIT("HSI: Boot Guard", CHECK_WARN, "not enabled");
            } else if (has_ver && strcmp(ver_val, "enabled") != 0) {
                EMIT("HSI: Boot Guard", CHECK_WARN, "measurement-only");
            } else {
                EMIT("HSI: Boot Guard", CHECK_OK, "enabled and verified");
            }
        }

        {
            char intel_en[64] = {0};
            char intel_lk[64] = {0};
            bool has_en = bythos_hsi_find_result(hsi_json,
                              "org.fwupd.hsi.SpiWriteProtection.Enabled", intel_en, sizeof(intel_en));
            bool has_lk = bythos_hsi_find_result(hsi_json,
                              "org.fwupd.hsi.SpiWriteProtection.Locked",  intel_lk, sizeof(intel_lk));

            if (!has_en && !has_lk) {
                EMIT("HSI: SPI write protection", CHECK_SKIP, "not reported");
            } else if (strcmp(intel_en, "enabled") == 0 && strcmp(intel_lk, "enabled") == 0) {
                EMIT("HSI: SPI write protection", CHECK_OK, "enabled and locked");
            } else {
                EMIT("HSI: SPI write protection", CHECK_WARN, "not fully active");
            }
        }
    }

#undef EMIT_HSI

    return used;
}
