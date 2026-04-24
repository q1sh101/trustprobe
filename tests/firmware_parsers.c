#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include "assert_helpers.h"
#include "firmware_parsers.h"

int main(void) {
    char owner[128] = {0};
    trustprobe_sbctl_status_t sbctl = {0};

    assert_eq_sz("count_nonempty_lines", trustprobe_count_nonempty_lines("a\n\nb\r\n  \n c\n"), 3);
    assert_true(
        "extract_short_list_name",
        trustprobe_extract_short_list_name("abcd123456 Example Platform Certificate\n", owner, sizeof(owner))
    );
    assert_true("extract_short_list_name_value", strcmp(owner, "Example Platform Certificate") == 0);
    assert_false("extract_short_list_name_null",
        trustprobe_extract_short_list_name(NULL, owner, sizeof(owner)));

    assert_eq_int(
        "secure_boot_enabled",
        trustprobe_parse_secure_boot_state("SecureBoot enabled\n"),
        TRUSTPROBE_SECURE_BOOT_ENABLED
    );
    assert_eq_int(
        "secure_boot_disabled",
        trustprobe_parse_secure_boot_state("SecureBoot disabled\n"),
        TRUSTPROBE_SECURE_BOOT_DISABLED
    );
    assert_eq_int(
        "secure_boot_unknown",
        trustprobe_parse_secure_boot_state("something odd\n"),
        TRUSTPROBE_SECURE_BOOT_UNKNOWN
    );
    assert_eq_int(
        "secure_boot_null",
        trustprobe_parse_secure_boot_state(NULL),
        TRUSTPROBE_SECURE_BOOT_UNKNOWN
    );
    assert_true(
        "secure_boot_setup_mode_true",
        trustprobe_secure_boot_setup_mode("SecureBoot enabled\nPlatform is in Setup Mode\n")
    );
    assert_true(
        "secure_boot_setup_mode_false",
        !trustprobe_secure_boot_setup_mode("SecureBoot enabled\n")
    );
    assert_false("secure_boot_setup_mode_null",
        trustprobe_secure_boot_setup_mode(NULL));

    assert_eq_int(
        "fwupd_no_updates",
        trustprobe_parse_fwupd_updates("No updates available\n", 2),
        TRUSTPROBE_FWUPD_UPDATES_NONE
    );
    assert_eq_int(
        "fwupd_updates_available",
        trustprobe_parse_fwupd_updates("Devices with firmware updates:\n", 0),
        TRUSTPROBE_FWUPD_UPDATES_AVAILABLE
    );
    assert_eq_int(
        "fwupd_unknown",
        trustprobe_parse_fwupd_updates("Idle...\n", 1),
        TRUSTPROBE_FWUPD_UPDATES_UNKNOWN
    );
    assert_eq_int(
        "fwupd_null",
        trustprobe_parse_fwupd_updates(NULL, 0),
        TRUSTPROBE_FWUPD_UPDATES_UNKNOWN
    );

    assert_true(
        "sbctl_status_not_installed_parsed",
        trustprobe_parse_sbctl_status(
            "Installed:\tSbctl is not installed\n"
            "Setup Mode:\tEnabled\n"
            "Secure Boot:\tDisabled\n",
            &sbctl
        )
    );
    assert_true("sbctl_status_not_installed_known", sbctl.installed_known);
    assert_true("sbctl_status_not_installed_value", !sbctl.installed);
    assert_true("sbctl_status_setup_mode_known", sbctl.setup_mode_known);
    assert_true("sbctl_status_setup_mode_enabled", sbctl.setup_mode_enabled);
    assert_true("sbctl_status_secure_boot_known", sbctl.secure_boot_known);
    assert_true("sbctl_status_secure_boot_disabled", !sbctl.secure_boot_enabled);
    assert_true(
        "sbctl_status_installed_parsed",
        trustprobe_parse_sbctl_status(
            "Installed:\tSbctl is installed\n"
            "Owner GUID:\t11111111-2222-3333-4444-555555555555\n"
            "Setup Mode:\tDisabled\n"
            "Secure Boot:\tEnabled\n"
            "Vendor Keys:\tmicrosoft\n",
            &sbctl
        )
    );
    assert_true("sbctl_status_installed_value", sbctl.installed);
    assert_true("sbctl_status_owner_guid", strcmp(sbctl.owner_guid, "11111111-2222-3333-4444-555555555555") == 0);
    assert_true("sbctl_status_vendor_keys", strcmp(sbctl.vendor_keys, "microsoft") == 0);
    assert_true("sbctl_status_secure_boot_enabled", sbctl.secure_boot_enabled);

    static const char *const hsi_sample =
        "{\n"
        "  \"SecurityAttributes\" : [\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.PlatformFused\",\n"
        "      \"HsiResult\" : \"locked\",\n"
        "      \"HsiLevel\" : 3\n"
        "    },\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.Amd.SpiWriteProtection\",\n"
        "      \"HsiResult\" : \"enabled\",\n"
        "      \"HsiLevel\" : 4\n"
        "    },\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.PlatformDebugLocked\",\n"
        "      \"HsiResult\" : \"not-valid\",\n"
        "      \"HsiLevel\" : 2\n"
        "    },\n"
        "    {\n"
        "      \"AppstreamId\" : \"org.fwupd.hsi.EncryptedRam\",\n"
        "      \"HsiResult\" : \"not-supported\",\n"
        "      \"HsiLevel\" : 4\n"
        "    }\n"
        "  ]\n"
        "}\n";

    char hsi_val[64] = {0};

    assert_true("hsi_find_locked",
        trustprobe_hsi_find_result(hsi_sample, "org.fwupd.hsi.PlatformFused", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_locked_value", strcmp(hsi_val, "locked") == 0);

    hsi_val[0] = '\0';
    assert_true("hsi_find_enabled",
        trustprobe_hsi_find_result(hsi_sample, "org.fwupd.hsi.Amd.SpiWriteProtection", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_enabled_value", strcmp(hsi_val, "enabled") == 0);

    hsi_val[0] = '\0';
    assert_true("hsi_find_not_valid",
        trustprobe_hsi_find_result(hsi_sample, "org.fwupd.hsi.PlatformDebugLocked", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_not_valid_value", strcmp(hsi_val, "not-valid") == 0);

    hsi_val[0] = '\0';
    assert_true("hsi_find_not_supported",
        trustprobe_hsi_find_result(hsi_sample, "org.fwupd.hsi.EncryptedRam", hsi_val, sizeof(hsi_val)));
    assert_true("hsi_not_supported_value", strcmp(hsi_val, "not-supported") == 0);

    hsi_val[0] = '\0';
    assert_false("hsi_find_absent",
        trustprobe_hsi_find_result(hsi_sample, "org.fwupd.hsi.IntelBootguard.Enabled", hsi_val, sizeof(hsi_val)));

    assert_false("hsi_null_json",
        trustprobe_hsi_find_result(NULL, "org.fwupd.hsi.PlatformFused", hsi_val, sizeof(hsi_val)));
    assert_false("hsi_null_id",
        trustprobe_hsi_find_result(hsi_sample, NULL, hsi_val, sizeof(hsi_val)));
    assert_false("hsi_null_buf",
        trustprobe_hsi_find_result(hsi_sample, "org.fwupd.hsi.PlatformFused", NULL, sizeof(hsi_val)));

    {
        /* target attribute positioned past 16384 bytes — catches buffer truncation bugs */
        char big[24576] = {0};
        size_t off = 0;
        off += (size_t)snprintf(big + off, sizeof(big) - off,
            "{\"SecurityAttributes\":[");
        for (int i = 0; i < 60; i++) {
            off += (size_t)snprintf(big + off, sizeof(big) - off,
                "{\"AppstreamId\":\"org.fwupd.hsi.Pad%d\","
                "\"HsiResult\":\"not-supported\"},", i);
        }
        snprintf(big + off, sizeof(big) - off,
            "{\"AppstreamId\":\"org.fwupd.hsi.EncryptedRam\","
            "\"HsiResult\":\"not-supported\"}]}");

        hsi_val[0] = '\0';
        assert_true("hsi_late_attr_found",
            trustprobe_hsi_find_result(big, "org.fwupd.hsi.EncryptedRam", hsi_val, sizeof(hsi_val)));
        assert_true("hsi_late_attr_value", strcmp(hsi_val, "not-supported") == 0);
    }

    printf("firmware parsers ok\n");
    return 0;
}
