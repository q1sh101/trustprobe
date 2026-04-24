#ifndef TRUSTPROBE_FIRMWARE_PARSERS_H
#define TRUSTPROBE_FIRMWARE_PARSERS_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
    TRUSTPROBE_SECURE_BOOT_UNKNOWN = 0,
    TRUSTPROBE_SECURE_BOOT_ENABLED,
    TRUSTPROBE_SECURE_BOOT_DISABLED,
} trustprobe_secure_boot_status_t;

typedef enum {
    TRUSTPROBE_FWUPD_UPDATES_UNKNOWN = 0,
    TRUSTPROBE_FWUPD_UPDATES_NONE,
    TRUSTPROBE_FWUPD_UPDATES_AVAILABLE,
} trustprobe_fwupd_updates_status_t;

typedef struct {
    bool installed_known;
    bool installed;
    bool setup_mode_known;
    bool setup_mode_enabled;
    bool secure_boot_known;
    bool secure_boot_enabled;
    bool owner_guid_present;
    char owner_guid[64];
    bool vendor_keys_present;
    char vendor_keys[64];
} trustprobe_sbctl_status_t;

size_t trustprobe_count_nonempty_lines(const char *text);
bool trustprobe_extract_short_list_name(const char *text, char *buffer, size_t size);
trustprobe_secure_boot_status_t trustprobe_parse_secure_boot_state(const char *text);
bool trustprobe_secure_boot_setup_mode(const char *text);
trustprobe_fwupd_updates_status_t trustprobe_parse_fwupd_updates(const char *text, int exit_status);
bool trustprobe_parse_sbctl_status(const char *text, trustprobe_sbctl_status_t *status);
bool trustprobe_hsi_find_result(const char *json, const char *appstream_id,
                                char *result_buf, size_t result_size);

/* efivar buf has a 4-byte UEFI attribute header; extracts first line of payload */
bool trustprobe_parse_sbat_level(const unsigned char *buf, size_t len,
                                 char *out, size_t out_size);
/* returns true if mokutil --sbat output contains applied SBAT entries */
bool trustprobe_sbat_entries_present(const char *text);
/* returns true if mokutil --db output contains Microsoft 3rd Party UEFI CA */
bool trustprobe_sb_has_ms_ca(const char *text);

#endif
